//! Wine-aware process and region tooling.
//!
//! A Windows game under Proton/Wine is, at the OS level, a **Linux process**
//! (or a small tree of them). This module gives the Linux-side tooling
//! (`trainlab-scanner`, and later the GUI) the ability to:
//!
//! - **Detect** whether a PID belongs to a Wine/Proton process tree.
//! - **Tag** memory regions with a coarse classification (heap / stack /
//!   image / mapped / anon) by reading `/proc/pid/maps`, so scans can be
//!   scoped to the interesting private heap instead of the whole address space.
//!
//! This is the Linux-side half of design decision **D5**. The other half — true
//! Windows heap tagging via `GetProcessHeaps`/`HeapWalk`/`VirtualQuery` — runs
//! *inside* the game (the injected DLL) and is a later phase. The two compose:
//! the Linux side is what you can use today, without injection.

use crate::memory::Region;

/// Coarse classification of a memory region, used to scope scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// Private heap / anonymous writable memory (the interesting scan target).
    Heap,
    /// The thread stack.
    Stack,
    /// A mapped executable image (the game's own code, or a loaded DLL).
    Image,
    /// A file-backed or shared mapping (assets, GPU buffers, etc.).
    Mapped,
    /// Anything else (e.g. vvar/vdso, guard pages).
    Other,
}

impl RegionKind {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            RegionKind::Heap => "heap",
            RegionKind::Stack => "stack",
            RegionKind::Image => "image",
            RegionKind::Mapped => "mapped",
            RegionKind::Other => "other",
        }
    }
}

/// A memory region annotated with a coarse classification.
#[derive(Debug, Clone)]
pub struct TaggedRegion {
    pub region: Region,
    pub kind: RegionKind,
}

/// Classify a single region from its `/proc/pid/maps` line attributes.
///
/// `path` is the mapped file path (or `None` for anonymous mappings).
/// `writable`/`executable` come from the region's permission bits.
pub fn classify(path: Option<&str>, writable: bool, executable: bool) -> RegionKind {
    match path {
        // A named mapping.
        Some(p) => {
            if p.starts_with('/') {
                // Executable file-backed mapping => code/image.
                if executable {
                    RegionKind::Image
                } else {
                    RegionKind::Mapped
                }
            } else {
                // Non-absolute path (e.g. "[heap]", "[stack]", "[vdso]").
                if p.contains("stack") {
                    RegionKind::Stack
                } else if p.contains("heap") {
                    RegionKind::Heap
                } else {
                    RegionKind::Other
                }
            }
        }
        // Anonymous mapping. Writable anonymous memory is the classic heap /
        // dynamic-allocation target; read-only anon is usually not interesting.
        None => {
            if writable {
                RegionKind::Heap
            } else {
                RegionKind::Other
            }
        }
    }
}

/// Tag every region of a process with a coarse classification.
///
/// This reads `/proc/pid/maps` directly (rather than going through
/// [`crate::memory::unix::LinuxProcess::regions`]) so it can also capture the
/// mapped pathname, which is what drives classification.
pub fn tag_regions(pid: i32) -> Result<Vec<TaggedRegion>, std::io::Error> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mut out = Vec::new();
    for line in maps.lines() {
        let mut it = line.split_whitespace();
        let range = it.next().unwrap_or("");
        let perms = it.next().unwrap_or("");
        // Skip the offset/dev/inode columns; the pathname is the 6th field.
        let _offset = it.next();
        let _dev = it.next();
        let _inode = it.next();
        let path = it.next().map(|s| s.to_string());
        let (start, end) = match range.split_once('-') {
            Some((s, e)) => (
                u64::from_str_radix(s, 16).unwrap_or(0),
                u64::from_str_radix(e, 16).unwrap_or(0),
            ),
            None => continue,
        };
        let readable = perms.contains('r');
        let writable = perms.contains('w');
        let executable = perms.contains('x');
        let kind = classify(path.as_deref(), writable, executable);
        out.push(TaggedRegion {
            region: Region {
                start,
                end,
                readable,
                writable,
                executable,
                name: path,
            },
            kind,
        });
    }
    Ok(out)
}

/// Filter tagged regions to those of a given kind.
pub fn regions_of_kind<'a>(
    regions: &'a [TaggedRegion],
    kind: RegionKind,
) -> impl Iterator<Item = &'a TaggedRegion> {
    regions.iter().filter(move |r| r.kind == kind)
}

/// A memory-scanning scope — which regions a scan should consider.
///
/// This is the D5 decision codified: scanning the whole address space is slow
/// and sweeps in gigabytes of GPU assets / code. Scoping to the interesting
/// regions makes scans fast and finds the value you actually want.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanScope {
    /// Only private heap (writable anonymous) — the usual target for
    /// dynamically-allocated game state. Fastest, most precise.
    Heap,
    /// Private heap plus the thread stack(s).
    HeapAndStack,
    /// Everything readable (slowest; use only when you must).
    All,
}

impl ScanScope {
    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            ScanScope::Heap => "heap",
            ScanScope::HeapAndStack => "heap+stack",
            ScanScope::All => "all",
        }
    }

    /// Return the [`Region`]s that fall within this scope.
    ///
    /// When `scope` is [`ScanScope::All`, returns every readable region.
    /// Otherwise, returns regions whose [`RegionKind`] is in scope.
    pub fn regions<'a>(
        &self,
        tagged: &'a [TaggedRegion],
    ) -> Vec<crate::memory::Region> {
        match self {
            ScanScope::All => tagged
                .iter()
                .filter(|t| t.region.readable)
                .map(|t| t.region.clone())
                .collect(),
            ScanScope::Heap => regions_of_kind(tagged, RegionKind::Heap)
                .map(|t| t.region.clone())
                .collect(),
            ScanScope::HeapAndStack => {
                let mut out: Vec<_> = regions_of_kind(tagged, RegionKind::Heap)
                    .map(|t| t.region.clone())
                    .collect();
                out.extend(regions_of_kind(tagged, RegionKind::Stack).map(|t| t.region.clone()));
                out
            }
        }
    }
}

/// Tag a process's regions and scope them to `scope` in one call.
///
/// This is the convenience entry point for "give me the regions to scan for
/// PID `pid`." Returns the scoped, readable regions.
pub fn scan_regions(pid: i32, scope: ScanScope) -> Result<Vec<crate::memory::Region>, std::io::Error> {
    let tagged = tag_regions(pid)?;
    Ok(scope.regions(&tagged))
}

/// Whether a PID is part of a Wine/Proton process tree.
///
/// Heuristics, in order of strength:
/// 1. The process's own environment contains a `WINEPREFIX` / `WINESERVER`
///    variable (set on every Windows process under Wine/Proton). Strongest,
///    and works regardless of the process tree shape.
/// 2. The process has Wine DLLs mapped (its `/proc/pid/maps` references a
///    `wine` directory). Strong and also tree-shape-independent.
/// 3. An *ancestor* is `wineserver` / `wine` / a `proton` launcher. This is
///    the weakest because under Steam's pressure-vessel `wineserver` is a
///    *sibling* of the game, not an ancestor — so we only use it as a fallback.
///
/// This is best-effort; a game launched under Proton reliably triggers #1.
pub fn is_wine_process(pid: i32) -> bool {
    // (1) Wine env vars.
    if let Ok(environ) = std::fs::read_to_string(format!("/proc/{pid}/environ")) {
        for var in environ.split('\0') {
            if var.starts_with("WINEPREFIX=")
                || var.starts_with("WINESERVER=")
                || var.starts_with("WINELOADER=")
            {
                return true;
            }
        }
    }
    // (2) Wine DLLs mapped.
    if let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) {
        if maps.contains("/wine/") || maps.to_lowercase().contains("wine") {
            return true;
        }
    }
    // (3) Ancestor walk.
    ancestor_has_wine(pid)
}

/// Walk the process ancestry looking for a `wineserver` / `wine` / proton
/// launcher. Used as a fallback when env/maps checks don't apply.
fn ancestor_has_wine(pid: i32) -> bool {
    let mut cur = pid;
    for _ in 0..64 {
        let comm = std::fs::read_to_string(format!("/proc/{cur}/comm"))
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        if comm.contains("wineserver") || comm.contains("wine") {
            return true;
        }
        let stat = match std::fs::read_to_string(format!("/proc/{cur}/stat")) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let Some(rparen) = stat.rfind(')') else {
            return false;
        };
        let rest = &stat[rparen + 1..];
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let Some(ppid) = fields.get(1).and_then(|s| s.parse::<i32>().ok()) else {
            return false;
        };
        if ppid <= 1 || ppid == cur {
            return false;
        }
        cur = ppid;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_anonymous_writable_is_heap() {
        assert_eq!(classify(None, true, false), RegionKind::Heap);
    }

    #[test]
    fn classify_anonymous_readonly_is_other() {
        assert_eq!(classify(None, false, false), RegionKind::Other);
    }

    #[test]
    fn classify_executable_image() {
        assert_eq!(
            classify(Some("/usr/lib/game/game.exe"), true, true),
            RegionKind::Image
        );
    }

    #[test]
    fn classify_file_mapped_assets() {
        assert_eq!(
            classify(Some("/home/user/assets/textures.bin"), true, false),
            RegionKind::Mapped
        );
    }

    #[test]
    fn classify_stack_and_heap_brackets() {
        assert_eq!(classify(Some("[stack]"), true, false), RegionKind::Stack);
        assert_eq!(classify(Some("[heap]"), true, false), RegionKind::Heap);
    }

    #[test]
    fn scan_scope_heap_only() {
        let tagged = vec![
            TaggedRegion {
                region: Region {
                    start: 0,
                    end: 10,
                    readable: true,
                    writable: true,
                    executable: false,
                    name: None,
                },
                kind: RegionKind::Heap,
            },
            TaggedRegion {
                region: Region {
                    start: 10,
                    end: 20,
                    readable: true,
                    writable: false,
                    executable: true,
                    name: Some("/x".into()),
                },
                kind: RegionKind::Image,
            },
            TaggedRegion {
                region: Region {
                    start: 20,
                    end: 30,
                    readable: true,
                    writable: true,
                    executable: false,
                    name: Some("[stack]".into()),
                },
                kind: RegionKind::Stack,
            },
        ];
        let heap = ScanScope::Heap.regions(&tagged);
        assert_eq!(heap.len(), 1);
        assert_eq!(heap[0].start, 0);

        let hs = ScanScope::HeapAndStack.regions(&tagged);
        assert_eq!(hs.len(), 2);

        let all = ScanScope::All.regions(&tagged);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn scan_scope_all_skips_unreadable() {
        let tagged = vec![
            TaggedRegion {
                region: Region {
                    start: 0,
                    end: 10,
                    readable: false,
                    writable: false,
                    executable: false,
                    name: None,
                },
                kind: RegionKind::Other,
            },
            TaggedRegion {
                region: Region {
                    start: 10,
                    end: 20,
                    readable: true,
                    writable: true,
                    executable: false,
                    name: None,
                },
                kind: RegionKind::Heap,
            },
        ];
        let all = ScanScope::All.regions(&tagged);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].start, 10);
    }

    #[test]
    fn regions_of_kind_filters() {
        let regions = vec![
            TaggedRegion {
                region: Region {
                    start: 0,
                    end: 10,
                    readable: true,
                    writable: true,
                    executable: false,
                    name: None,
                },
                kind: RegionKind::Heap,
            },
            TaggedRegion {
                region: Region {
                    start: 10,
                    end: 20,
                    readable: true,
                    writable: false,
                    executable: true,
                    name: Some("/x".into()),
                },
                kind: RegionKind::Image,
            },
        ];
        let heaps: Vec<_> = regions_of_kind(&regions, RegionKind::Heap).collect();
        assert_eq!(heaps.len(), 1);
        assert_eq!(heaps[0].region.start, 0);
    }
}
