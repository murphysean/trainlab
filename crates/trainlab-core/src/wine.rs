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

/// Whether a PID is part of a Wine/Proton process tree.
///
/// Heuristic: walk the process's ancestors (via `/proc/<pid>/stat` ppid) and
/// look for a `wineserver` or `wine` process, or a `proton`/`steam` launcher
/// in the ancestry. This is a best-effort detection; a game launched under
/// Proton will have `wineserver` somewhere in its process tree.
pub fn is_wine_process(pid: i32) -> bool {
    let mut cur = pid;
    // Cap the walk to avoid pathological chains.
    for _ in 0..64 {
        let comm = std::fs::read_to_string(format!("/proc/{cur}/comm"))
            .unwrap_or_default()
            .trim()
            .to_lowercase();
        if comm.contains("wineserver") || comm.contains("wine") {
            return true;
        }
        // Read the parent PID from /proc/<pid>/stat (field 4).
        let stat = match std::fs::read_to_string(format!("/proc/{cur}/stat")) {
            Ok(s) => s,
            Err(_) => return false,
        };
        // The comm field may contain spaces/parens; find the last ')'.
        let Some(rparen) = stat.rfind(')') else {
            return false;
        };
        let rest = &stat[rparen + 1..];
        let fields: Vec<&str> = rest.split_whitespace().collect();
        // After the ')' the fields are: state(3) ppid(4) ...
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
