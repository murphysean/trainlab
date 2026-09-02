//! Array-of-bytes (AOB) pattern scanning.
//!
//! AOB scanning is the bread and butter of game training: you search for a
//! distinctive byte pattern (with `??` wildcards) to locate a function or
//! data structure, then use that as an anchor for code caves and hooks.
//!
//! Patterns are represented as `Vec<Option<u8>>` where `None` is a wildcard.
//! A small helper [`parse`] converts the familiar `"48 8B 05 ?? ?? ?? ??"` text
//! form into that representation.

/// Parse a textual AOB pattern like `"48 8B 05 ?? ?? ?? ??"` into a
/// `Vec<Option<u8>>`. Whitespace and `??`/`?` are handled.
pub fn parse(text: &str) -> Vec<Option<u8>> {
    text.split_whitespace()
        .filter(|t| !t.is_empty())
        .map(|tok| {
            if tok == "??" || tok == "?" {
                None
            } else {
                u8::from_str_radix(tok, 16).ok()
            }
        })
        .collect()
}

/// Find all occurrences of `pattern` in `haystack`, returning the byte
/// offsets of each match. Wildcards (`None`) match any byte.
pub fn find_all(haystack: &[u8], pattern: &[Option<u8>]) -> Vec<usize> {
    find_all_aligned(haystack, pattern, 0)
}

/// Find all occurrences of `pattern` in `haystack` starting at an offset where `(base + offset)`
/// satisfies `alignment`. If `alignment <= 1`, matches at any byte boundary.
pub fn find_all_aligned(haystack: &[u8], pattern: &[Option<u8>], alignment: usize) -> Vec<usize> {
    find_all_aligned_with_base(haystack, pattern, 0, alignment)
}

/// Find all occurrences of `pattern` in `haystack` at `base` address with `alignment`.
pub fn find_all_aligned_with_base(
    haystack: &[u8],
    pattern: &[Option<u8>],
    base: u64,
    alignment: usize,
) -> Vec<usize> {
    if pattern.is_empty() || pattern.len() > haystack.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let step = if alignment > 1 { alignment } else { 1 };
    let last = haystack.len() - pattern.len();

    // Fast-path: If pattern contains no wildcards at all, we can do fast exact byte searches
    let all_exact = pattern.iter().all(|p| p.is_some());
    if all_exact && pattern.len() <= 16 {
        let exact_bytes: Vec<u8> = pattern.iter().map(|p| p.unwrap()).collect();
        let mut i = 0;
        while i <= last {
            let addr = base + i as u64;
            if alignment > 1 && !addr.is_multiple_of(alignment as u64) {
                let rem = (addr % (alignment as u64)) as usize;
                i += alignment - rem;
                continue;
            }
            if &haystack[i..i + exact_bytes.len()] == exact_bytes.as_slice() {
                out.push(i);
            }
            i += step;
        }
        return out;
    }

    let mut i = 0;
    while i <= last {
        let addr = base + i as u64;
        if alignment > 1 && !addr.is_multiple_of(alignment as u64) {
            let rem = (addr % (alignment as u64)) as usize;
            i += alignment - rem;
            continue;
        }

        let mut matched = true;
        for (j, p) in pattern.iter().enumerate() {
            if let Some(b) = p
                && haystack[i + j] != *b {
                    matched = false;
                    break;
                }
        }
        if matched {
            out.push(i);
        }
        i += step;
    }
    out
}

/// Find the first occurrence of `pattern` in `haystack`, or `None`.
pub fn find_first(haystack: &[u8], pattern: &[Option<u8>]) -> Option<usize> {
    find_all(haystack, pattern).into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let p = parse("48 8B 05 ?? ?? ?? ??");
        assert_eq!(p.len(), 7);
        assert_eq!(p[0], Some(0x48));
        assert_eq!(p[3], None);
    }

    #[test]
    fn find_all_matches() {
        let hay = [0x48u8, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05];
        let p = parse("48 8B 05 ?? ?? ?? ??");
        let hits = find_all(&hay, &p);
        assert_eq!(hits, vec![0]);
    }

    #[test]
    fn wildcard_matches_any() {
        let hay = [0xAAu8, 0xBB, 0xCC, 0xDD];
        let p = parse("AA ?? CC");
        assert_eq!(find_first(&hay, &p), Some(0));
    }

    #[test]
    fn aligned_matches_filter_unaligned() {
        // Pattern at index 2 (base 0x1000 + 2 = 0x1002) and index 8 (base 0x1000 + 8 = 0x1008)
        let mut hay = vec![0u8; 16];
        hay[2] = 0xAA;
        hay[3] = 0xBB;
        hay[8] = 0xAA;
        hay[9] = 0xBB;

        let p = parse("AA BB");
        let all = find_all(&hay, &p);
        assert_eq!(all, vec![2, 8]);

        // 8-byte aligned with base 0x1000 -> only offset 8 (0x1008) matches
        let aligned8 = find_all_aligned_with_base(&hay, &p, 0x1000, 8);
        assert_eq!(aligned8, vec![8]);

        // 4-byte aligned with base 0x1000 -> neither 2 nor 8? 8 is 4-aligned, 2 is not
        let aligned4 = find_all_aligned_with_base(&hay, &p, 0x1000, 4);
        assert_eq!(aligned4, vec![8]);
    }
}
