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
    if pattern.is_empty() || pattern.len() > haystack.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let last = haystack.len() - pattern.len();
    'outer: for i in 0..=last {
        for (j, p) in pattern.iter().enumerate() {
            if let Some(b) = p {
                if haystack[i + j] != *b {
                    continue 'outer;
                }
            }
        }
        out.push(i);
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
}
