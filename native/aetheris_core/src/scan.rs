//! Byte-crunching primitives: Shannon entropy and pattern search.
//!
//! Carried over from the original `entropy_rs` crate, with the multi-match
//! search the carver needs. Pure computation — no OS calls, no allocation on
//! the hot paths.

/// Shannon entropy in bits/byte (0.0..=8.0) for a byte slice.
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0f64;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

/// The maximum entropy over non-overlapping `window`-byte tiles — flags a
/// packed/encrypted region hiding inside an otherwise low-entropy buffer.
/// A `window` of 0 scores the whole buffer.
pub fn max_window_entropy(data: &[u8], window: usize) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let w = if window == 0 { data.len() } else { window };
    let mut max = 0.0f64;
    let mut i = 0;
    while i < data.len() {
        let end = (i + w).min(data.len());
        let e = shannon(&data[i..end]);
        if e > max {
            max = e;
        }
        i += w;
    }
    max
}

/// First offset of `needle` in `data`, or None.
pub fn find(data: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > data.len() {
        return None;
    }
    // Anchor on the first byte before comparing the tail: on the sparse
    // needles this is used for (`MZ`, pool tags) that skips almost every
    // window without touching it.
    let first = needle[0];
    let last = data.len() - needle.len();
    let mut i = 0;
    while i <= last {
        if data[i] == first && &data[i..i + needle.len()] == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Every non-overlapping offset of `needle` in `data`, capped at `limit`.
pub fn find_all(data: &[u8], needle: &[u8], limit: usize) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || needle.len() > data.len() || limit == 0 {
        return out;
    }
    let mut base = 0usize;
    while base < data.len() {
        match find(&data[base..], needle) {
            Some(off) => {
                out.push(base + off);
                if out.len() >= limit {
                    break;
                }
                base += off + needle.len();
            }
            None => break,
        }
    }
    out
}

/// Every offset in `data` where `needle` occurs on a `stride` boundary.
/// Physical-memory carving only cares about page- or pool-aligned hits, and
/// striding turns a whole-buffer scan into one comparison per page.
pub fn find_aligned(data: &[u8], needle: &[u8], stride: usize, limit: usize) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || stride == 0 || needle.len() > data.len() || limit == 0 {
        return out;
    }
    let mut off = 0usize;
    while off + needle.len() <= data.len() {
        if &data[off..off + needle.len()] == needle {
            out.push(off);
            if out.len() >= limit {
                break;
            }
        }
        off += stride;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_bounds() {
        assert_eq!(shannon(&[]), 0.0);
        assert_eq!(shannon(&[7u8; 64]), 0.0); // one symbol -> zero entropy
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((shannon(&all) - 8.0).abs() < 1e-9); // uniform -> 8 bits/byte
    }

    #[test]
    fn window_entropy_finds_a_hot_tile() {
        let mut buf = vec![0u8; 512];
        buf[256..512].copy_from_slice(&(0..=255u8).collect::<Vec<u8>>());
        // The point of the windowed score: averaged over the whole buffer the
        // packed half is diluted (~4.98 bits here), but the tile itself is
        // maximal — that gap is what flags a packed region hiding in padding.
        let whole = shannon(&buf);
        let hottest = max_window_entropy(&buf, 256);
        assert!((hottest - 8.0).abs() < 1e-9, "hot tile scored {hottest}");
        assert!(hottest - whole > 2.5, "whole={whole} hottest={hottest}");
        // window 0 scores the whole buffer
        assert!((max_window_entropy(&buf, 0) - shannon(&buf)).abs() < 1e-9);
    }

    #[test]
    fn find_and_find_all() {
        let data = b"MZabcMZdefMZ";
        assert_eq!(find(data, b"MZ"), Some(0));
        assert_eq!(find(data, b"zz"), None);
        assert_eq!(find(data, b""), None);
        assert_eq!(find_all(data, b"MZ", 10), vec![0, 5, 10]);
        assert_eq!(find_all(data, b"MZ", 2), vec![0, 5]);
    }

    #[test]
    fn find_all_does_not_overlap() {
        assert_eq!(find_all(b"aaaa", b"aa", 10), vec![0, 2]);
    }

    #[test]
    fn aligned_search_skips_unaligned_hits() {
        let mut buf = vec![0u8; 4096 * 3];
        buf[0..2].copy_from_slice(b"MZ");
        buf[4096..4098].copy_from_slice(b"MZ");
        buf[5000..5002].copy_from_slice(b"MZ"); // unaligned — must be skipped
        assert_eq!(find_aligned(&buf, b"MZ", 4096, 16), vec![0, 4096]);
    }
}
