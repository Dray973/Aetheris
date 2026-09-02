//! Aetheris native scan helpers — a dependency-free `cdylib` exposed over the C
//! ABI and called from Python via ctypes (`forensics/nativescan.py`). It
//! accelerates the hot byte-crunching used by the injection / YARA / threat-hunt
//! analysis: Shannon-entropy scoring (a packed/encrypted-region tell) and fast
//! byte-pattern search. Pure, memory-safe Rust — no OS calls, no dependencies —
//! and every FFI entry point is panic-guarded so a fault can never cross back
//! into the host. A pure-Python fallback covers hosts without this library.

use std::panic::catch_unwind;
use std::slice;

/// Shannon entropy in bits/byte (0.0..=8.0) for a byte slice.
fn shannon(data: &[u8]) -> f64 {
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

/// Shannon entropy (bits/byte, 0.0..=8.0) of the whole buffer.
#[no_mangle]
pub extern "C" fn aetheris_entropy(ptr: *const u8, len: usize) -> f64 {
    catch_unwind(|| {
        if ptr.is_null() || len == 0 {
            return 0.0;
        }
        shannon(unsafe { slice::from_raw_parts(ptr, len) })
    })
    .unwrap_or(0.0)
}

/// The maximum entropy over non-overlapping `window`-byte tiles — flags a
/// packed/encrypted region hiding inside an otherwise low-entropy buffer.
/// `window == 0` scores the whole buffer.
#[no_mangle]
pub extern "C" fn aetheris_max_window_entropy(ptr: *const u8, len: usize, window: usize) -> f64 {
    catch_unwind(|| {
        if ptr.is_null() || len == 0 {
            return 0.0;
        }
        let data = unsafe { slice::from_raw_parts(ptr, len) };
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
    })
    .unwrap_or(0.0)
}

/// First offset of `pat` in the buffer, or -1 if not found / invalid input.
#[no_mangle]
pub extern "C" fn aetheris_find(
    ptr: *const u8,
    len: usize,
    pat: *const u8,
    pat_len: usize,
) -> isize {
    catch_unwind(|| {
        if ptr.is_null() || pat.is_null() || pat_len == 0 || pat_len > len {
            return -1isize;
        }
        let data = unsafe { slice::from_raw_parts(ptr, len) };
        let needle = unsafe { slice::from_raw_parts(pat, pat_len) };
        data.windows(needle.len())
            .position(|w| w == needle)
            .map(|p| p as isize)
            .unwrap_or(-1)
    })
    .unwrap_or(-1)
}
