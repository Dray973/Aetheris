//! Aetheris native analysis core — the C ABI the Python host calls via ctypes.
//!
//! This crate is the Rust half of the native migration: the pure-computation
//! forensics that used to live in `aetheris/forensics/*.py`. It is
//! dependency-free and makes no OS calls, which keeps it trivially portable
//! and keeps the supply chain of a security tool down to the toolchain itself.
//!
//! **ABI rules.** Every entry point is `extern "C"`, `#[no_mangle]`, and
//! wrapped in `catch_unwind` so a fault can never unwind into the host
//! interpreter. Buffers are borrowed, never owned: the caller supplies the
//! input and an output buffer with its capacity, and the return value is the
//! number of items produced (or a negative error code). Nothing crosses the
//! boundary that the host would have to free, so there is no leak to manage
//! and no allocator to match.
//!
//! The `aetheris_entropy` / `aetheris_max_window_entropy` / `aetheris_find`
//! signatures are inherited unchanged from the original `entropy_rs` crate, so
//! this library is a drop-in superset of `aetheris_scan.dll`.

// Every export takes raw pointers because that *is* the C ABI contract.
// Clippy would have these marked `unsafe fn`, which changes nothing for a
// ctypes caller but forces an `unsafe {}` block around each call in our own
// tests. The obligation that marking would document is instead discharged
// directly: no entry point touches a pointer except through `as_slice` /
// `as_out` / `as_str`, each of which null-checks and bounds the borrow, and
// every body is wrapped in `catch_unwind`.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod classify;
pub mod hash;
pub mod mft;
pub mod pe;
pub mod scan;

use std::panic::catch_unwind;
use std::slice;

/// Bumped when the export surface changes at all — a changed signature, or
/// added exports, since the Python binding resolves every symbol up front. The
/// host refuses a library whose version it does not know, so a stale DLL in
/// `dist/` degrades to the Python fallback instead of misreading structs.
///
///   v1 — entropy, search, PE, classification, hashing
///   v2 — + NTFS MFT boot sector, record blocks, run lists
pub const ABI_VERSION: u32 = 2;

/// Returned when input pointers are null or lengths are nonsensical.
const ERR_INVALID: isize = -1;

// --- helpers ---------------------------------------------------------------

/// Borrow a caller-supplied buffer. Empty is represented as an empty slice
/// rather than an error: a zero-length region is a normal thing to score.
unsafe fn as_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        if len == 0 {
            return Some(&[]);
        }
        return None;
    }
    Some(slice::from_raw_parts(ptr, len))
}

unsafe fn as_out<'a, T>(ptr: *mut T, cap: usize) -> Option<&'a mut [T]> {
    if ptr.is_null() {
        return None;
    }
    Some(slice::from_raw_parts_mut(ptr, cap))
}

/// Borrow a NUL-terminated UTF-8 string. Invalid UTF-8 is replaced rather
/// than rejected — these are protection/type labels the host produced, and a
/// mangled one should classify as "nothing to see", not abort the scan.
unsafe fn as_str(ptr: *const std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    Some(std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned())
}

// --- version ---------------------------------------------------------------

#[no_mangle]
pub extern "C" fn aetheris_abi_version() -> u32 {
    ABI_VERSION
}

// --- entropy + search (ABI-compatible with entropy_rs) ---------------------

/// Shannon entropy (bits/byte, 0.0..=8.0) of the whole buffer.
#[no_mangle]
pub extern "C" fn aetheris_entropy(ptr: *const u8, len: usize) -> f64 {
    catch_unwind(|| match unsafe { as_slice(ptr, len) } {
        Some(d) => scan::shannon(d),
        None => 0.0,
    })
    .unwrap_or(0.0)
}

/// Maximum entropy over non-overlapping `window`-byte tiles. `window == 0`
/// scores the whole buffer.
#[no_mangle]
pub extern "C" fn aetheris_max_window_entropy(ptr: *const u8, len: usize, window: usize) -> f64 {
    catch_unwind(|| match unsafe { as_slice(ptr, len) } {
        Some(d) => scan::max_window_entropy(d, window),
        None => 0.0,
    })
    .unwrap_or(0.0)
}

/// First offset of `pat`, or -1 if absent / invalid.
#[no_mangle]
pub extern "C" fn aetheris_find(
    ptr: *const u8,
    len: usize,
    pat: *const u8,
    pat_len: usize,
) -> isize {
    catch_unwind(|| {
        let (Some(d), Some(p)) = (unsafe { as_slice(ptr, len) }, unsafe {
            as_slice(pat, pat_len)
        }) else {
            return ERR_INVALID;
        };
        scan::find(d, p).map(|v| v as isize).unwrap_or(ERR_INVALID)
    })
    .unwrap_or(ERR_INVALID)
}

/// Every non-overlapping offset of `pat`, written into `out`. Returns the
/// count written, or -1 on invalid input.
#[no_mangle]
pub extern "C" fn aetheris_find_all(
    ptr: *const u8,
    len: usize,
    pat: *const u8,
    pat_len: usize,
    out: *mut u64,
    cap: usize,
) -> isize {
    catch_unwind(|| {
        let (Some(d), Some(p), Some(o)) = (
            unsafe { as_slice(ptr, len) },
            unsafe { as_slice(pat, pat_len) },
            unsafe { as_out(out, cap) },
        ) else {
            return ERR_INVALID;
        };
        let hits = scan::find_all(d, p, cap);
        for (slot, hit) in o.iter_mut().zip(hits.iter()) {
            *slot = *hit as u64;
        }
        hits.len() as isize
    })
    .unwrap_or(ERR_INVALID)
}

// --- region classification -------------------------------------------------

/// Classify a memory region. Returns 0 (nothing), 1 (rwx), 2 (unbacked-exec),
/// or 3 (private-pe); -1 on invalid input.
#[no_mangle]
pub extern "C" fn aetheris_classify_region(
    protect: *const std::os::raw::c_char,
    region_type: *const std::os::raw::c_char,
) -> i32 {
    catch_unwind(|| {
        let (Some(p), Some(t)) = (unsafe { as_str(protect) }, unsafe { as_str(region_type) })
        else {
            return -1;
        };
        classify::classify_region(&p, &t).map(|k| k.code()).unwrap_or(0)
    })
    .unwrap_or(-1)
}

/// Promote an unbacked-exec verdict to private-pe given the region's head
/// bytes. Any other `kind` is returned unchanged.
#[no_mangle]
pub extern "C" fn aetheris_promote_kind(kind: i32, head: *const u8, head_len: usize) -> i32 {
    catch_unwind(|| {
        let (Some(k), Some(h)) = (classify::Kind::from_code(kind), unsafe {
            as_slice(head, head_len)
        }) else {
            return kind;
        };
        classify::promote(k, h).code()
    })
    .unwrap_or(kind)
}

/// Threat score for a kind code, matching `injection.SCORE`. 0 if unknown.
#[no_mangle]
pub extern "C" fn aetheris_kind_score(kind: i32) -> i32 {
    classify::Kind::from_code(kind).map(|k| k.score()).unwrap_or(0)
}

// --- PE --------------------------------------------------------------------

/// Mirrors `pe::PeInfo` across the ABI. All-`u32` then the one `u64` keeps
/// the layout free of implicit padding, so the ctypes struct on the host
/// matches without any packing directives.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct CPeInfo {
    pub is_64: u32,
    pub machine: u32,
    pub num_sections: u32,
    pub timestamp: u32,
    pub characteristics: u32,
    pub entry_point: u32,
    pub size_of_image: u32,
    pub subsystem: u32,
    pub dll_characteristics: u32,
    pub nt_offset: u32,
    pub image_base: u64,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct CPeSection {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub characteristics: u32,
}

/// 1 if the buffer starts with a structurally valid PE image, else 0.
#[no_mangle]
pub extern "C" fn aetheris_pe_is_valid(ptr: *const u8, len: usize) -> i32 {
    catch_unwind(|| match unsafe { as_slice(ptr, len) } {
        Some(d) if pe::is_pe(d) => 1,
        _ => 0,
    })
    .unwrap_or(0)
}

/// Parse PE headers into `out`. Returns 1 on success, 0 if not a PE, -1 on
/// invalid input.
#[no_mangle]
pub extern "C" fn aetheris_pe_parse(ptr: *const u8, len: usize, out: *mut CPeInfo) -> i32 {
    catch_unwind(|| {
        let (Some(d), false) = (unsafe { as_slice(ptr, len) }, out.is_null()) else {
            return -1;
        };
        let Some(i) = pe::parse(d) else { return 0 };
        unsafe {
            *out = CPeInfo {
                is_64: i.is_64 as u32,
                machine: i.machine as u32,
                num_sections: i.num_sections as u32,
                timestamp: i.timestamp,
                characteristics: i.characteristics as u32,
                entry_point: i.entry_point,
                size_of_image: i.size_of_image,
                subsystem: i.subsystem as u32,
                dll_characteristics: i.dll_characteristics as u32,
                nt_offset: i.nt_offset,
                image_base: i.image_base,
            };
        }
        1
    })
    .unwrap_or(-1)
}

/// Fill `out` with up to `cap` section headers. Returns the count, or -1.
#[no_mangle]
pub extern "C" fn aetheris_pe_sections(
    ptr: *const u8,
    len: usize,
    out: *mut CPeSection,
    cap: usize,
) -> isize {
    catch_unwind(|| {
        let (Some(d), Some(o)) = (unsafe { as_slice(ptr, len) }, unsafe { as_out(out, cap) })
        else {
            return ERR_INVALID;
        };
        let secs = pe::sections(d, cap);
        for (slot, s) in o.iter_mut().zip(secs.iter()) {
            *slot = CPeSection {
                name: s.name,
                virtual_size: s.virtual_size,
                virtual_address: s.virtual_address,
                raw_size: s.raw_size,
                raw_ptr: s.raw_ptr,
                characteristics: s.characteristics,
            };
        }
        secs.len() as isize
    })
    .unwrap_or(ERR_INVALID)
}

/// Carve PE images from a raw buffer, writing their offsets into `out`.
/// Scans on `stride` boundaries. Returns the count, or -1.
#[no_mangle]
pub extern "C" fn aetheris_pe_carve(
    ptr: *const u8,
    len: usize,
    stride: usize,
    out: *mut u64,
    cap: usize,
) -> isize {
    catch_unwind(|| {
        let (Some(d), Some(o)) = (unsafe { as_slice(ptr, len) }, unsafe { as_out(out, cap) })
        else {
            return ERR_INVALID;
        };
        let hits = pe::carve(d, stride, cap);
        for (slot, hit) in o.iter_mut().zip(hits.iter()) {
            *slot = *hit as u64;
        }
        hits.len() as isize
    })
    .unwrap_or(ERR_INVALID)
}

/// Offsets where `tag` sits on a `stride` boundary — the pool-tag sweep used
/// to surface allocations (`Proc`, `Thre`, `File`) in a physical image.
#[no_mangle]
pub extern "C" fn aetheris_carve_aligned(
    ptr: *const u8,
    len: usize,
    tag: *const u8,
    tag_len: usize,
    stride: usize,
    out: *mut u64,
    cap: usize,
) -> isize {
    catch_unwind(|| {
        let (Some(d), Some(t), Some(o)) = (
            unsafe { as_slice(ptr, len) },
            unsafe { as_slice(tag, tag_len) },
            unsafe { as_out(out, cap) },
        ) else {
            return ERR_INVALID;
        };
        let hits = scan::find_aligned(d, t, stride, cap);
        for (slot, hit) in o.iter_mut().zip(hits.iter()) {
            *slot = *hit as u64;
        }
        hits.len() as isize
    })
    .unwrap_or(ERR_INVALID)
}

// --- NTFS MFT --------------------------------------------------------------

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct CBootInfo {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub cluster_size: u32,
    pub record_size: u32,
    pub mft_cluster: u64,
}

/// One parsed FILE record. The name is inline UTF-16 rather than a pointer so
/// a whole block crosses the boundary in a single copy with nothing to free.
/// 255 is the NTFS maximum name length; `name_len` is in UTF-16 code units.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CMftRecord {
    pub index: u64,
    pub parent_index: u64,
    pub size: u64,
    pub flags: u32, // bit 0 in_use, bit 1 is_directory
    pub name_len: u32,
    pub name: [u16; 255],
    pub _pad: u16,
}

impl Default for CMftRecord {
    fn default() -> Self {
        CMftRecord {
            index: 0,
            parent_index: 0,
            size: 0,
            flags: 0,
            name_len: 0,
            name: [0u16; 255],
            _pad: 0,
        }
    }
}

/// Parse the NTFS boot sector. 1 on success, 0 if not NTFS, -1 on bad input.
#[no_mangle]
pub extern "C" fn aetheris_mft_boot_info(
    ptr: *const u8,
    len: usize,
    out: *mut CBootInfo,
) -> i32 {
    catch_unwind(|| {
        let (Some(d), false) = (unsafe { as_slice(ptr, len) }, out.is_null()) else {
            return -1;
        };
        let Some(b) = mft::read_boot_info(d) else { return 0 };
        unsafe {
            *out = CBootInfo {
                bytes_per_sector: b.bytes_per_sector,
                sectors_per_cluster: b.sectors_per_cluster,
                cluster_size: b.cluster_size,
                record_size: b.record_size,
                mft_cluster: b.mft_cluster,
            };
        }
        1
    })
    .unwrap_or(-1)
}

/// Parse a contiguous block of FILE records.
///
/// This is the entry point that earns the port: the Python original ran a
/// dozen `struct.unpack_from` calls per record over tens of thousands of
/// records. Here one call fixes up and decodes an entire block.
///
/// `first_index` is the MFT slot number of the first record in the block, so
/// indices stay correct across extents. Records that fail their fixups or
/// carry no name are skipped, exactly as the Python loop did — so the returned
/// count is <= the number of slots in the block. Returns the count, or -1.
#[no_mangle]
pub extern "C" fn aetheris_mft_parse_block(
    ptr: *const u8,
    len: usize,
    record_size: usize,
    bytes_per_sector: usize,
    first_index: u64,
    out: *mut CMftRecord,
    cap: usize,
) -> isize {
    catch_unwind(|| {
        let (Some(d), Some(o)) = (unsafe { as_slice(ptr, len) }, unsafe { as_out(out, cap) })
        else {
            return ERR_INVALID;
        };
        if record_size == 0 || bytes_per_sector == 0 || record_size > len {
            return ERR_INVALID;
        }
        let mut written = 0usize;
        let mut slot = 0usize;
        let mut pos = 0usize;
        // A private copy per record: fixups mutate, and the caller's buffer is
        // borrowed immutably (it is a Python bytes object).
        let mut scratch = vec![0u8; record_size];
        while pos + record_size <= d.len() && written < cap {
            let chunk = &d[pos..pos + record_size];
            pos += record_size;
            let index = first_index + slot as u64;
            slot += 1;
            if &chunk[0..4] != mft::FILE_SIGNATURE {
                continue;
            }
            scratch.copy_from_slice(chunk);
            if !mft::apply_fixups(&mut scratch, bytes_per_sector) {
                continue;
            }
            let Some(rec) = mft::parse_record(&scratch, index) else {
                continue;
            };
            if rec.name.is_empty() {
                continue;
            }
            let slot_out = &mut o[written];
            *slot_out = CMftRecord::default();
            slot_out.index = rec.index;
            slot_out.parent_index = rec.parent_index;
            slot_out.size = rec.size;
            slot_out.flags =
                (rec.in_use as u32) | ((rec.is_directory as u32) << 1);
            let units: Vec<u16> = rec.name.encode_utf16().take(255).collect();
            slot_out.name[..units.len()].copy_from_slice(&units);
            slot_out.name_len = units.len() as u32;
            written += 1;
        }
        written as isize
    })
    .unwrap_or(ERR_INVALID)
}

/// Decode a mapping-pairs (data-run) list starting at `pos`. Byte offsets go
/// to `out_offsets` and byte lengths to `out_lengths`. Returns the count.
#[no_mangle]
pub extern "C" fn aetheris_mft_run_list(
    ptr: *const u8,
    len: usize,
    pos: usize,
    cluster_size: u64,
    out_offsets: *mut u64,
    out_lengths: *mut u64,
    cap: usize,
) -> isize {
    catch_unwind(|| {
        let (Some(d), Some(offs), Some(lens)) = (
            unsafe { as_slice(ptr, len) },
            unsafe { as_out(out_offsets, cap) },
            unsafe { as_out(out_lengths, cap) },
        ) else {
            return ERR_INVALID;
        };
        let extents = mft::parse_run_list(d, pos, cluster_size);
        let n = extents.len().min(cap);
        for i in 0..n {
            offs[i] = extents[i].0;
            lens[i] = extents[i].1;
        }
        n as isize
    })
    .unwrap_or(ERR_INVALID)
}

// --- hashing ---------------------------------------------------------------

/// SHA-256 of the buffer into a caller-supplied 32-byte `out`. Returns 0 on
/// success, -1 on invalid input.
#[no_mangle]
pub extern "C" fn aetheris_sha256(ptr: *const u8, len: usize, out: *mut u8) -> i32 {
    catch_unwind(|| {
        let (Some(d), Some(o)) = (unsafe { as_slice(ptr, len) }, unsafe { as_out(out, 32) }) else {
            return -1;
        };
        o.copy_from_slice(&hash::sha256(d));
        0
    })
    .unwrap_or(-1)
}

#[cfg(test)]
mod ffi_tests {
    use super::*;

    #[test]
    fn null_inputs_never_panic() {
        assert_eq!(aetheris_entropy(std::ptr::null(), 16), 0.0);
        assert_eq!(aetheris_find(std::ptr::null(), 8, b"MZ".as_ptr(), 2), -1);
        assert_eq!(aetheris_pe_is_valid(std::ptr::null(), 64), 0);
        assert_eq!(aetheris_pe_parse(std::ptr::null(), 64, std::ptr::null_mut()), -1);
        assert_eq!(aetheris_classify_region(std::ptr::null(), std::ptr::null()), -1);
        assert_eq!(aetheris_sha256(std::ptr::null(), 4, std::ptr::null_mut()), -1);
    }

    #[test]
    fn a_null_pointer_with_zero_length_is_an_empty_buffer() {
        assert_eq!(aetheris_entropy(std::ptr::null(), 0), 0.0);
    }

    #[test]
    fn find_all_respects_capacity() {
        let data = b"MZMZMZMZ";
        let mut out = [0u64; 2];
        let n = aetheris_find_all(data.as_ptr(), data.len(), b"MZ".as_ptr(), 2, out.as_mut_ptr(), 2);
        assert_eq!(n, 2);
        assert_eq!(out, [0, 2]);
    }

    #[test]
    fn classify_over_the_abi() {
        let rwx = std::ffi::CString::new("rwx").unwrap();
        let private = std::ffi::CString::new("private").unwrap();
        let image = std::ffi::CString::new("image").unwrap();
        let rx = std::ffi::CString::new("r-x").unwrap();
        assert_eq!(aetheris_classify_region(rwx.as_ptr(), private.as_ptr()), 1);
        assert_eq!(aetheris_classify_region(rx.as_ptr(), private.as_ptr()), 2);
        assert_eq!(aetheris_classify_region(rx.as_ptr(), image.as_ptr()), 0);
        assert_eq!(aetheris_promote_kind(2, b"MZ".as_ptr(), 2), 3);
        assert_eq!(aetheris_promote_kind(1, b"MZ".as_ptr(), 2), 1);
        assert_eq!(aetheris_kind_score(3), 75);
    }

    #[test]
    fn sha256_over_the_abi() {
        let mut out = [0u8; 32];
        assert_eq!(aetheris_sha256(b"abc".as_ptr(), 3, out.as_mut_ptr()), 0);
        assert_eq!(
            hash::hex(&out),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn abi_version_is_exposed() {
        assert_eq!(aetheris_abi_version(), ABI_VERSION);
    }

    /// These structs are shared with the ctypes definitions in
    /// `aetheris/native/core.py` by memory layout alone, and the MFT one is
    /// additionally decoded with a hand-written struct format string. A field
    /// reordered on one side would misread every record rather than raise, so
    /// the sizes are pinned on both sides.
    #[test]
    fn c_struct_layouts_are_stable() {
        use std::mem::size_of;
        assert_eq!(size_of::<CPeInfo>(), 48);
        assert_eq!(size_of::<CPeSection>(), 28);
        assert_eq!(size_of::<CBootInfo>(), 24);
        assert_eq!(size_of::<CMftRecord>(), 544);
        // The name array must start at 32: aetheris/native/core.py unpacks the
        // five leading fields with "<QQQII" and slices the name from there.
        let r = CMftRecord::default();
        let base = &r as *const _ as usize;
        assert_eq!(&r.name as *const _ as usize - base, 32);
    }
}
