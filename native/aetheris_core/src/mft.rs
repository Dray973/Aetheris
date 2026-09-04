//! NTFS Master File Table record parsing.
//!
//! Ports the pure-byte half of `storage/mft.py`: boot-sector geometry, the
//! update-sequence (fixup) array, FILE record decoding, and mapping-pairs
//! (data-run) lists. The raw volume handle stays on the Python side — this
//! crate makes no OS calls — so the split is exactly "Rust crunches the bytes,
//! Python owns the file".
//!
//! Every input here is attacker-controllable: a FILE record is on-disk data
//! that a hostile volume can shape freely, and a truncated or malformed record
//! is the normal case when scanning unallocated MFT slots. Nothing indexes
//! without a bounds check, and a bad record yields None rather than panicking.

pub const FILE_SIGNATURE: &[u8; 4] = b"FILE";
pub const ATTR_FILE_NAME: u32 = 0x30;
pub const ATTR_DATA: u32 = 0x80;
pub const ATTR_END: u32 = 0xFFFF_FFFF;

/// The DOS 8.3 namespace. A record often carries both a long name and its
/// short alias; the long one wins unless nothing else has been seen.
const NAMESPACE_DOS: u8 = 2;

#[derive(Debug, Clone, PartialEq)]
pub struct MftRecord {
    pub index: u64,
    pub in_use: bool,
    pub is_directory: bool,
    pub name: String,
    pub size: u64,
    pub parent_index: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootInfo {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub cluster_size: u32,
    pub mft_cluster: u64,
    pub record_size: u32,
}

impl BootInfo {
    pub fn mft_offset(&self) -> u64 {
        self.mft_cluster * self.cluster_size as u64
    }
}

fn u16_at(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(d: &[u8], off: usize) -> Option<u64> {
    d.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Parse the NTFS boot sector for MFT geometry. None if it is not NTFS.
pub fn read_boot_info(boot: &[u8]) -> Option<BootInfo> {
    if boot.len() < 0x41 || boot.get(3..11)? != b"NTFS    " {
        return None;
    }
    let bps = u16_at(boot, 0x0B)? as u32;
    let spc = *boot.get(0x0D)? as u32;
    let mft_cluster = u64_at(boot, 0x30)?;
    // A positive value is a cluster count; a negative one is a log2 byte size.
    let raw = *boot.get(0x40)? as i8;
    let record_size = if raw >= 0 {
        (raw as u32).checked_mul(spc)?.checked_mul(bps)?
    } else {
        1u32.checked_shl((-raw) as u32)?
    };
    if bps == 0 || spc == 0 || record_size == 0 {
        return None;
    }
    Some(BootInfo {
        bytes_per_sector: bps,
        sectors_per_cluster: spc,
        cluster_size: bps.checked_mul(spc)?,
        mft_cluster,
        record_size,
    })
}

/// Apply the update-sequence array in place. False on an integrity failure or
/// a malformed record — the caller skips the slot rather than trusting it.
pub fn apply_fixups(record: &mut [u8], bytes_per_sector: usize) -> bool {
    let n = record.len();
    if n < 8 || &record[0..4] != FILE_SIGNATURE {
        return false;
    }
    let (usa_off, usa_cnt) = match (u16_at(record, 0x04), u16_at(record, 0x06)) {
        (Some(o), Some(c)) => (o as usize, c as usize),
        _ => return false,
    };
    if usa_cnt == 0 {
        return true;
    }
    if usa_off + usa_cnt * 2 > n {
        return false;
    }
    let usn = [record[usa_off], record[usa_off + 1]];
    for i in 1..usa_cnt {
        // The last two bytes of each sector hold the sequence number; the real
        // bytes live in the array and are swapped back in.
        let sector_end = match i.checked_mul(bytes_per_sector).and_then(|v| v.checked_sub(2)) {
            Some(v) => v,
            None => return false,
        };
        if sector_end + 2 > n {
            return false;
        }
        let fix = [record[usa_off + i * 2], record[usa_off + i * 2 + 1]];
        if record[sector_end..sector_end + 2] != usn {
            return false;
        }
        record[sector_end] = fix[0];
        record[sector_end + 1] = fix[1];
    }
    true
}

/// Decode one FILE record. `record` must already have had fixups applied.
pub fn parse_record(record: &[u8], index: u64) -> Option<MftRecord> {
    let n = record.len();
    if n < 0x18 || record.get(0..4)? != FILE_SIGNATURE {
        return None;
    }
    let flags = u16_at(record, 0x16)?;
    let in_use = flags & 0x01 != 0;
    let is_directory = flags & 0x02 != 0;

    let mut name = String::new();
    let mut size: u64 = 0;
    let mut parent_index: u64 = 0;

    let mut off = u16_at(record, 0x14)? as usize;
    while off + 8 <= n {
        let attr_type = u32_at(record, off)?;
        if attr_type == ATTR_END {
            break;
        }
        let attr_len = u32_at(record, off + 4)? as usize;
        // A zero or absurd length would loop forever or run off the record.
        if attr_len < 16 || off + attr_len > n {
            break;
        }
        let non_resident = record[off + 8];

        if attr_type == ATTR_FILE_NAME && non_resident == 0 && off + 0x16 <= n {
            if let Some(content_off) = u16_at(record, off + 0x14) {
                let base = off + content_off as usize;
                if base + 0x42 <= n {
                    if let Some(parent_ref) = u64_at(record, base) {
                        parent_index = parent_ref & 0x0000_FFFF_FFFF_FFFF;
                    }
                    let name_len = record[base + 0x40] as usize;
                    let namespace = record[base + 0x41];
                    let start = base + 0x42;
                    // Clamp rather than reject: a truncated name still tells us
                    // what the record is, and Python's slicing did the same.
                    let end = (start + name_len * 2).min(n);
                    let cand = decode_utf16le(&record[start..end]);
                    if namespace != NAMESPACE_DOS || name.is_empty() {
                        name = cand;
                    }
                }
            }
        } else if attr_type == ATTR_DATA {
            if non_resident == 0 && off + 0x14 <= n {
                if let Some(v) = u32_at(record, off + 0x10) {
                    size = v as u64;
                }
            } else if non_resident == 1 && off + 0x38 <= n {
                if let Some(v) = u64_at(record, off + 0x30) {
                    size = v;
                }
            }
        }

        off += attr_len;
    }

    Some(MftRecord { index, in_use, is_directory, name, size, parent_index })
}

/// UTF-16LE with replacement for unpaired surrogates, matching Python's
/// `decode("utf-16-le", errors="replace")`.
fn decode_utf16le(bytes: &[u8]) -> String {
    // as_chunks gives [u8; 2] arrays, so from_le_bytes applies directly and a
    // trailing odd byte lands in the discarded remainder rather than needing a
    // length check. This runs once per MFT record name.
    let (pairs, _odd) = bytes.as_chunks::<2>();
    let units: Vec<u16> = pairs.iter().copied().map(u16::from_le_bytes).collect();
    char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Decode a mapping-pairs (data-run) list into physical byte extents.
/// Sparse runs — those with no offset field — carry no clusters and are
/// skipped, matching the Python original.
pub fn parse_run_list(buf: &[u8], mut pos: usize, cluster_size: u64) -> Vec<(u64, u64)> {
    let mut extents = Vec::new();
    let mut lcn: i64 = 0;
    let n = buf.len();
    while pos < n {
        let header = buf[pos];
        pos += 1;
        if header == 0 {
            break;
        }
        let len_bytes = (header & 0x0F) as usize;
        let off_bytes = ((header >> 4) & 0x0F) as usize;
        if len_bytes == 0 || pos + len_bytes + off_bytes > n {
            break;
        }
        let run_len = le_uint(&buf[pos..pos + len_bytes]);
        pos += len_bytes;
        if off_bytes == 0 {
            continue; // sparse run
        }
        let run_off = le_int(&buf[pos..pos + off_bytes]);
        pos += off_bytes;
        lcn += run_off;
        if lcn < 0 || run_len == 0 {
            continue;
        }
        extents.push((lcn as u64 * cluster_size, run_len * cluster_size));
    }
    extents
}

fn le_uint(bytes: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for (i, &b) in bytes.iter().enumerate().take(8) {
        v |= (b as u64) << (i * 8);
    }
    v
}

/// Little-endian signed integer of 1..=8 bytes (run offsets are deltas).
fn le_int(bytes: &[u8]) -> i64 {
    let v = le_uint(bytes);
    let bits = bytes.len().min(8) * 8;
    if bits < 64 && v & (1 << (bits - 1)) != 0 {
        (v | !((1u64 << bits) - 1)) as i64
    } else {
        v as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn boot_sector(bps: u16, spc: u8, mft_cluster: u64, rec: i8) -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[3..11].copy_from_slice(b"NTFS    ");
        b[0x0B..0x0D].copy_from_slice(&bps.to_le_bytes());
        b[0x0D] = spc;
        b[0x30..0x38].copy_from_slice(&mft_cluster.to_le_bytes());
        b[0x40] = rec as u8;
        b
    }

    #[test]
    fn boot_info_negative_record_size_is_log2() {
        let info = read_boot_info(&boot_sector(512, 8, 786432, -10)).unwrap();
        assert_eq!(info.bytes_per_sector, 512);
        assert_eq!(info.sectors_per_cluster, 8);
        assert_eq!(info.cluster_size, 4096);
        assert_eq!(info.record_size, 1024); // 1 << 10
        assert_eq!(info.mft_cluster, 786432);
        assert_eq!(info.mft_offset(), 786432 * 4096);
    }

    #[test]
    fn boot_info_positive_record_size_is_clusters() {
        let info = read_boot_info(&boot_sector(512, 2, 100, 1)).unwrap();
        assert_eq!(info.record_size, 2 * 512); // 1 cluster = spc * bps
    }

    #[test]
    fn boot_info_rejects_non_ntfs() {
        let mut b = boot_sector(512, 8, 1, -10);
        b[3..11].copy_from_slice(b"FAT32   ");
        assert!(read_boot_info(&b).is_none());
        assert!(read_boot_info(&[]).is_none());
        assert!(read_boot_info(&[0u8; 16]).is_none());
    }

    #[test]
    fn boot_info_rejects_zero_geometry() {
        assert!(read_boot_info(&boot_sector(0, 8, 1, -10)).is_none());
        assert!(read_boot_info(&boot_sector(512, 0, 1, -10)).is_none());
    }

    /// A record whose sector tails carry the USN, ready for fixup.
    fn record_with_fixups(size: usize, bps: usize, usn: u16, real: &[u16]) -> Vec<u8> {
        let mut r = vec![0u8; size];
        r[0..4].copy_from_slice(FILE_SIGNATURE);
        let usa_off = 0x30usize;
        let usa_cnt = real.len() + 1;
        r[0x04..0x06].copy_from_slice(&(usa_off as u16).to_le_bytes());
        r[0x06..0x08].copy_from_slice(&(usa_cnt as u16).to_le_bytes());
        r[usa_off..usa_off + 2].copy_from_slice(&usn.to_le_bytes());
        for (i, &v) in real.iter().enumerate() {
            r[usa_off + (i + 1) * 2..usa_off + (i + 1) * 2 + 2].copy_from_slice(&v.to_le_bytes());
            let end = (i + 1) * bps - 2;
            r[end..end + 2].copy_from_slice(&usn.to_le_bytes());
        }
        r
    }

    #[test]
    fn fixups_swap_the_sector_tails_back() {
        let mut r = record_with_fixups(1024, 512, 0xAAAA, &[0x1111, 0x2222]);
        assert!(apply_fixups(&mut r, 512));
        assert_eq!(&r[510..512], &0x1111u16.to_le_bytes());
        assert_eq!(&r[1022..1024], &0x2222u16.to_le_bytes());
    }

    #[test]
    fn fixups_reject_a_torn_record() {
        let mut r = record_with_fixups(1024, 512, 0xAAAA, &[0x1111, 0x2222]);
        r[1022] = 0x00; // second sector never made it to disk
        assert!(!apply_fixups(&mut r, 512));
    }

    #[test]
    fn fixups_reject_junk_and_truncation() {
        assert!(!apply_fixups(&mut [], 512));
        assert!(!apply_fixups(&mut [0u8; 4], 512));
        let mut not_a_record = vec![0u8; 1024];
        not_a_record[0..4].copy_from_slice(b"BAAD");
        assert!(!apply_fixups(&mut not_a_record, 512));
    }

    #[test]
    fn fixups_with_no_array_are_a_no_op() {
        let mut r = vec![0u8; 1024];
        r[0..4].copy_from_slice(FILE_SIGNATURE);
        r[0x06..0x08].copy_from_slice(&0u16.to_le_bytes());
        assert!(apply_fixups(&mut r, 512));
    }

    /// Build a FILE record with one $FILE_NAME and one resident $DATA.
    fn synth_record(name: &str, namespace: u8, parent: u64, size: u32, dir: bool) -> Vec<u8> {
        let mut r = vec![0u8; 1024];
        r[0..4].copy_from_slice(FILE_SIGNATURE);
        r[0x06..0x08].copy_from_slice(&0u16.to_le_bytes()); // no fixup array
        let attr_off = 0x38usize;
        r[0x14..0x16].copy_from_slice(&(attr_off as u16).to_le_bytes());
        r[0x16..0x18].copy_from_slice(&(if dir { 0x03u16 } else { 0x01u16 }).to_le_bytes());

        // $FILE_NAME
        let units: Vec<u16> = name.encode_utf16().collect();
        let content_off = 0x18usize;
        let content_len = 0x42 + units.len() * 2;
        let attr_len = (content_off + content_len).div_ceil(8) * 8;
        let mut o = attr_off;
        r[o..o + 4].copy_from_slice(&ATTR_FILE_NAME.to_le_bytes());
        r[o + 4..o + 8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        r[o + 8] = 0; // resident
        r[o + 0x14..o + 0x16].copy_from_slice(&(content_off as u16).to_le_bytes());
        let base = o + content_off;
        r[base..base + 8].copy_from_slice(&parent.to_le_bytes());
        r[base + 0x40] = units.len() as u8;
        r[base + 0x41] = namespace;
        for (i, &u) in units.iter().enumerate() {
            r[base + 0x42 + i * 2..base + 0x42 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        o += attr_len;

        // resident $DATA
        r[o..o + 4].copy_from_slice(&ATTR_DATA.to_le_bytes());
        r[o + 4..o + 8].copy_from_slice(&32u32.to_le_bytes());
        r[o + 8] = 0;
        r[o + 0x10..o + 0x14].copy_from_slice(&size.to_le_bytes());
        o += 32;

        r[o..o + 4].copy_from_slice(&ATTR_END.to_le_bytes());
        r
    }

    #[test]
    fn parses_a_file_record() {
        let raw = synth_record("report.docx", 1, 5, 4096, false);
        let rec = parse_record(&raw, 42).unwrap();
        assert_eq!(rec.index, 42);
        assert_eq!(rec.name, "report.docx");
        assert_eq!(rec.size, 4096);
        assert_eq!(rec.parent_index, 5);
        assert!(rec.in_use && !rec.is_directory);
    }

    #[test]
    fn directory_flag_is_read() {
        let raw = synth_record("Windows", 1, 5, 0, true);
        let rec = parse_record(&raw, 7).unwrap();
        assert!(rec.is_directory && rec.in_use);
    }

    #[test]
    fn parent_reference_is_masked_to_48_bits() {
        // The high 16 bits are a sequence number, not part of the index.
        let raw = synth_record("f", 1, 0xDEAD_0000_0000_0005, 0, false);
        assert_eq!(parse_record(&raw, 1).unwrap().parent_index, 5);
    }

    #[test]
    fn dos_short_name_does_not_override_a_long_one() {
        // A long name already seen wins over a later 8.3 alias.
        let long = synth_record("LongFileName.txt", 1, 5, 0, false);
        assert_eq!(parse_record(&long, 1).unwrap().name, "LongFileName.txt");
        // ...but a DOS name is still taken when it is all there is.
        let dos = synth_record("LONGFI~1.TXT", NAMESPACE_DOS, 5, 0, false);
        assert_eq!(parse_record(&dos, 1).unwrap().name, "LONGFI~1.TXT");
    }

    #[test]
    fn rejects_junk_records() {
        assert!(parse_record(&[], 0).is_none());
        assert!(parse_record(&[0u8; 8], 0).is_none());
        let mut bad = vec![0u8; 1024];
        bad[0..4].copy_from_slice(b"BAAD");
        assert!(parse_record(&bad, 0).is_none());
    }

    #[test]
    fn a_zero_length_attribute_cannot_loop_forever() {
        let mut r = vec![0u8; 1024];
        r[0..4].copy_from_slice(FILE_SIGNATURE);
        r[0x14..0x16].copy_from_slice(&0x38u16.to_le_bytes());
        r[0x38..0x3C].copy_from_slice(&ATTR_DATA.to_le_bytes());
        r[0x3C..0x40].copy_from_slice(&0u32.to_le_bytes()); // length 0
        assert!(parse_record(&r, 1).is_some()); // returns, does not hang
    }

    #[test]
    fn run_list_decodes_offsets_and_lengths() {
        // header 0x21: 1 length byte, 2 offset bytes
        let buf = [0x21, 0x18, 0x34, 0x56, 0x00];
        let ex = parse_run_list(&buf, 0, 4096);
        assert_eq!(ex.len(), 1);
        assert_eq!(ex[0], (0x5634 * 4096, 0x18 * 4096));
    }

    #[test]
    fn run_list_offsets_are_signed_deltas() {
        // second run steps backwards via a negative delta
        let buf = [0x11, 0x10, 0x20, 0x11, 0x10, 0xF0, 0x00];
        let ex = parse_run_list(&buf, 0, 1);
        assert_eq!(ex.len(), 2);
        assert_eq!(ex[0].0, 0x20);
        assert_eq!(ex[1].0, 0x20 - 0x10); // 0xF0 as i8 == -16
    }

    #[test]
    fn run_list_skips_sparse_runs() {
        // header 0x01: length only, no offset -> sparse, carries no clusters
        let buf = [0x01, 0x08, 0x11, 0x04, 0x20, 0x00];
        let ex = parse_run_list(&buf, 0, 1);
        assert_eq!(ex.len(), 1);
        assert_eq!(ex[0], (0x20, 4));
    }

    #[test]
    fn run_list_stops_on_truncation() {
        assert!(parse_run_list(&[0x21, 0x18], 0, 4096).is_empty());
        assert!(parse_run_list(&[], 0, 4096).is_empty());
        assert!(parse_run_list(&[0x00], 0, 4096).is_empty());
    }
}
