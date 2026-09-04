//! PE (Portable Executable) header parsing and carving.
//!
//! Two jobs. **Parsing** backs static triage — sections, per-section entropy,
//! entry point, characteristics. **Carving** finds PE images in a raw buffer
//! that has no file system to describe it: a physical-memory image, or the
//! private memory of a process that mapped a module without the loader.
//!
//! Everything is bounds-checked against the supplied slice. Carving in
//! particular runs over untrusted, half-overwritten memory, where a truncated
//! or deliberately malformed header is the normal case, not the exception —
//! so every field read is fallible and a bad header yields None, never a panic.

pub const DOS_MAGIC: u16 = 0x5A4D; // "MZ"
pub const NT_SIGNATURE: u32 = 0x0000_4550; // "PE\0\0"
pub const PE32_MAGIC: u16 = 0x010B;
pub const PE32PLUS_MAGIC: u16 = 0x020B;

const SECTION_HEADER_SIZE: usize = 40;

/// Parsed PE headers. Field-for-field mirrored by the `PeInfo` C struct in
/// `lib.rs`, so the layout here is part of the ABI — append, never reorder.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PeInfo {
    pub is_64: bool,
    pub machine: u16,
    pub num_sections: u16,
    pub timestamp: u32,
    pub characteristics: u16,
    pub entry_point: u32,
    pub image_base: u64,
    pub size_of_image: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub nt_offset: u32,
}

/// One section header.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PeSection {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_ptr: u32,
    pub characteristics: u32,
}

impl PeSection {
    /// Section name as text, trimmed of its NUL padding.
    pub fn name_str(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }

    /// IMAGE_SCN_MEM_EXECUTE
    pub fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    /// IMAGE_SCN_MEM_WRITE
    pub fn is_writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }
}

fn u16_at(d: &[u8], off: usize) -> Option<u16> {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(d: &[u8], off: usize) -> Option<u32> {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(d: &[u8], off: usize) -> Option<u64> {
    d.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Offset of the NT headers if `data` starts with a structurally valid PE.
fn nt_offset(data: &[u8]) -> Option<usize> {
    if u16_at(data, 0)? != DOS_MAGIC {
        return None;
    }
    let nt = u32_at(data, 0x3C)? as usize;
    // A wild e_lfanew is the usual shape of a false MZ hit while carving.
    if nt < 0x40 || nt > data.len().saturating_sub(24) {
        return None;
    }
    if u32_at(data, nt)? != NT_SIGNATURE {
        return None;
    }
    Some(nt)
}

/// True when `data` begins with a structurally valid PE image.
pub fn is_pe(data: &[u8]) -> bool {
    nt_offset(data).is_some()
}

/// Parse the DOS + NT headers at the start of `data`.
pub fn parse(data: &[u8]) -> Option<PeInfo> {
    let nt = nt_offset(data)?;
    let file = nt + 4; // IMAGE_FILE_HEADER
    let opt = nt + 24; // IMAGE_OPTIONAL_HEADER

    let magic = u16_at(data, opt)?;
    let is_64 = match magic {
        PE32PLUS_MAGIC => true,
        PE32_MAGIC => false,
        _ => return None,
    };

    // ImageBase is the one field whose offset differs between the two
    // optional-header layouts: PE32+ widens it to 8 bytes and drops BaseOfData.
    let image_base = if is_64 {
        u64_at(data, opt + 24)?
    } else {
        u32_at(data, opt + 28)? as u64
    };

    Some(PeInfo {
        is_64,
        machine: u16_at(data, file)?,
        num_sections: u16_at(data, file + 2)?,
        timestamp: u32_at(data, file + 4)?,
        characteristics: u16_at(data, file + 18)?,
        entry_point: u32_at(data, opt + 16)?,
        image_base,
        size_of_image: u32_at(data, opt + 56)?,
        subsystem: u16_at(data, opt + 68)?,
        dll_characteristics: u16_at(data, opt + 70)?,
        nt_offset: nt as u32,
    })
}

/// Parse the section table. Returns at most `limit` entries.
pub fn sections(data: &[u8], limit: usize) -> Vec<PeSection> {
    let mut out = Vec::new();
    let (nt, info) = match (nt_offset(data), parse(data)) {
        (Some(nt), Some(info)) => (nt, info),
        _ => return out,
    };
    let size_of_optional = match u16_at(data, nt + 20) {
        Some(v) => v as usize,
        None => return out,
    };
    let mut off = nt + 24 + size_of_optional;
    let count = (info.num_sections as usize).min(limit);
    for _ in 0..count {
        let Some(chunk) = data.get(off..off + SECTION_HEADER_SIZE) else {
            break;
        };
        let mut name = [0u8; 8];
        name.copy_from_slice(&chunk[0..8]);
        out.push(PeSection {
            name,
            virtual_size: u32::from_le_bytes([chunk[8], chunk[9], chunk[10], chunk[11]]),
            virtual_address: u32::from_le_bytes([chunk[12], chunk[13], chunk[14], chunk[15]]),
            raw_size: u32::from_le_bytes([chunk[16], chunk[17], chunk[18], chunk[19]]),
            raw_ptr: u32::from_le_bytes([chunk[20], chunk[21], chunk[22], chunk[23]]),
            characteristics: u32::from_le_bytes([chunk[36], chunk[37], chunk[38], chunk[39]]),
        });
        off += SECTION_HEADER_SIZE;
    }
    out
}

/// Carve PE images out of a raw buffer.
///
/// Scans on `stride` boundaries (pass the page size for a physical-memory
/// image; a mapped module always starts on a page) and keeps only offsets
/// whose headers actually parse — an `MZ` pair alone is far too common in
/// arbitrary memory to report on its own.
pub fn carve(data: &[u8], stride: usize, limit: usize) -> Vec<usize> {
    let mut out = Vec::new();
    if stride == 0 || limit == 0 {
        return out;
    }
    let mut off = 0usize;
    while off + 2 <= data.len() {
        if data[off] == b'M' && data[off + 1] == b'Z' && is_pe(&data[off..]) {
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

    /// Build a minimal but structurally valid PE32+ with `n` sections.
    fn synth_pe(sections: &[(&str, u32)]) -> Vec<u8> {
        let nt = 0x80usize;
        let size_of_optional = 240usize;
        let mut b = vec![0u8; nt + 24 + size_of_optional + sections.len() * SECTION_HEADER_SIZE];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&(nt as u32).to_le_bytes());
        b[nt..nt + 4].copy_from_slice(&NT_SIGNATURE.to_le_bytes());
        // IMAGE_FILE_HEADER
        b[nt + 4..nt + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // machine x64
        b[nt + 6..nt + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        b[nt + 8..nt + 12].copy_from_slice(&0x6642_1337u32.to_le_bytes()); // timestamp
        b[nt + 20..nt + 22].copy_from_slice(&(size_of_optional as u16).to_le_bytes());
        b[nt + 22..nt + 24].copy_from_slice(&0x0022u16.to_le_bytes()); // characteristics
        // IMAGE_OPTIONAL_HEADER64
        let opt = nt + 24;
        b[opt..opt + 2].copy_from_slice(&PE32PLUS_MAGIC.to_le_bytes());
        b[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point
        b[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes()); // image base
        b[opt + 56..opt + 60].copy_from_slice(&0x2_0000u32.to_le_bytes()); // size of image
        b[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes()); // subsystem GUI
        b[opt + 70..opt + 72].copy_from_slice(&0x0160u16.to_le_bytes()); // dll characteristics
        // sections
        let mut so = opt + size_of_optional;
        for (name, chars) in sections {
            let nb = name.as_bytes();
            b[so..so + nb.len().min(8)].copy_from_slice(&nb[..nb.len().min(8)]);
            b[so + 8..so + 12].copy_from_slice(&0x1000u32.to_le_bytes());
            b[so + 12..so + 16].copy_from_slice(&0x1000u32.to_le_bytes());
            b[so + 16..so + 20].copy_from_slice(&0x200u32.to_le_bytes());
            b[so + 20..so + 24].copy_from_slice(&0x400u32.to_le_bytes());
            b[so + 36..so + 40].copy_from_slice(&chars.to_le_bytes());
            so += SECTION_HEADER_SIZE;
        }
        b
    }

    #[test]
    fn parses_a_pe64() {
        let b = synth_pe(&[(".text", 0x6000_0020)]);
        let info = parse(&b).expect("should parse");
        assert!(info.is_64);
        assert_eq!(info.machine, 0x8664);
        assert_eq!(info.num_sections, 1);
        assert_eq!(info.entry_point, 0x1000);
        assert_eq!(info.image_base, 0x1_4000_0000);
        assert_eq!(info.size_of_image, 0x2_0000);
        assert_eq!(info.subsystem, 2);
        assert_eq!(info.timestamp, 0x6642_1337);
    }

    #[test]
    fn parses_pe32_image_base_at_its_own_offset() {
        let mut b = synth_pe(&[(".text", 0)]);
        let opt = 0x80 + 24;
        b[opt..opt + 2].copy_from_slice(&PE32_MAGIC.to_le_bytes());
        b[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        let info = parse(&b).expect("should parse");
        assert!(!info.is_64);
        assert_eq!(info.image_base, 0x0040_0000);
    }

    #[test]
    fn reads_the_section_table() {
        let b = synth_pe(&[(".text", 0x6000_0020), (".data", 0xC000_0040)]);
        let s = sections(&b, 16);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].name_str(), ".text");
        assert!(s[0].is_executable() && !s[0].is_writable());
        assert_eq!(s[1].name_str(), ".data");
        assert!(s[1].is_writable() && !s[1].is_executable());
        assert_eq!(s[0].virtual_address, 0x1000);
    }

    #[test]
    fn section_limit_is_honoured() {
        let b = synth_pe(&[(".a", 0), (".b", 0), (".c", 0)]);
        assert_eq!(sections(&b, 2).len(), 2);
    }

    #[test]
    fn rejects_junk_and_truncation() {
        assert!(!is_pe(b""));
        assert!(!is_pe(b"MZ"));
        assert!(!is_pe(&[0u8; 512]));
        // valid header, then truncated before the NT headers
        let b = synth_pe(&[(".text", 0)]);
        assert!(!is_pe(&b[..0x60]));
        assert!(parse(&b[..0x60]).is_none());
    }

    #[test]
    fn rejects_an_mz_with_a_wild_e_lfanew() {
        let mut b = vec![0u8; 4096];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(!is_pe(&b));
    }

    #[test]
    fn carves_only_real_headers_on_page_boundaries() {
        let pe = synth_pe(&[(".text", 0x6000_0020)]);
        let mut buf = vec![0u8; 4096 * 4];
        buf[0..pe.len()].copy_from_slice(&pe);
        buf[8192..8192 + pe.len()].copy_from_slice(&pe);
        // a bare MZ with no valid NT headers, and an unaligned real one
        buf[4096..4098].copy_from_slice(b"MZ");
        buf[5000..5000 + pe.len()].copy_from_slice(&pe);
        assert_eq!(carve(&buf, 4096, 32), vec![0, 8192]);
    }
}
