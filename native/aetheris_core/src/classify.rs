//! Injection / anomaly classification for a process memory region.
//!
//! Ports `forensics/injection.py::classify_region` byte-for-byte, including
//! its scores, so the native and Python paths agree on every verdict. The
//! Python side stays as the fallback, and `tests/test_injection.py` pins both
//! to the same table.

/// What a region looks like. `None` is the ordinary case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Writable *and* executable — shellcode staging.
    Rwx,
    /// Executable memory not backed by an image file on disk.
    UnbackedExec,
    /// A PE image mapped into private memory — a module loaded without the
    /// loader. Promoted from `UnbackedExec` once an `MZ` header is confirmed.
    PrivatePe,
}

impl Kind {
    /// Stable wire value for the C ABI. 0 means "no finding".
    pub fn code(self) -> i32 {
        match self {
            Kind::Rwx => 1,
            Kind::UnbackedExec => 2,
            Kind::PrivatePe => 3,
        }
    }

    /// Threat score, matching `injection.SCORE`.
    pub fn score(self) -> i32 {
        match self {
            Kind::Rwx => 55,
            Kind::UnbackedExec => 55,
            Kind::PrivatePe => 75,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::Rwx => "rwx",
            Kind::UnbackedExec => "unbacked-exec",
            Kind::PrivatePe => "private-pe",
        }
    }

    pub fn from_code(code: i32) -> Option<Kind> {
        match code {
            1 => Some(Kind::Rwx),
            2 => Some(Kind::UnbackedExec),
            3 => Some(Kind::PrivatePe),
            _ => None,
        }
    }
}

/// Classify a region from its protection string (`"rwx"`, `"r-x"`, …) and
/// type (`"image"`, `"private"`, `"mapped"`).
///
/// The protection string is matched case-insensitively on the presence of
/// `w` and `x`, exactly as the Python original does — which means the
/// `"rwxc"` / `"+guard"` decorations both backends emit fall out correctly
/// without special-casing.
pub fn classify_region(protect: &str, region_type: &str) -> Option<Kind> {
    let p = protect.to_ascii_lowercase();
    let is_exec = p.contains('x');
    let is_write = p.contains('w');
    if is_exec && is_write {
        return Some(Kind::Rwx);
    }
    if is_exec && region_type != "image" {
        return Some(Kind::UnbackedExec);
    }
    None
}

/// Promote an `UnbackedExec` verdict to `PrivatePe` when the region's first
/// bytes are an `MZ` header. Any other verdict passes through untouched.
pub fn promote(kind: Kind, head: &[u8]) -> Kind {
    if kind == Kind::UnbackedExec && head.len() >= 2 && &head[..2] == b"MZ" {
        Kind::PrivatePe
    } else {
        kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rwx_wins_over_unbacked() {
        assert_eq!(classify_region("rwx", "private"), Some(Kind::Rwx));
        assert_eq!(classify_region("rwx", "image"), Some(Kind::Rwx));
        assert_eq!(classify_region("rwxc", "image"), Some(Kind::Rwx));
    }

    #[test]
    fn unbacked_exec_needs_a_non_image_type() {
        assert_eq!(classify_region("r-x", "private"), Some(Kind::UnbackedExec));
        assert_eq!(classify_region("r-x", "mapped"), Some(Kind::UnbackedExec));
        assert_eq!(classify_region("r-x", "image"), None);
    }

    #[test]
    fn ordinary_regions_are_not_flagged() {
        assert_eq!(classify_region("rw-", "private"), None);
        assert_eq!(classify_region("r--", "image"), None);
        assert_eq!(classify_region("---", "private"), None);
        assert_eq!(classify_region("", "private"), None);
    }

    #[test]
    fn guard_decoration_does_not_break_matching() {
        assert_eq!(classify_region("r-x+guard", "private"), Some(Kind::UnbackedExec));
        // "+guard" contains no 'w' or 'x' of its own beyond the protection bits
        assert_eq!(classify_region("rw-+guard", "private"), None);
    }

    #[test]
    fn promotion_requires_an_mz_header() {
        assert_eq!(promote(Kind::UnbackedExec, b"MZ\x90\x00"), Kind::PrivatePe);
        assert_eq!(promote(Kind::UnbackedExec, b"ZM"), Kind::UnbackedExec);
        assert_eq!(promote(Kind::UnbackedExec, b"M"), Kind::UnbackedExec);
        assert_eq!(promote(Kind::UnbackedExec, b""), Kind::UnbackedExec);
        // rwx is never promoted, even over a PE header
        assert_eq!(promote(Kind::Rwx, b"MZ"), Kind::Rwx);
    }

    #[test]
    fn scores_match_the_python_table() {
        assert_eq!(Kind::Rwx.score(), 55);
        assert_eq!(Kind::UnbackedExec.score(), 55);
        assert_eq!(Kind::PrivatePe.score(), 75);
    }

    #[test]
    fn codes_round_trip() {
        for k in [Kind::Rwx, Kind::UnbackedExec, Kind::PrivatePe] {
            assert_eq!(Kind::from_code(k.code()), Some(k));
        }
        assert_eq!(Kind::from_code(0), None);
        assert_eq!(Kind::from_code(99), None);
    }
}
