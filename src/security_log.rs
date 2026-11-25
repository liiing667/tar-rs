//! Reviewable security records written into the extraction root.
//!
//! When a PAX extended header overrides the name stored in a USTAR header,
//! that override is a security-relevant event: the same archive entry carries
//! two different spellings of its file name (or link name). To make every
//! such decision auditable after extraction, each event is appended to a
//! plain-text manifest at the root of the destination directory.
//!
//! The manifest is intentionally simple and dependency-free: one line per
//! event, with enough context (archive position, both byte spellings and the
//! validation verdict) for a reviewer to reconstruct what happened without
//! access to the original archive.

use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::path::PathConflict;

/// File name of the security manifest, relative to the extraction root.
///
/// The leading `.` keeps it out of normal directory listings while still
/// leaving it inside the extraction root where a reviewer expects to find it.
pub(crate) const SECURITY_RECORD: &str = ".tar-security-record";

/// A single audit event tied to a concrete archive entry.
pub(crate) struct SecurityEvent<'a> {
    /// Byte offset of the entry header within the archive, when known.
    pub header_pos: Option<u64>,
    /// The conflict that was validated (or rejected) for this entry.
    pub conflict: &'a PathConflict<'a>,
}

impl SecurityEvent<'_> {
    fn render(&self) -> String {
        let position = match self.header_pos {
            Some(pos) => pos.to_string(),
            None => "unknown".to_owned(),
        };
        format!(
            "header_offset={} {} accepted={}\n",
            position,
            self.conflict.describe(),
            // A benign truncation is the only override we accept.
            self.conflict.benign_truncation
        )
    }
}

/// Resolve the location of the security manifest under `dst`.
fn record_path(dst: &Path) -> PathBuf {
    dst.join(SECURITY_RECORD)
}

/// Open the manifest for appending without ever following a symlink.
///
/// The manifest lives inside a directory populated from an untrusted archive.
/// A malicious archive could first extract a symlink at the manifest path
/// pointing outside the extraction root; opening it normally would then write
/// the audit trail to an attacker-chosen location. `O_NOFOLLOW` (on Unix) and
/// an explicit pre-open symlink check elsewhere make the open fail instead of
/// following the link.
fn open_manifest(path: &Path) -> std::io::Result<std::fs::File> {
    // On every platform, refuse a symlink at the final path component before
    // opening. `Path::is_symlink` does not follow the link itself and is
    // available on the crate's MSRV (unlike the Windows `follow_links`
    // open option), so this is the portable baseline protection.
    if path.is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "refusing to write the security record through a symlink",
        ));
    }

    let mut options = OpenOptions::new();
    options.create(true).append(true);

    // On Unix additionally make the open itself reject a symlink atomically.
    // The explicit check above covers the other platforms; the small residual
    // TOCTOU window there matches this crate's documented threat model, which
    // excludes concurrent mutation of the destination tree.
    #[cfg(all(unix, not(target_arch = "wasm32")))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }

    options.open(path)
}

/// Append one validated PAX/USTAR name override to the extraction manifest.
///
/// Failures to write the record are surfaced to the caller: silently losing an
/// audit trail would defeat its purpose, and callers run during extraction
/// where an I/O error should already be fatal.
pub(crate) fn record_event(dst: &Path, event: &SecurityEvent<'_>) -> std::io::Result<()> {
    let path = record_path(dst);
    let preexisting_len = path.metadata().map(|m| m.len()).unwrap_or(0);
    let ends_with_newline = preexisting_len == 0 || file_ends_with_newline(&path)?;
    let mut file = open_manifest(&path)?;

    // An archive may legitimately contain a regular file with this same name.
    // Never overwrite it: if it already has content that does not end in a
    // newline, start our audit section on a fresh line so audit records stay
    // parseable and cannot be silently concatenated onto archive-controlled
    // bytes.
    if preexisting_len == 0 {
        writeln!(
            file,
            "# tar-rs extraction security record \
             (PAX/USTAR name overrides; one event per line)"
        )?;
    } else if !ends_with_newline {
        file.write_all(b"\n")?;
        writeln!(
            file,
            "# begin tar-rs security records (pre-existing file content above)"
        )?;
    }
    file.write_all(event.render().as_bytes())?;
    Ok(())
}

/// Check whether an appendable file currently ends in a newline byte.
fn file_ends_with_newline(path: &Path) -> std::io::Result<bool> {
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(true);
    }
    let mut last = [0u8; 1];
    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(len - 1))?;
    file.read_exact(&mut last)?;
    Ok(last[0] == b'\n')
}
