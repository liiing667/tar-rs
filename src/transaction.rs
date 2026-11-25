//! Per-extraction tracking of the path identities committed by an
//! [`Archive::unpack`](crate::Archive::unpack) transaction.
//!
//! # Why this module exists
//!
//! The filesystem location produced by an entry is not determined by the
//! entry's raw path string. [`EntryFields::unpack_in`](crate::entry) collapses
//! every syntactic variant of a path onto the same destination:
//!
//! * leading `/` and drive prefixes are trimmed,
//! * `.` components are ignored,
//! * runs of `/` (or `\`, which the header parser converts to `/`) are merged,
//! * trailing slashes are irrelevant.
//!
//! As a result two entries with different raw path strings can target the
//! exact same file. When `overwrite` is enabled (the default) the second
//! entry silently replaces the first one, which lets a malicious archive
//! smuggle a second, untrusted copy of a file behind a benign first copy.
//!
//! [`ExtractionTransaction`] records the *normalized* path identity of every
//! entry committed during an extraction and rejects a later entry that maps
//! to an identity already claimed within the same transaction. The check is
//! deliberately based on normalized identity rather than the raw path string
//! so that dot/separator variants cannot bypass it.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Component, Path};

use crate::other;

/// File name, relative to the extraction root, under which the human
/// reviewable security record is written.
///
/// The name begins with `.` so that it does not clutter ordinary listings, and
/// the path is also reserved by the transaction itself: an archive entry that
/// targets this file is rejected as a conflict like any other duplicate.
pub const SECURITY_RECORD_NAME: &str = ".tar-extraction-security.log";

/// Sibling path used to stage the security record before it is renamed into
/// place. It must be reserved just like the record itself: otherwise an
/// archive entry (for example a symlink) planted at this path could redirect
/// the record write, potentially outside the extraction root.
const SECURITY_RECORD_TMP_NAME: &str = ".tar-extraction-security.log.tmp";

/// One rejected conflict, kept for the security record written into the
/// extraction root.
#[derive(Debug, Clone)]
pub struct Conflict {
    /// Raw path string of the entry that was rejected, as stored in the
    /// archive header (lossy representation, used only for reporting).
    pub raw_path: String,
    /// Raw path string of the entry that previously claimed the same
    /// normalized path identity (lossy representation).
    pub first_raw_path: String,
    /// Normalized path identity that both entries resolve to, using `/` as
    /// the separator regardless of platform.
    pub normalized_path: String,
}

/// Reason an entry claim was rejected, recorded for the security log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RejectKind {
    /// Another entry already claimed the same normalized path identity.
    Duplicate,
    /// The entry targeted the transaction's reserved security-record path.
    ReservedRecord,
}

/// State shared by every entry extracted within a single
/// [`Archive::unpack`](crate::Archive::unpack) call.
///
/// A transaction tracks the normalized path identities that have already been
/// claimed so that a later entry whose path is only different in spelling
/// (`.` components, duplicated separators, leading/trailing slashes, ...)
/// cannot overwrite an entry committed earlier in the same archive.
#[derive(Debug, Default)]
pub struct ExtractionTransaction {
    /// Normalized identities already committed, keyed by the sequence of
    /// normal path components.
    claimed: HashSet<Vec<OsString>>,
    /// Raw path spelling of the first entry for each claimed identity, used
    /// to produce an informative conflict error and security record.
    first_spelling: std::collections::HashMap<Vec<OsString>, String>,
    /// Claims rejected during the transaction, with the reason for rejection.
    conflicts: Vec<(RejectKind, Conflict)>,
}

impl ExtractionTransaction {
    /// Create a new, empty transaction.
    pub fn new() -> Self {
        Self::default()
    }

    /// Normalize an archive entry path into the identity used for conflict
    /// detection.
    ///
    /// This mirrors the path handling performed while unpacking: root/prefix
    /// and `.` components are dropped and `..` components cause the entry to be
    /// skipped by the unpacker, in which case `None` is returned here as well
    /// (such entries never commit anything to the destination).
    pub fn normalize(path: &Path) -> Option<Vec<OsString>> {
        let mut components = Vec::new();
        for part in path.components() {
            match part {
                Component::Prefix(..) | Component::RootDir | Component::CurDir => continue,
                Component::ParentDir => return None,
                Component::Normal(part) => components.push(part.to_os_string()),
            }
        }
        if components.is_empty() {
            return None;
        }
        Some(components)
    }

    /// Claim the normalized identity of an entry before it is unpacked.
    ///
    /// Returns `Ok(())` when the identity has not been claimed earlier in this
    /// transaction, recording both the identity and the raw spelling used by
    /// the entry. Returns an error (kind [`io::ErrorKind::Other`], matching the
    /// crate's other path-security checks) when another entry already claimed
    /// the same identity; the conflict is also appended to the transaction's
    /// conflict list for the security record.
    ///
    /// Entries whose path normalizes to nothing (only slashes/`.` parts, or
    /// paths containing `..` which the unpacker skips) are ignored: they do not
    /// commit a destination path and therefore cannot conflict.
    pub fn claim(&mut self, path: &Path, raw_path: &str) -> io::Result<()> {
        let identity = match Self::normalize(path) {
            Some(identity) => identity,
            None => return Ok(()),
        };

        // The security record (and its staging path) are owned by the
        // extraction transaction itself. An archive entry targeting either one
        // would otherwise be able to pre-create or overwrite the reviewable
        // record — a symlink at the staging path could even redirect the write
        // outside the extraction root — so both are treated as reserved
        // identities that no entry is allowed to claim.
        let reserved_record =
            Self::normalize(Path::new(SECURITY_RECORD_NAME)).expect("record name is non-empty");
        let reserved_tmp =
            Self::normalize(Path::new(SECURITY_RECORD_TMP_NAME)).expect("tmp name is non-empty");
        if identity == reserved_record || identity == reserved_tmp {
            let conflict = Conflict {
                raw_path: raw_path.to_owned(),
                first_raw_path: String::new(),
                normalized_path: display_identity(&identity),
            };
            let err = other(&format!(
                "entry `{}` targets the reserved extraction security record path `{}`",
                conflict.raw_path, conflict.normalized_path,
            ));
            self.conflicts.push((RejectKind::ReservedRecord, conflict));
            return Err(err);
        }

        if let Some(first_raw_path) = self.first_spelling.get(&identity) {
            let conflict = Conflict {
                raw_path: raw_path.to_owned(),
                first_raw_path: first_raw_path.clone(),
                normalized_path: display_identity(&identity),
            };
            let err = other(&format!(
                "duplicate entry in archive for path `{}`: entry `{}` was already \
                 committed by entry `{}` with the same normalized path identity; \
                 overwriting a previously extracted entry via a dot/separator path \
                 variant is not allowed within one extraction transaction",
                conflict.normalized_path, conflict.raw_path, conflict.first_raw_path,
            ));
            self.conflicts.push((RejectKind::Duplicate, conflict));
            return Err(err);
        }

        self.first_spelling
            .insert(identity.clone(), raw_path.to_owned());
        self.claimed.insert(identity);
        Ok(())
    }

    /// Write a human-readable security record into the extraction root.
    ///
    /// The record is written both on success and after a rejected conflict so
    /// that reviewers can always see which entries were committed and which
    /// attempts were blocked. Failures while writing the record never mask the
    /// outcome of the extraction itself: they are surfaced through the returned
    /// result only when writing is impossible, and callers choose how to
    /// combine them with the extraction result.
    pub fn write_security_record(&self, dst: &Path) -> io::Result<()> {
        let record_path = dst.join(SECURITY_RECORD_NAME);
        let mut contents = String::new();
        let _ = writeln!(contents, "# tar-rs extraction security record");
        let _ = writeln!(
            contents,
            "# This file is written by Archive::unpack and records path-identity"
        );
        let _ = writeln!(
            contents,
            "# conflicts rejected during the extraction transaction."
        );
        let _ = writeln!(contents, "#");
        let _ = writeln!(
            contents,
            "# Entries are identified by their normalized path: leading slashes,"
        );
        let _ = writeln!(
            contents,
            "# '.' components and repeated separators are collapsed, so two entries"
        );
        let _ = writeln!(
            contents,
            "# with different raw spellings of the same path cannot overwrite each other."
        );
        let duplicates = self
            .conflicts
            .iter()
            .filter(|(kind, _)| *kind == RejectKind::Duplicate)
            .count();
        let reserved = self
            .conflicts
            .iter()
            .filter(|(kind, _)| *kind == RejectKind::ReservedRecord)
            .count();
        let _ = writeln!(contents, "committed_entries={}", self.claimed.len());
        let _ = writeln!(contents, "rejected_conflicts={duplicates}");
        let _ = writeln!(contents, "rejected_reserved_record_entries={reserved}");
        for (kind, conflict) in &self.conflicts {
            let label = match kind {
                RejectKind::Duplicate => "CONFLICT",
                RejectKind::ReservedRecord => "RESERVED",
            };
            let _ = writeln!(
                contents,
                "{label} normalized_path={:?} rejected_entry={:?} first_entry={:?}",
                conflict.normalized_path, conflict.raw_path, conflict.first_raw_path,
            );
        }

        // Write through a temporary file in the same directory and rename into
        // place so that a concurrent reader never observes a partial record.
        let tmp_path = dst.join(SECURITY_RECORD_TMP_NAME);
        match fs::write(&tmp_path, contents).and_then(|()| fs::rename(&tmp_path, &record_path)) {
            Ok(()) => Ok(()),
            Err(err) => {
                // Best-effort cleanup so a failed write cannot leave a stale
                // temporary file behind in the extraction root.
                let _ = fs::remove_file(&tmp_path);
                Err(err)
            }
        }
    }
}

/// Render a normalized identity with `/` separators, for diagnostics only.
fn display_identity(identity: &[OsString]) -> String {
    identity
        .iter()
        .map(|part| part.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}
