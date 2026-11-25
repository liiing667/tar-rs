//! Reviewable security records written into an extraction root.
//!
//! When two supported tar format interpretations disagree about an entry's
//! hierarchy, extraction fails before publishing the member. A one-line audit
//! record is appended to a stable dotfile in the destination root so that the
//! rejected transaction can be reconstructed and recovered after the fact.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::path_validation::GnuUstarPathConflict;

/// File name of the security manifest, relative to the extraction root.
pub(crate) const SECURITY_RECORD_FILE: &str = ".tar-security-record";

const RECORD_HEADER: &str = "# tar-rs extraction security record; one event per line\n";

/// A rejected GNU-longname/USTAR-path interpretation transaction.
pub(crate) struct PathConflictRecord<'a> {
    /// Byte offset of the member header following the extension records.
    pub(crate) header_offset: u64,
    /// The conflict details, including both raw format spellings.
    pub(crate) conflict: &'a GnuUstarPathConflict,
}

impl PathConflictRecord<'_> {
    fn render(&self) -> String {
        format!(
            "event=gnu_ustar_path_conflict \
             kind=\"GNU longname vs USTAR prefix/name\" \
             decision=rejected \
             transaction=recoverable_fail_closed_without_member_write \
             header_offset={} \
             gnu_longname={:?} \
             ustar_prefix_name={:?} \
             message=\"GNU longname and USTAR prefix/name point to different path hierarchies\"\n",
            self.header_offset,
            String::from_utf8_lossy(&self.conflict.gnu_longname),
            String::from_utf8_lossy(&self.conflict.ustar_path),
        )
    }
}

/// Resolve the audit record location below an extraction root.
pub(crate) fn record_path(root: &Path) -> PathBuf {
    root.join(SECURITY_RECORD_FILE)
}

/// Append a fail-closed path conflict event to the extraction-root manifest.
///
/// The record is written before the conflict error is returned. Audit-writing
/// failures are propagated because silently losing the reviewable record would
/// defeat the security transaction.
pub(crate) fn record_gnu_ustar_path_conflict(
    root: &Path,
    event: &PathConflictRecord<'_>,
) -> io::Result<()> {
    let root = if root.as_os_str().is_empty() {
        Path::new(".")
    } else {
        root
    };
    if !root.exists() {
        fs::create_dir_all(root)?;
    }

    let path = record_path(root);
    let mut options = OpenOptions::new();
    options.create(true).append(true);

    // Never let an archive-controlled or pre-existing symlink redirect the
    // audit record outside the extraction root.
    #[cfg(all(unix, not(target_arch = "wasm32")))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // `O_NONBLOCK` prevents an archive-created FIFO from blocking the
        // audit write; a non-regular file is rejected by the metadata check.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    let mut file = options.open(&path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "{} when opening extraction security record {}",
                err,
                path.display()
            ),
        )
    })?;

    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "extraction security record {} is not a regular file",
                path.display()
            ),
        ));
    }

    if file.metadata()?.len() == 0 {
        file.write_all(RECORD_HEADER.as_bytes())?;
    }
    file.write_all(event.render().as_bytes())?;
    file.flush()?;
    Ok(())
}
