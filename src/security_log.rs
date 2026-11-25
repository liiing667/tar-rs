//! Append-only, reviewable records for security-sensitive extraction actions.
//!
//! The record is deliberately plain text and lives inside the extraction root so
//! that an auditor can correlate an extracted path with the archive position and
//! the filesystem identity that actually received metadata. Writes are
//! best-effort append operations; callers retain the original extraction error
//! if an audit write fails after another operation has already failed.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Primary audit record name at the root of an extraction.
pub(crate) const SECURITY_RECORD_FILE: &str = ".tar-security-record";

/// One metadata application or rejection event.
pub(crate) struct SecurityRecord<'a> {
    /// Header/start position in the input archive.
    pub header_pos: u64,
    /// Archive member name, rendered lossily for audit output.
    pub entry: &'a str,
    /// Destination path relative to or inside the extraction root.
    pub destination: &'a Path,
    /// `dev:inode` identity of the committed object, when available.
    pub identity: Option<String>,
    /// Metadata fields that were successfully committed or requested.
    pub metadata: String,
    /// `committed` or a short rejection reason.
    pub verdict: &'a str,
}

fn open_record(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);

    // The record name is reserved by tar-rs. Never follow an archive-planted
    // symlink at that location out of the extraction root.
    #[cfg(unix)]
    {
        options.mode(0o644);
    }
    #[cfg(all(unix, not(target_arch = "wasm32")))]
    {
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }

    match options.open(path) {
        Ok(file) if is_safe_record_identity(&file) => Ok(file),
        Ok(file) => {
            drop(file);
            replace_record(path)
        }
        Err(err) if path.symlink_metadata().is_ok() => replace_record(path).map_err(|_| err),
        Err(err) => Err(err),
    }
}

fn is_safe_record_identity(file: &File) -> bool {
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !metadata.file_type().is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // A link count above one means the audit path may share an inode with
        // another name, potentially outside the extraction root. Replace it
        // with a fresh, non-hard-linked audit file.
        metadata.nlink() == 1
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn replace_record(path: &Path) -> std::io::Result<File> {
    // Remove only this directory entry. For a symlink or hard link this does
    // not remove or modify the linked object's data.
    let _ = std::fs::remove_file(path);

    let mut options = OpenOptions::new();
    options.create_new(true).append(true);
    #[cfg(unix)]
    {
        options.mode(0o644);
    }
    #[cfg(all(unix, not(target_arch = "wasm32")))]
    {
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path)
}

fn render(event: &SecurityRecord<'_>) -> String {
    let destination = event.destination.display().to_string();
    let identity = event.identity.as_deref().unwrap_or("unavailable");
    format!(
        "header_offset={} entry={:?} destination={:?} identity={} metadata={} verdict={}\n",
        event.header_pos, event.entry, destination, identity, event.metadata, event.verdict
    )
}

/// Append one event to the extraction-root security record.
pub(crate) fn append(root: &Path, event: &SecurityRecord<'_>) -> std::io::Result<()> {
    let line = render(event);
    let path = root.join(SECURITY_RECORD_FILE);
    let mut file = open_record(&path)?;
    if file.metadata()?.len() == 0 {
        file.write_all(b"# tar-rs extraction security record; one key=value event per line\n")?;
    }
    file.write_all(line.as_bytes())?;
    file.flush()?;
    Ok(())
}

/// Record a session-level notice that is not associated with one member.
pub(crate) fn record_notice(root: &Path, verdict: &str) -> std::io::Result<()> {
    append(
        root,
        &SecurityRecord {
            header_pos: 0,
            entry: "<archive>",
            destination: root,
            identity: None,
            metadata: "session".to_owned(),
            verdict,
        },
    )
}
