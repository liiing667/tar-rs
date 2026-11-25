//! Reviewable records for security-sensitive extraction decisions.
//!
//! A malformed entry whose declared length does not match its streamed body
//! must never leave a partially written member at its final destination.
//! When [`Entry::unpack_in`](crate::Entry::unpack_in) rejects such an entry,
//! this module appends a machine- and human-readable event to a stable file in
//! the extraction root. The record gives reviewers the entry identity, header
//! offset, declared size and the error that prevented verification.
//!
//! The format is intentionally dependency-free line-oriented text so it can be
//! inspected with standard tools and does not require trusting a structured
//! parser during incident review.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

/// Stable audit filename at the root of an extraction destination.
pub(crate) const SECURITY_RECORD_FILE: &str = ".tar-security-record";

const RECORD_HEADER: &str = "# tar-rs extraction security record\n\
# one key=\"value\" event per line; decision=rejected events are not published\n";

/// Details of one rejected atomic publication.
pub(crate) struct RejectedPublication<'a> {
    /// Archive byte offset of the member header.
    pub header_offset: u64,
    /// Archive-provided member path, rendered lossily for the audit log.
    pub entry_path: &'a str,
    /// Size declared by the header/PAX extension.
    pub declared_size: u64,
    /// Number of bytes observed in the staging file before rollback, if known.
    pub staged_bytes: Option<u64>,
    /// The verification or publication error.
    pub error: &'a io::Error,
}

/// Append a rejection event to the security record in `root`.
///
/// Audit-writing errors are returned to the caller. The extraction boundary
/// treats them as secondary to the original verification failure, ensuring
/// that the original error kind remains observable.
pub(crate) fn record_rejected_publication(
    root: &Path,
    event: &RejectedPublication<'_>,
) -> io::Result<()> {
    let path = root.join(SECURITY_RECORD_FILE);
    let mut file = open_record(&path)?;
    if file.metadata()?.len() == 0 {
        file.write_all(RECORD_HEADER.as_bytes())?;
    }

    let error_chain = error_chain(event.error);
    let staged_bytes = match event.staged_bytes {
        Some(bytes) => bytes.to_string(),
        None => "unknown".to_owned(),
    };
    writeln!(
        file,
        "event=\"atomic_file_publication\" decision=\"rejected\" \
         header_offset={} declared_size={} staged_bytes={} \
        entry_path={:?} error_kind={:?} error={:?} error_chain={:?} \
         target_published=\"false\"",
        event.header_offset,
        event.declared_size,
        staged_bytes,
        event.entry_path,
        event.error.kind(),
        event.error.to_string(),
        error_chain,
    )?;
    file.flush()?;
    Ok(())
}

/// Open the audit record without writing through a symlink or shared inode.
fn open_record(path: &Path) -> io::Result<File> {
    // Portable first-line check. On Unix O_NOFOLLOW below closes the
    // concurrent-swap window; concurrent mutation is otherwise outside the
    // crate's documented threat model.
    if path.is_symlink() {
        return replace_record(path);
    }

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(all(unix, not(target_arch = "wasm32")))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK prevents an archive-planted FIFO from blocking audit
        // writes; the regular-file identity check rejects it afterwards.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }

    match options.open(path) {
        Ok(file) if has_safe_identity(&file) => Ok(file),
        Ok(file) => {
            drop(file);
            replace_record(path)
        }
        Err(err) if path.symlink_metadata().is_ok() => replace_record(path).map_err(|_| err),
        Err(err) => Err(err),
    }
}

/// Reject non-regular files and Unix hard links sharing another inode.
fn has_safe_identity(file: &File) -> bool {
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };
    if !metadata.file_type().is_file() {
        return false;
    }

    #[cfg(all(unix, not(target_arch = "wasm32")))]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink() == 1
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Fail closed if the link count is unavailable. A multi-linked record
        // may share an inode outside the extraction root.
        metadata.number_of_links().map_or(false, |links| links == 1)
    }
    #[cfg(not(any(all(unix, not(target_arch = "wasm32")), windows)))]
    {
        true
    }
}

/// Replace an unsafe record directory entry with a fresh regular audit file.
///
/// Removing a symlink or hard link removes only that directory entry; it does
/// not modify or delete the linked object outside the extraction root.
fn replace_record(path: &Path) -> io::Result<File> {
    let _ = std::fs::remove_file(path);

    let mut options = OpenOptions::new();
    options.create_new(true).append(true);
    #[cfg(all(unix, not(target_arch = "wasm32")))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

/// Render the complete [`std::error::Error::source`] chain for auditing.
fn error_chain(error: &io::Error) -> String {
    let mut chain = Vec::new();
    chain.push(error.to_string());
    let mut source = std::error::Error::source(error);
    while let Some(err) = source {
        chain.push(err.to_string());
        source = err.source();
    }
    chain.join(" <- ")
}
