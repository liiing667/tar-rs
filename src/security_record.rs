//! Reviewable extraction security records.
//!
//! Untrusted archives can try to make a hard link resolve to an inode that
//! was not created by the current extraction, even when the visible path name
//! is inside the destination root. The commit registry records object
//! identities that [`crate::Entry::unpack_in`] has just published. Hard-link
//! requests are accepted only when their resolved object identity is in that
//! registry.
//!
//! Every commit and hard-link verdict is also appended to a plain-text record
//! in the extraction root so that a reviewer can reconstruct the decision
//! later. The file is audit evidence only. Authorization uses the in-memory
//! registry because a pre-existing record in an untrusted extraction root could
//! otherwise be forged to claim an external inode as committed.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
#[cfg(not(unix))]
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

/// File name of the reviewable security record, relative to extraction root.
pub const SECURITY_RECORD_FILE_NAME: &str = ".tar-security-record";

/// Object identities published through secure extraction.
#[derive(Default)]
pub(crate) struct CommitRegistry {
    #[cfg(unix)]
    objects: Mutex<HashSet<(u64, u64)>>,
    #[cfg(not(unix))]
    paths: Mutex<HashSet<PathBuf>>,
}

impl CommitRegistry {
    pub(crate) fn new_shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record the identity of a regular file successfully committed by
    /// `unpack_in`.
    #[cfg(unix)]
    pub(crate) fn mark_committed_file(&self, metadata: &fs::Metadata) {
        let id = (metadata.dev(), metadata.ino());
        self.objects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id);
    }

    /// Return whether `metadata` identifies an already committed object.
    #[cfg(unix)]
    pub(crate) fn contains_committed(&self, metadata: &fs::Metadata) -> bool {
        let id = (metadata.dev(), metadata.ino());
        self.objects
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&id)
    }

    /// Return whether an object identity was committed by this archive handle.
    #[cfg(unix)]
    pub(crate) fn is_committed(&self, metadata: &fs::Metadata) -> bool {
        self.contains_committed(metadata)
    }

    /// Record a committed path on platforms without stable Unix object IDs.
    #[cfg(not(unix))]
    pub(crate) fn mark_committed_path(&self, path: &Path) {
        let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        self.paths
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(path);
    }

    /// Return whether a canonical target path was committed.
    #[cfg(not(unix))]
    pub(crate) fn contains_committed_path(&self, path: &Path) -> bool {
        self.paths
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(path)
    }

    /// Path-based fallback used on non-Unix platforms.
    #[cfg(not(unix))]
    pub(crate) fn is_committed(&self, canonical_target: &Path) -> bool {
        self.contains_committed_path(canonical_target)
    }
}

/// Open the audit record without following a symlink at its final component.
fn open_record(root: &Path) -> io::Result<fs::File> {
    let path = root.join(SECURITY_RECORD_FILE_NAME);
    let mut options = OpenOptions::new();
    options.create(true).append(true);

    // The audit trail must never be redirected through a pre-planted symlink.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }

    let file = options.open(&path)?;
    let metadata = file.metadata()?;

    // A regular audit record created by tar-rs has one link. A pre-planted
    // hard link to another file would otherwise make appends modify that
    // external inode. Symlinks are rejected by `O_NOFOLLOW` above.
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "security record has multiple hard links",
        ));
    }

    let mut file = file;
    if metadata.len() == 0 {
        file.write_all(b"# tar-rs extraction security record version=1\n")?;
    }
    Ok(file)
}

fn append(root: &Path, event: &str) -> io::Result<()> {
    let mut file = open_record(root)?;
    file.write_all(event.as_bytes())?;
    if !event.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    Ok(())
}

/// Filesystem identity fields used by reviewers to correlate paths and inodes.
fn identity_fields(metadata: Option<&fs::Metadata>) -> String {
    match metadata {
        Some(_md) => {
            #[cfg(unix)]
            {
                format!(" dev={} ino={} nlink={}", _md.dev(), _md.ino(), _md.nlink())
            }
            #[cfg(not(unix))]
            {
                let _ = _md;
                String::new()
            }
        }
        None => String::from(" identity=unavailable"),
    }
}

/// Machine-readable object identity placed before archive-controlled fields.
fn object_field(metadata: Option<&fs::Metadata>) -> String {
    match metadata {
        Some(_md) => {
            #[cfg(unix)]
            {
                format!("object=unix:{}:{}", _md.dev(), _md.ino())
            }
            #[cfg(not(unix))]
            {
                String::from(" object=path")
            }
        }
        None => String::from(" object=unavailable"),
    }
}

/// Record a successfully committed archive member.
pub(crate) fn record_commit(
    root: &Path,
    header_offset: u64,
    entry: &Path,
    destination: &Path,
    kind: &str,
    metadata: Option<&fs::Metadata>,
) -> io::Result<()> {
    append(
        root,
        &format!(
            "event=committed kind={} {} header_offset={} entry={:?} path={:?}{}",
            kind,
            object_field(metadata),
            header_offset,
            entry,
            destination,
            identity_fields(metadata),
        ),
    )
}

/// Details for a hard-link authorization decision.
pub(crate) struct HardlinkAudit<'a> {
    pub header_offset: u64,
    pub entry: &'a Path,
    pub link_name: &'a Path,
    pub requested_target: &'a Path,
    pub canonical_target: Option<&'a Path>,
    pub destination: &'a Path,
    pub metadata: Option<&'a fs::Metadata>,
}

/// Record whether a hard link was accepted or denied.
pub(crate) fn record_hardlink_verdict(
    root: &Path,
    audit: &HardlinkAudit<'_>,
    accepted: bool,
    reason: Option<&str>,
) -> io::Result<()> {
    let (event, verdict, decision) = if accepted {
        ("hardlink_accepted", "accepted", "allow")
    } else {
        ("hardlink_denied", "rejected", "deny")
    };
    let reason = reason.unwrap_or("none");
    let canonical_target = audit
        .canonical_target
        .map(|p| format!("{:?}", p))
        .unwrap_or_else(|| "unavailable".to_owned());

    append(
        root,
        &format!(
            "event={} verdict={} decision={} reason={} header_offset={} entry={:?} link_name={:?} \
             requested_target={:?} canonical_target={} destination={:?}{}",
            event,
            verdict,
            decision,
            reason,
            audit.header_offset,
            audit.entry,
            audit.link_name,
            audit.requested_target,
            canonical_target,
            audit.destination,
            identity_fields(audit.metadata),
        ),
    )
}
