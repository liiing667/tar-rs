//! A library for reading and writing TAR archives
//!
//! This library provides utilities necessary to manage [TAR archives][1]
//! abstracted over a reader or writer. Great strides are taken to ensure that
//! an archive is never required to be fully resident in memory, and all objects
//! provide largely a streaming interface to read bytes from.
//!
//! [1]: https://en.wikipedia.org/wiki/Tar_%28computing%29
//!
//! # Security
//!
//! When unpacking archives ([`Archive::unpack`], [`Entry::unpack_in`]), a
//! best-effort is made to prevent writing files outside the destination
//! directory: paths containing `..` are rejected, and symlink targets within
//! the archive are validated before use.
//!
//! ### Single, validated name interpretation
//!
//! An entry may carry its name in more than one place: the USTAR header
//! fields, a GNU long-name record, or a PAX `path`/`linkpath` extension. The
//! public [`Entry::path`]/[`Entry::link_name`] accessors and the extraction
//! code resolve these through one shared routine, so a validator inspecting an
//! entry and the code writing it to disk always observe the same path. When a
//! PAX name differs from the USTAR header name, the only accepted discrepancy
//! is the standard long-name case where the 100-byte USTAR name field is
//! completely filled with a truncated prefix of the longer PAX name. A short
//! header name that merely happens to be a prefix, and any other disagreement,
//! is rejected with an error rather than resolved in favor of one spelling.
//!
//! Every accepted PAX/USTAR name override is appended to a plain-text
//! security manifest named `.tar-security-record` at the root of the
//! extraction destination. Each line records the entry's header offset, both
//! byte spellings and whether the override was an accepted truncation,
//! providing a reviewable audit trail inside the extracted tree. The manifest
//! is opened without following symlinks, so an archive that plants a symlink at
//! that path cannot redirect the audit trail outside the destination.
//!
//! **Concurrent mutation of the destination tree is outside the threat model.**
//! If another process modifies the destination (for example, by atomically
//! swapping a symlink) while extraction is in progress, this crate may follow
//! a path outside the intended destination. Preventing such TOCTOU races
//! requires OS primitives (e.g. `openat`/`O_PATH` used throughout) that this
//! crate does not use. When extracting untrusted archives in an environment
//! where the destination may be concurrently modified, use the [`cap-std`]
//! crate and/or OS-level sandboxing.
//!
//! [`cap-std`]: https://docs.rs/cap-std/

// More docs about the detailed tar format can also be found here:
// https://man.freebsd.org/cgi/man.cgi?query=tar&sektion=5&manpath=FreeBSD+8-current

// NB: some of the coding patterns and idioms here may seem a little strange.
//     This is currently attempting to expose a super generic interface while
//     also not forcing clients to codegen the entire crate each time they use
//     it. To that end lots of work is done to ensure that concrete
//     implementations are all found in this crate and the generic functions are
//     all just super thin wrappers (e.g. easy to codegen).

#![doc(html_root_url = "https://docs.rs/tar/0.4")]
#![deny(missing_docs)]
#![cfg_attr(test, deny(warnings))]

use std::io::{Error, ErrorKind};

pub use crate::archive::{Archive, Entries};
pub use crate::builder::{Builder, EntryWriter};
pub use crate::entry::{Entry, Unpacked};
pub use crate::entry_type::EntryType;
pub use crate::header::GnuExtSparseHeader;
#[cfg(all(any(unix, windows), not(target_arch = "wasm32")))]
pub use crate::header::DETERMINISTIC_TIMESTAMP;
pub use crate::header::{GnuHeader, GnuSparseHeader, Header, HeaderMode, OldHeader, UstarHeader};
pub use crate::pax::{PaxExtension, PaxExtensions};

mod archive;
mod builder;
mod entry;
mod entry_type;
mod error;
mod header;
mod path;
mod pax;
mod security_log;

fn other(msg: &str) -> Error {
    Error::new(ErrorKind::Other, msg)
}
