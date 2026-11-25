//! Centralized interpretation of the on-disk name of an entry.
//!
//! A single tar entry can carry up to three different spellings of its name
//! (or link name):
//!
//! 1. the name stored in the classic/USTAR header fields,
//! 2. a GNU long-name (`L`/`K`) extension record,
//! 3. a PAX `path`/`linkpath` extension record.
//!
//! Historically the public [`crate::Entry`] accessors and the extraction code
//! each picked one of these spellings independently. A malicious archive could
//! therefore make a *validator* (which inspects the public path) and a
//! *consumer* (which writes to disk during extraction) disagree about which
//! file an entry refers to. Everything in this module goes through a single
//! [`interpret_name`] entry point so that both call sites share exactly one
//! interpretation, and any disagreement that cannot be explained by a
//! legitimate long name is rejected instead of being silently resolved.

use std::borrow::Cow;
use std::io;

use crate::other;
use crate::pax::PaxExtensions;

/// Capacity of the classic/USTAR fixed-size name and link-name fields.
///
/// Both the `name` and `linkname` fields are 100 bytes across the old, USTAR
/// and GNU header layouts. A conforming writer that needs an extension record
/// for an over-long name fills this field completely with the first bytes of
/// the full name.
const FIXED_NAME_FIELD_LEN: usize = 100;

/// Identifies which tar field a name interpretation applies to.
///
/// The two cases use distinct PAX keywords and are validated independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NameKind {
    /// The entry's own path name (PAX keyword `path`).
    Path,
    /// The target of a hard link or symbolic link (PAX keyword `linkpath`).
    Link,
}

impl NameKind {
    fn pax_keyword(self) -> &'static [u8] {
        match self {
            NameKind::Path => b"path",
            NameKind::Link => b"linkpath",
        }
    }

    fn label(self) -> &'static str {
        match self {
            NameKind::Path => "path",
            NameKind::Link => "link name",
        }
    }
}

/// The outcome of interpreting the name(s) attached to an entry.
///
/// `bytes` is the single, authoritative byte spelling that every caller must
/// use. `record` is set whenever a PAX extension overrode the USTAR header, so
/// that the override can be audited during extraction.
pub(crate) struct InterpretedName<'a> {
    pub bytes: Cow<'a, [u8]>,
    pub record: Option<PathConflict<'a>>,
}

/// A reviewable description of a PAX name overriding the USTAR header name.
#[derive(Clone, Debug)]
pub(crate) struct PathConflict<'a> {
    pub kind: NameKind,
    pub header_name: Cow<'a, [u8]>,
    pub extended_name: Cow<'a, [u8]>,
    /// Whether the USTAR name is merely a truncated prefix of the long name.
    pub benign_truncation: bool,
}

impl PathConflict<'_> {
    /// Renders the conflict as a single human-auditable line.
    ///
    /// The raw (lossy) byte spellings are kept so that a reviewer can see
    /// exactly what the archive claimed rather than a sanitized rendering.
    pub fn describe(&self) -> String {
        format!(
            "{} conflict: ustar_header={:?} pax_extension={:?} benign_truncation={}",
            self.kind.label(),
            String::from_utf8_lossy(&self.header_name),
            String::from_utf8_lossy(&self.extended_name),
            self.benign_truncation,
        )
    }
}

/// Strip the trailing NUL that GNU long-name records use as a terminator.
fn strip_terminator(bytes: &[u8]) -> &[u8] {
    match bytes.last() {
        Some(0) => &bytes[..bytes.len() - 1],
        _ => bytes,
    }
}

/// Whether a raw, NUL-padded fixed-size header field was completely filled.
///
/// A conforming writer stores a name shorter than the field as the bytes
/// followed by a NUL (or leaves the rest zero-filled). When the name is exactly
/// as long as the field, there is no room for a terminator and every byte is a
/// non-NUL name byte. Detecting that full saturation is what distinguishes a
/// genuine truncation from a short, independently chosen name.
fn field_is_saturated(raw_field: &[u8]) -> bool {
    raw_field.len() == FIXED_NAME_FIELD_LEN && !raw_field.contains(&0)
}

/// Whether the entry's fixed-size header name field was completely filled.
///
/// USTAR archives may also split a long name across a `prefix` and `name`
/// field; that combination reconstructs the full name losslessly, so it is
/// handled by the equality branch rather than the truncation branch. Here we
/// only consider the plain `name` field, which is the field that gets truncated
/// when an extension record is used.
pub(crate) fn header_name_field_saturated(header: &crate::Header) -> bool {
    field_is_saturated(&header.as_old().name)
}

/// Whether the entry's fixed-size header link-name field was completely filled.
pub(crate) fn header_linkname_field_saturated(header: &crate::Header) -> bool {
    field_is_saturated(&header.as_old().linkname)
}

/// Look up a PAX name keyword (`path` or `linkpath`) in raw extension bytes.
///
/// Malformed extension records are ignored here, matching the long-standing
/// behavior of the public accessors; a malformed record therefore cannot
/// introduce a name that disagrees with the USTAR header.
fn pax_name(pax_extensions: &[u8], kind: NameKind) -> Option<&[u8]> {
    PaxExtensions::new(pax_extensions)
        .filter_map(|record| record.ok())
        .find(|record| record.key_bytes() == kind.pax_keyword())
        .map(|record| record.value_bytes())
}

/// Determine whether a USTAR header name is consistent with a longer
/// extension-provided name.
///
/// When a path does not fit in the fixed-size USTAR name field, conforming
/// writers (GNU tar, BSD tar, ...) fill the 100-byte field completely with the
/// first bytes of the full name and place the full name in the extension
/// record. We therefore accept a discrepancy only when *all* of the following
/// hold:
///
/// * the fixed-size field was completely filled (`header_field_saturated`),
///   which proves the header genuinely could not hold the whole name — this
///   rejects short, attacker-chosen names that merely happen to be a prefix;
/// * the header name is strictly shorter than the extension name; and
/// * the header name is a byte-for-byte prefix of the extension name.
///
/// A name that fits without filling the field is represented losslessly (and
/// handled by the equality branch), so a partial prefix there is rejected.
fn is_benign_truncation(
    header_name: &[u8],
    extended_name: &[u8],
    header_field_saturated: bool,
) -> bool {
    if !header_field_saturated || header_name.is_empty() {
        return false;
    }
    // The header field cannot hold more than the long name it is derived from.
    if header_name.len() >= extended_name.len() {
        return false;
    }
    extended_name.starts_with(header_name)
}

/// Interpret one name field of an entry.
///
/// `gnu_longname` is the payload of a GNU `L`/`K` record, `pax_extensions`
/// the raw PAX extension bytes (if any) and `header_name` the name carried in
/// the USTAR/classic header itself.
///
/// GNU long names always win and are produced by this crate's own writer, so
/// they are trusted as before. A PAX name wins over the USTAR header, but the
/// pair is validated to ensure the USTAR header is only a truncated form of
/// the same long name.
///
/// `header_field_saturated` reports whether the fixed-size (100-byte) header
/// name/link-name field that produced `header_name` was completely filled.
pub(crate) fn interpret_name<'a>(
    gnu_longname: Option<&'a [u8]>,
    pax_extensions: Option<&'a [u8]>,
    header_name: Cow<'a, [u8]>,
    header_field_saturated: bool,
    kind: NameKind,
) -> io::Result<InterpretedName<'a>> {
    // GNU long-name extension: highest precedence, unchanged behavior.
    if let Some(bytes) = gnu_longname {
        return Ok(InterpretedName {
            bytes: Cow::Borrowed(strip_terminator(bytes)),
            record: None,
        });
    }

    // PAX extension name: validate its relationship with the USTAR header.
    if let Some(pax) = pax_extensions {
        if let Some(extended) = pax_name(pax, kind) {
            let extended = Cow::<'a, [u8]>::Borrowed(extended);
            let benign = is_benign_truncation(&header_name, &extended, header_field_saturated);
            let equal = *header_name == *extended;
            if !equal && !benign {
                return Err(other(&format!(
                    "refusing entry with {} names that disagree: \
                     ustar header {:?} is neither equal to nor a truncated \
                     prefix of the pax {:?}",
                    kind.label(),
                    String::from_utf8_lossy(&header_name),
                    String::from_utf8_lossy(&extended),
                )));
            }
            // Identical spellings are not an override and have nothing to
            // audit, so only a genuine (validated) long-name override is
            // recorded.
            if equal {
                return Ok(InterpretedName {
                    bytes: extended,
                    record: None,
                });
            }
            let record = PathConflict {
                kind,
                header_name,
                extended_name: extended.clone(),
                benign_truncation: benign,
            };
            return Ok(InterpretedName {
                bytes: extended,
                record: Some(record),
            });
        }
    }

    // No overriding extension: the USTAR header is authoritative.
    Ok(InterpretedName {
        bytes: header_name,
        record: None,
    })
}
