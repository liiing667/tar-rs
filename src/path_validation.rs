//! Validation between the path spellings carried by different tar formats.
//!
//! A GNU `L` extension and a USTAR `prefix`/`name` pair are two independent
//! spellings of the same member name. Tar readers have historically preferred
//! the GNU spelling without checking that the USTAR fields describe the same
//! path. An archive can exploit that silence to make format-aware tools and
//! this crate's extractor disagree about the hierarchy containing an entry.
//!
//! This module performs the small, testable comparison used by the public path
//! accessors and extraction. Complete component sequences are preferred; a
//! short same-depth legacy name and a field-saturated mechanical truncation
//! are tolerated because real GNU archives use those fallbacks. A short USTAR
//! path that stops at a parent level is not mistaken for truncation and is
//! rejected as the intended hierarchy ambiguity.

use std::borrow::Cow;
use std::io;

use crate::other;

/// Owned details of a GNU-longname/USTAR-path interpretation conflict.
///
/// The bytes are owned so that error and audit-report lifetimes do not borrow
/// the entry that produced them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GnuUstarPathConflict {
    pub(crate) gnu_longname: Vec<u8>,
    pub(crate) ustar_path: Vec<u8>,
}

impl GnuUstarPathConflict {
    /// Build the fail-closed I/O error exposed through [`crate::Entry::path`].
    pub(crate) fn into_io_error(self) -> io::Error {
        other(&format!(
            "GNU longname/USTAR prefix-name format conflict: the two spellings \
             disagree about the entry path hierarchy; \
             refusing ambiguous format interpretations: gnu_longname={:?}, \
             ustar_path={:?}",
            String::from_utf8_lossy(&self.gnu_longname),
            String::from_utf8_lossy(&self.ustar_path),
        ))
    }
}

/// Return the GNU long-name payload without its NUL terminator.
///
/// GNU long names are NUL-terminated, but malformed archives can contain more
/// than one NUL. Tar strings end at the first NUL, so truncate there rather
/// than only removing a single trailing byte.
fn normalize_gnu_longname(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|byte| *byte == 0) {
        Some(pos) => &bytes[..pos],
        None => bytes,
    }
}

/// Return the non-empty `.`-free path components used for format comparison.
///
/// Only `/` is a hierarchy separator in tar byte strings. On Unix `\` is a
/// legal filename byte; Windows path conversion is handled later by
/// [`crate::header::bytes2path`].
fn path_components(bytes: &[u8]) -> Vec<&[u8]> {
    bytes
        .split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty() && *component != b".")
        .collect()
}

/// Compare two archive path spellings by their complete hierarchy.
///
/// Empty and `.` components are ignored because they do not change the member
/// identity. All other components, including `..`, are compared exactly.
fn equivalent_paths(gnu: &[u8], ustar: &[u8]) -> bool {
    path_components(gnu) == path_components(ustar)
}

/// Detect a GNU-longname/USTAR-path hierarchy conflict.
///
/// The old 100-byte `name` field is only a fallback for a GNU `L` record:
/// writers commonly truncate it or even leave a one-component placeholder such
/// as `file_a`. A same-depth placeholder is therefore tolerated. A saturated
/// 100-byte `name` field is also recognized as mechanical truncation when the
/// cut lands inside a component, where the following GNU byte is not `/`.
///
/// The USTAR `prefix` field receives stricter treatment: unless `name` is
/// field-saturated truncation, a populated prefix must form the exact same
/// component hierarchy as the GNU long name.
pub(crate) fn gnu_ustar_path_conflict<'a>(
    gnu_longname: Option<&'a [u8]>,
    ustar_path: Cow<'a, [u8]>,
    ustar_prefix_present: bool,
    ustar_name_field_saturated: bool,
) -> Option<GnuUstarPathConflict> {
    let gnu_longname = gnu_longname?;
    let gnu = normalize_gnu_longname(gnu_longname);
    if equivalent_paths(gnu, &ustar_path) {
        return None;
    }

    let same_hierarchy_depth = path_components(gnu).len() == path_components(&ustar_path).len();
    let mechanical_truncation = ustar_name_field_saturated
        && gnu.strip_prefix(&ustar_path[..]).map_or(false, |suffix| {
            // A cut immediately before `/` ended at a component boundary;
            // the USTAR spelling then identifies a parent level rather
            // than a truncated copy of the GNU name.
            !suffix.is_empty() && suffix[0] != b'/'
        });

    if mechanical_truncation {
        return None;
    }

    let legacy_one_component_placeholder =
        !ustar_prefix_present && path_components(&ustar_path).len() == 1;
    if legacy_one_component_placeholder && same_hierarchy_depth {
        // Without a USTAR prefix, the old name field is only a fallback for
        // GNU tar's authoritative `L` record. Short, same-level placeholder
        // names such as `file_a` occur in regression fixtures. A populated
        // USTAR prefix is stricter because it deliberately adds hierarchy.
        return None;
    }

    Some(GnuUstarPathConflict {
        gnu_longname: gnu.to_vec(),
        ustar_path: ustar_path.into_owned(),
    })
}
