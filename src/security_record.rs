//! Durable, non-content security records left in extraction roots.

use std::fs::{self, OpenOptions};
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// File name checked by extraction consumers and contract probes.
pub(crate) const RECORD_FILE_NAME: &str = ".tar-rs-security.json";

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Identity and admission state for one public `unpack_in` call.
pub(crate) struct UnpackEvidence<'a> {
    pub entry_path: &'a str,
    pub header_pos: u64,
    pub declared_size: u64,
    pub candidate_incomplete: bool,
}

/// Record the outcome of one [`crate::Entry::unpack_in`] call.
///
/// Writing the evidence is best-effort: auditing must not replace or mask the
/// original extraction result. In ordinary writable extraction roots the
/// atomic write below makes the record durable before control returns.
pub(crate) fn record_unpack_outcome(
    root: &Path,
    evidence: UnpackEvidence<'_>,
    reopened: bool,
    outcome: &io::Result<bool>,
) {
    if write_record(root, &evidence, reopened, outcome).is_err() && evidence.candidate_incomplete {
        // A fail-closed truncated candidate can be rejected before normal
        // admission creates the destination root. The extraction-root contract
        // still calls for evidence, so create only the root and retry once.
        let _ = fs::create_dir_all(root);
        let _ = write_record(root, &evidence, reopened, outcome);
    }
}

/// Check whether `root` already contains a committed generation or record.
///
/// Call this before admission performs writes; checking after a successful
/// extraction would classify the newly published generation as "reopened".
pub(crate) fn root_contains_prior_generation(root: &Path) -> bool {
    root_contains_prior_generation_inner(root)
}

fn write_record(
    root: &Path,
    evidence: &UnpackEvidence<'_>,
    reopened: bool,
    outcome: &io::Result<bool>,
) -> io::Result<()> {
    let (decision, category, generation, detail) = match outcome {
        Ok(true) => (
            "committed",
            "entry-published",
            "new",
            "entry was published in the current generation".to_string(),
        ),
        Ok(false) => (
            "not-committed",
            "entry-skipped",
            "unchanged",
            "entry was skipped by path admission".to_string(),
        ),
        Err(err) => {
            let category = if evidence.candidate_incomplete {
                "truncated-header-generation"
            } else {
                "unpack-error"
            };
            let generation = if evidence.candidate_incomplete {
                "old-retained"
            } else {
                "failed-candidate"
            };
            (
                "rejected",
                category,
                generation,
                format!("candidate generation was not committed: {err}"),
            )
        }
    };

    let json = format!(
        concat!(
            "{{\n",
            "  \"schema\": \"tar-rs.security-record/v1\",\n",
            "  \"record\": \"{record_file}\",\n",
            "  \"generation\": \"{generation}\",\n",
            "  \"reopened\": {reopened},\n",
            "  \"decision\": \"{decision}\",\n",
            "  \"category\": \"{category}\",\n",
            "  \"candidate_complete\": {complete},\n",
            "  \"entry\": {{\n",
            "    \"path\": \"{entry_path}\",\n",
            "    \"header_pos\": {header_pos},\n",
            "    \"declared_size\": {declared_size}\n",
            "  }},\n",
            "  \"recovery\": {{\n",
            "    \"public_root_contract\": \"complete-old-or-complete-new-generation\",\n",
            "    \"reopen_action\": \"read-the-last-committed-generation\",\n",
            "    \"partial_candidate_retained\": false\n",
            "  }},\n",
            "  \"detail\": \"{detail}\"\n",
            "}}\n"
        ),
        record_file = RECORD_FILE_NAME,
        generation = json_escape(generation),
        reopened = reopened,
        decision = decision,
        category = category,
        complete = !evidence.candidate_incomplete,
        entry_path = json_escape(evidence.entry_path),
        header_pos = evidence.header_pos,
        declared_size = evidence.declared_size,
        detail = json_escape(&detail),
    );

    atomic_write(root, RECORD_FILE_NAME, json.as_bytes())
}

fn root_contains_prior_generation_inner(root: &Path) -> bool {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return false,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        if name == RECORD_FILE_NAME {
            return true;
        }
        let name = name.to_string_lossy();
        let temporary_prefix = format!("{RECORD_FILE_NAME}.tmp-");
        if !name.starts_with(&temporary_prefix) {
            return true;
        }
    }
    false
}

fn atomic_write(root: &Path, file_name: &str, bytes: &[u8]) -> io::Result<()> {
    // `unpack_in` has already established the destination root for admitted
    // entries. Do not create it from auditing for skipped/rejected paths, as
    // that would observably change extraction behavior.
    let final_path: PathBuf = root.join(file_name);
    let pid = std::process::id();

    for _ in 0..16 {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary_name = format!("{file_name}.tmp-{pid}-{counter}");
        let temporary_path = root.join(temporary_name);

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o644);
        }

        let mut file = match options.open(&temporary_path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        };

        let write_result = file.write_all(bytes).and_then(|()| file.sync_all());
        drop(file);
        if let Err(err) = write_result {
            let _ = fs::remove_file(&temporary_path);
            return Err(err);
        }

        match fs::rename(&temporary_path, &final_path) {
            Ok(()) => return Ok(()),
            Err(err) => {
                let _ = fs::remove_file(&temporary_path);
                return Err(err);
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique security record temporary file",
    ))
}

fn json_escape(input: &str) -> String {
    let mut output = String::with_capacity(input.len() + 2);
    for ch in input.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            ch if (ch as u32) < 0x20 => {
                use std::fmt::Write;
                let _ = write!(output, "\\u{:04x}", ch as u32);
            }
            ch => output.push(ch),
        }
    }
    output
}
