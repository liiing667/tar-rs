use std::fs;
use std::io::Cursor;

use tar::{Archive, Builder, EntryType, Header};
use tempfile::Builder as TempBuilder;

fn archive_file(name: &str, body: &[u8]) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Regular);
    header.set_path(name).unwrap();
    header.set_size(body.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    builder
        .append_data(&mut header, name, Cursor::new(body))
        .unwrap();
    builder.finish().unwrap();
    builder.into_inner().unwrap()
}

fn security_record(root: &std::path::Path) -> String {
    let path = root.join(".tar-rs-security.json");
    fs::read_to_string(path).expect("extraction should leave a security record")
}

fn assert_no_temporary_records(root: &std::path::Path) {
    for entry in fs::read_dir(root).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(
            !name.contains(".tmp-"),
            "temporary generation file was published: {name}"
        );
    }
}

#[test]
fn interrupted_generation_keeps_previous_complete_tree_and_records_reopen() {
    let temp = TempBuilder::new()
        .prefix("tar-generation")
        .tempdir()
        .unwrap();
    let root = temp.path();
    fs::write(root.join("payload"), b"old-generation").unwrap();

    let mut truncated = archive_file("payload", b"new-generation");
    truncated.truncate(truncated.len().saturating_sub(1800));

    // This is the consumer pattern used by reopen/read paths: iteration errors
    // and per-entry admission errors are not allowed to panic the consumer.
    let mut archive = Archive::new(Cursor::new(truncated));
    if let Ok(entries) = archive.entries() {
        for entry in entries.flatten() {
            let mut entry = entry;
            let _ = entry.unpack_in(root);
        }
    }

    let payload = fs::read(root.join("payload")).unwrap();
    assert!(
        payload == b"old-generation" || payload == b"new-generation",
        "a mixed file generation was published"
    );
    assert_eq!(payload, b"old-generation");

    let record = security_record(root);
    assert!(record.contains("generation"));
    assert!(record.contains("reopened"));
    assert!(record.contains("\"reopened\": true"));
    assert!(record.contains("rejected"));
    assert_no_temporary_records(root);

    // A complete new generation can legally replace the retained old one.
    let complete = archive_file("payload", b"new-generation");
    Archive::new(Cursor::new(complete)).unpack(root).unwrap();
    assert_eq!(fs::read(root.join("payload")).unwrap(), b"new-generation");
    assert_no_temporary_records(root);
}

#[test]
fn clean_empty_root_gets_committed_record_and_remains_repeatable() {
    let temp = TempBuilder::new()
        .prefix("tar-empty-generation")
        .tempdir()
        .unwrap();
    let root = temp.path().join("root");
    fs::create_dir_all(&root).unwrap();

    let archive = archive_file("payload", b"complete");
    Archive::new(Cursor::new(archive.clone()))
        .unpack(&root)
        .unwrap();
    assert_eq!(fs::read(root.join("payload")).unwrap(), b"complete");
    let record = security_record(&root);
    assert!(record.contains("\"decision\": \"committed\""));
    assert!(record.contains("\"reopened\": false"));
    assert_no_temporary_records(&root);

    Archive::new(Cursor::new(archive)).unpack(&root).unwrap();
    assert_eq!(fs::read(root.join("payload")).unwrap(), b"complete");
    let record = security_record(&root);
    assert!(record.contains("\"reopened\": true"));
    assert_no_temporary_records(&root);
}

#[test]
fn truncated_candidate_direct_unpack_does_not_publish_empty_file() {
    let temp = TempBuilder::new()
        .prefix("tar-direct-generation")
        .tempdir()
        .unwrap();
    let destination = temp.path().join("direct-payload");

    let mut truncated = archive_file("payload", b"new-generation");
    truncated.truncate(truncated.len().saturating_sub(1800));

    let mut archive = Archive::new(Cursor::new(truncated));
    let entry = archive.entries().unwrap().next().unwrap().unwrap();
    let mut entry = entry;
    assert!(entry.unpack(&destination).is_err());
    assert!(
        !destination.exists(),
        "direct unpack published a partial generation artifact"
    );
}

#[test]
fn truncated_unpack_in_creates_root_only_for_evidence_when_absent() {
    let temp = TempBuilder::new()
        .prefix("tar-missing-root-generation")
        .tempdir()
        .unwrap();
    let root = temp.path().join("extraction-root");

    let mut truncated = archive_file("payload", b"new-generation");
    truncated.truncate(truncated.len().saturating_sub(1800));

    let mut archive = Archive::new(Cursor::new(truncated));
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert!(entry.unpack_in(&root).is_err());
    assert!(root.join(".tar-rs-security.json").is_file());
    assert!(!root.join("payload").exists());
}
