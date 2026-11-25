use std::fs;

use tar::{Archive, Builder, EntryType, Header};
use tempfile::Builder as TempBuilder;

const RECORD_FILE: &str = ".tar-security-record";

/// Build a GNU `L` long-name record followed by a regular USTAR member whose
/// `prefix` and `name` fields can be controlled independently.
fn build_gnu_ustar_archive(gnu_path: &str, ustar_prefix: &[u8], ustar_name: &[u8]) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());

    let payload = format!("{gnu_path}\0");
    let mut long_name = Header::new_gnu();
    long_name.set_path("././@LongLink").unwrap();
    long_name.set_size(payload.len() as u64);
    long_name.set_entry_type(EntryType::GNULongName);
    long_name.set_cksum();
    builder.append(&long_name, payload.as_bytes()).unwrap();

    let mut member = Header::new_ustar();
    member.set_size(0);
    member.set_mode(0o644);
    member.set_entry_type(EntryType::Regular);
    {
        let ustar = member.as_ustar_mut().unwrap();
        assert!(ustar_prefix.len() <= ustar.prefix.len());
        assert!(ustar_name.len() <= ustar.name.len());
        ustar.prefix[..ustar_prefix.len()].copy_from_slice(ustar_prefix);
        ustar.name[..ustar_name.len()].copy_from_slice(ustar_name);
    }
    member.set_cksum();
    builder.append(&member, &[][..]).unwrap();

    builder.into_inner().unwrap()
}

#[test]
fn gnu_and_ustar_paths_at_different_levels_are_rejected_by_public_path() {
    let bytes =
        build_gnu_ustar_archive("gnu/deep/hierarchy/file.txt", b"ustar_shallow", b"file.txt");

    let mut archive = Archive::new(&bytes[..]);
    let entry = archive.entries().unwrap().next().unwrap().unwrap();
    let error = entry.path().unwrap_err().to_string();

    assert!(error.contains("GNU"), "missing GNU detail: {error}");
    assert!(error.contains("USTAR"), "missing USTAR detail: {error}");
    assert!(
        error.contains("conflict"),
        "missing conflict marker: {error}"
    );
    assert!(error.contains("gnu/deep/hierarchy/file.txt"));
    assert!(error.contains("ustar_shallow/file.txt"));
}

#[test]
fn conflicting_path_bytes_fail_closed_to_empty_identity() {
    let bytes = build_gnu_ustar_archive("gnu/file.txt", b"other", b"file.txt");

    let mut archive = Archive::new(&bytes[..]);
    let entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert_eq!(&*entry.path_bytes(), b"");
}

#[test]
fn gnu_and_ustar_conflict_is_recorded_before_unpack_fails() {
    let bytes = build_gnu_ustar_archive("gnu/deep/file.txt", b"different/level", b"file.txt");
    let dir = TempBuilder::new()
        .prefix("tar-gnu-ustar")
        .tempdir()
        .unwrap();

    let mut archive = Archive::new(&bytes[..]);
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert!(entry.unpack_in(dir.path()).is_err());

    // The failed transaction publishes neither interpretation.
    assert!(!dir.path().join("gnu/deep/file.txt").exists());
    assert!(!dir.path().join("different/level/file.txt").exists());

    let record_path = dir.path().join(RECORD_FILE);
    let record = fs::read_to_string(record_path).expect("security record must remain in root");
    assert!(record.contains("event=gnu_ustar_path_conflict"), "{record}");
    assert!(record.contains("decision=rejected"), "{record}");
    assert!(record.contains("gnu/deep/file.txt"), "{record}");
    assert!(record.contains("different/level/file.txt"), "{record}");
}

#[test]
fn archive_unpack_records_conflict_and_writes_no_member() {
    let bytes = build_gnu_ustar_archive("attack/path.txt", b"decoy", b"path.txt");
    let dir = TempBuilder::new()
        .prefix("tar-gnu-ustar")
        .tempdir()
        .unwrap();

    let mut archive = Archive::new(&bytes[..]);
    assert!(archive.unpack(dir.path()).is_err());
    assert!(!dir.path().join("attack/path.txt").exists());
    assert!(!dir.path().join("decoy/path.txt").exists());

    let record = fs::read_to_string(dir.path().join(RECORD_FILE)).unwrap();
    assert!(record.contains("event=gnu_ustar_path_conflict"));
    assert!(record.contains("decision=rejected"));
}

#[test]
fn matching_gnu_longname_and_ustar_prefix_name_remain_accepted() {
    let bytes = build_gnu_ustar_archive("same/deep/path/file.txt", b"same/deep/path", b"file.txt");

    let mut archive = Archive::new(&bytes[..]);
    let entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert_eq!(
        entry.path().unwrap().to_str().unwrap(),
        "same/deep/path/file.txt"
    );
    assert_eq!(&*entry.path_bytes(), b"same/deep/path/file.txt");
}

#[test]
fn legitimate_builder_gnu_long_path_is_preserved() {
    let long_path = format!("{}/deep-file.txt", "gnu-long-directory".repeat(12));
    assert!(long_path.len() > 100);

    let mut builder = Builder::new(Vec::new());
    let mut header = Header::new_gnu();
    header.set_size(5);
    header.set_mode(0o644);
    header.set_entry_type(EntryType::Regular);
    builder
        .append_data(&mut header, &long_path, &b"hello"[..])
        .unwrap();
    let bytes = builder.into_inner().unwrap();

    let dir = TempBuilder::new().prefix("tar-gnu-long").tempdir().unwrap();
    let mut archive = Archive::new(&bytes[..]);
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert_eq!(entry.path().unwrap().to_str().unwrap(), long_path);
    assert!(entry.unpack_in(dir.path()).unwrap());
    assert!(dir.path().join(&long_path).is_file());
    assert!(!dir.path().join(RECORD_FILE).exists());
}

#[test]
fn legitimate_ustar_prefix_is_preserved() {
    let long_path = format!("{}/prefix-file.txt", "u".repeat(150));
    assert!(long_path.len() > 100);

    let mut header = Header::new_ustar();
    header.set_path(&long_path).unwrap();
    assert_ne!(header.as_ustar().unwrap().prefix[0], 0);
    header.set_size(0);
    header.set_mode(0o644);
    header.set_entry_type(EntryType::Regular);
    header.set_cksum();

    let mut builder = Builder::new(Vec::new());
    builder.append(&header, &[][..]).unwrap();
    let bytes = builder.into_inner().unwrap();

    let dir = TempBuilder::new()
        .prefix("tar-ustar-prefix")
        .tempdir()
        .unwrap();
    let mut archive = Archive::new(&bytes[..]);
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert_eq!(entry.header().path().unwrap().to_str().unwrap(), long_path);
    assert_eq!(entry.path().unwrap().to_str().unwrap(), long_path);
    assert!(entry.unpack_in(dir.path()).unwrap());
    assert!(dir.path().join(&long_path).is_file());
}

#[test]
fn name_only_fallback_at_a_different_level_fails_closed() {
    let bytes = build_gnu_ustar_archive("deep/a/b/c/file.txt", b"", b"shallow/file.txt");

    let mut archive = Archive::new(&bytes[..]);
    let entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert!(entry.path().is_err());
}

#[test]
fn same_level_short_name_placeholder_remains_compatible_with_gnu_override() {
    // GNU `L` overrides the legacy name. Existing archives and parser
    // regression fixtures may use a short placeholder at the same depth.
    let bytes = build_gnu_ustar_archive("longname.txt", b"", b"file_a");

    let mut archive = Archive::new(&bytes[..]);
    let entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert_eq!(entry.path().unwrap().to_str().unwrap(), "longname.txt");
}

#[test]
fn saturated_truncated_ustar_name_is_recognized_as_benign_truncation() {
    let gnu_path = format!("{}/file.txt", "a".repeat(120));
    let truncated = gnu_path[..99].to_owned();
    let bytes = build_gnu_ustar_archive(&gnu_path, b"", truncated.as_bytes());

    let mut archive = Archive::new(&bytes[..]);
    let entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert_eq!(entry.path().unwrap().to_str().unwrap(), gnu_path);
}

#[test]
fn same_depth_multi_component_name_with_different_tree_is_rejected() {
    let bytes = build_gnu_ustar_archive("attack/a/file.txt", b"", b"decoy/a/file.txt");

    let mut archive = Archive::new(&bytes[..]);
    let entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert!(entry.path().is_err());
}

#[test]
fn saturated_name_ending_at_component_boundary_is_not_benign_truncation() {
    let directory = "a".repeat(99);
    let gnu_path = format!("{directory}/file.txt");
    let bytes = build_gnu_ustar_archive(&gnu_path, b"", directory.as_bytes());

    let mut archive = Archive::new(&bytes[..]);
    let entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert!(entry.path().is_err());
}

#[test]
fn conflict_error_is_recoverable_for_subsequent_iterator_members() {
    let mut bytes = build_gnu_ustar_archive("bad/deep/file.txt", b"decoy", b"file.txt");
    // Remove the two zero blocks written by `Builder::into_inner`.
    bytes.truncate(bytes.len() - 1024);

    let mut builder = Builder::new(bytes);
    let mut header = Header::new_ustar();
    header.set_path("recovered/ok.txt").unwrap();
    header.set_size(0);
    header.set_mode(0o644);
    header.set_entry_type(EntryType::Regular);
    header.set_cksum();
    builder.append(&header, &[][..]).unwrap();
    let bytes = builder.into_inner().unwrap();

    let mut archive = Archive::new(&bytes[..]);
    let mut entries = archive.entries().unwrap();

    let bad = entries.next().unwrap().unwrap();
    assert!(bad.path().is_err());
    drop(bad);

    let good = entries.next().unwrap().unwrap();
    assert_eq!(good.path().unwrap().to_str().unwrap(), "recovered/ok.txt");
}
