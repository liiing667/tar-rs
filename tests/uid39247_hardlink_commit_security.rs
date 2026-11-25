use tempfile::Builder;

#[cfg(unix)]
#[test]
fn unpack_in_rejects_preexisting_hardlink_to_outside_and_records_verdict() {
    use std::os::unix::fs::MetadataExt;

    let td = Builder::new()
        .prefix("tar-hardlink-policy")
        .tempdir()
        .unwrap();
    let outside = td.path().join("outside-secret");
    std::fs::write(&outside, b"outside-readable-content").unwrap();

    let root = td.path().join("extract");
    std::fs::create_dir(&root).unwrap();
    let planted = root.join("planted");
    std::fs::hard_link(&outside, &planted).unwrap();
    let outside_ino = std::fs::metadata(&outside).unwrap().ino();
    assert_eq!(std::fs::metadata(&planted).unwrap().ino(), outside_ino);

    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Link);
    header.set_path("published").unwrap();
    header.set_link_name("planted").unwrap();
    header.set_cksum();
    builder.append(&header, &[][..]).unwrap();
    let bytes = builder.into_inner().unwrap();

    let mut archive = tar::Archive::new(&bytes[..]);
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    let result = entry.unpack_in(&root);
    assert!(
        result.is_err(),
        "uncommitted hardlink identity must be rejected"
    );

    assert!(!root.join("published").exists());
    assert_eq!(
        std::fs::read(&outside).unwrap(),
        b"outside-readable-content"
    );

    let record_path = root.join(".tar-security-record");
    let record = std::fs::read_to_string(&record_path).unwrap();
    assert!(record.contains("event=hardlink_denied"));
    assert!(record.contains("reason=target_not_committed"));
    assert!(record.contains("entry=\"published\""));
    assert!(record.contains("link_name=\"planted\""));
    assert!(record.contains(&format!("ino={outside_ino}")));
}

#[test]
fn unpack_in_accepts_committed_hardlink_and_records_commit() {
    let td = Builder::new().prefix("tar-hardlink-ok").tempdir().unwrap();
    let root = td.path().join("extract");
    std::fs::create_dir(&root).unwrap();

    let mut builder = tar::Builder::new(Vec::new());

    let mut regular = tar::Header::new_gnu();
    regular.set_size(5);
    regular.set_entry_type(tar::EntryType::Regular);
    regular.set_path("original").unwrap();
    regular.set_cksum();
    builder.append(&regular, &b"hello"[..]).unwrap();

    let mut hardlink = tar::Header::new_gnu();
    hardlink.set_size(0);
    hardlink.set_entry_type(tar::EntryType::Link);
    hardlink.set_path("alias").unwrap();
    hardlink.set_link_name("original").unwrap();
    hardlink.set_cksum();
    builder.append(&hardlink, &[][..]).unwrap();

    let bytes = builder.into_inner().unwrap();
    let mut archive = tar::Archive::new(&bytes[..]);
    for entry in archive.entries().unwrap() {
        entry.unwrap().unpack_in(&root).unwrap();
    }

    assert_eq!(std::fs::read(root.join("original")).unwrap(), b"hello");
    assert_eq!(std::fs::read(root.join("alias")).unwrap(), b"hello");

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            std::fs::metadata(root.join("original")).unwrap().ino(),
            std::fs::metadata(root.join("alias")).unwrap().ino(),
        );
    }

    let record = std::fs::read_to_string(root.join(".tar-security-record")).unwrap();
    assert!(record.contains("event=committed kind=file"));
    assert!(record.contains("event=hardlink_accepted"));
    assert!(record.contains("entry=\"alias\""));
    assert!(record.contains("link_name=\"original\""));
}

#[test]
fn unpack_in_records_regular_file_commit() {
    let td = Builder::new()
        .prefix("tar-regular-record")
        .tempdir()
        .unwrap();
    let root = td.path().join("extract");
    std::fs::create_dir(&root).unwrap();

    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(3);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("plain.txt").unwrap();
    header.set_cksum();
    builder.append(&header, &b"abc"[..]).unwrap();
    let bytes = builder.into_inner().unwrap();

    let mut archive = tar::Archive::new(&bytes[..]);
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert!(entry.unpack_in(&root).unwrap());
    assert_eq!(std::fs::read(root.join("plain.txt")).unwrap(), b"abc");

    let record = std::fs::read_to_string(root.join(".tar-security-record")).unwrap();
    assert!(record.contains("event=committed kind=file"));
    assert!(record.contains("entry=\"plain.txt\""));
}

#[test]
fn unpack_in_records_hardlink_escape_decision() {
    let td = Builder::new()
        .prefix("tar-hardlink-escape")
        .tempdir()
        .unwrap();
    let outside = td.path().join("outside-secret");
    std::fs::write(&outside, b"secret").unwrap();
    let root = td.path().join("extract");
    std::fs::create_dir(&root).unwrap();

    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Link);
    header.set_path("escape").unwrap();
    header.set_link_name("../outside-secret").unwrap();
    header.set_cksum();
    builder.append(&header, &[][..]).unwrap();
    let bytes = builder.into_inner().unwrap();

    let mut archive = tar::Archive::new(&bytes[..]);
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert!(entry.unpack_in(&root).is_err());
    assert!(!root.join("escape").exists());

    let record = std::fs::read_to_string(root.join(".tar-security-record")).unwrap();
    assert!(record.contains("event=hardlink_denied"));
    assert!(record.contains("reason=outside_or_missing_target"));
    assert!(record.contains("link_name=\"../outside-secret\""));
}

#[test]
fn hardlink_does_not_treat_audit_file_as_authorization() {
    let td = Builder::new().prefix("hardlink-restart").tempdir().unwrap();
    let root = td.path().join("extract");
    std::fs::create_dir(&root).unwrap();

    let mut builder = tar::Builder::new(Vec::new());
    let mut regular = tar::Header::new_gnu();
    regular.set_size(5);
    regular.set_entry_type(tar::EntryType::Regular);
    regular.set_path("original").unwrap();
    regular.set_cksum();
    builder.append(&regular, &b"hello"[..]).unwrap();
    let result = tar::Archive::new(&builder.into_inner().unwrap()[..]).unpack(&root);

    let mut builder = tar::Builder::new(Vec::new());
    let mut hardlink = tar::Header::new_gnu();
    hardlink.set_size(0);
    hardlink.set_entry_type(tar::EntryType::Link);
    hardlink.set_path("alias").unwrap();
    hardlink.set_link_name("original").unwrap();
    hardlink.set_cksum();
    builder.append(&hardlink, &[][..]).unwrap();
    let hardlink_result = tar::Archive::new(&builder.into_inner().unwrap()[..]).unpack(&root);

    assert!(result.is_ok());
    assert!(hardlink_result.is_err());
    assert!(!root.join("alias").exists());
    assert_eq!(std::fs::read(root.join("original")).unwrap(), b"hello");
}
