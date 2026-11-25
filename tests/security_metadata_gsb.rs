use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn temp_root() -> TempDir {
    let target_tmp = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(target_tmp).unwrap();
    TempDir::new_in(target_tmp).unwrap()
}

fn build_metadata_archive(external: &Path) -> Vec<u8> {
    let mut ar = tar::Builder::new(Vec::new());

    let mut link = tar::Header::new_gnu();
    link.set_size(0);
    link.set_entry_type(tar::EntryType::Symlink);
    link.set_path("identity").unwrap();
    link.set_link_name(external).unwrap();
    link.set_mode(0o777);
    link.set_cksum();
    ar.append(&link, &[][..]).unwrap();

    let mut file = tar::Header::new_gnu();
    file.set_size(2);
    file.set_entry_type(tar::EntryType::Regular);
    file.set_path("identity").unwrap();
    file.set_mode(0o640);
    file.set_mtime(1_700_000_000);
    file.set_cksum();
    ar.append(&file, &b"ok"[..]).unwrap();

    ar.into_inner().unwrap()
}

#[test]
fn committed_regular_entry_replaces_redirecting_symlink_and_records() {
    let td = temp_root();
    let root = td.path().join("extract");
    fs::create_dir(&root).unwrap();
    let external = td.path().join("outside");
    fs::write(&external, b"outside").unwrap();

    let bytes = build_metadata_archive(&external);
    let mut ar = tar::Archive::new(&bytes[..]);
    ar.unpack(&root).unwrap();

    assert_eq!(fs::read(root.join("identity")).unwrap(), b"ok");
    assert!(root
        .join("identity")
        .symlink_metadata()
        .unwrap()
        .file_type()
        .is_file());
    assert_eq!(fs::read(&external).unwrap(), b"outside");
    let record = fs::read_to_string(root.join(".tar-security-record")).unwrap();
    assert!(record.contains("committed-current-entry-identity"));
    assert!(record.contains("mode=640"));
}

#[test]
#[cfg(all(unix, feature = "xattr"))]
fn mode_mtime_and_xattr_apply_to_committed_regular_identity() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::UNIX_EPOCH;

    let td = temp_root();
    let root = td.path().join("extract");
    fs::create_dir(&root).unwrap();

    let mut ar = tar::Builder::new(Vec::new());
    ar.append_pax_extensions([("SCHILY.xattr.user.gsb-meta", b"kept".as_slice())])
        .unwrap();
    let mut header = tar::Header::new_gnu();
    header.set_size(2);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("meta").unwrap();
    header.set_mode(0o600);
    header.set_mtime(1_700_000_123);
    header.set_cksum();
    ar.append(&header, &b"ok"[..]).unwrap();
    let bytes = ar.into_inner().unwrap();

    let mut ar = tar::Archive::new(&bytes[..]);
    ar.set_unpack_xattrs(true);
    ar.unpack(&root).unwrap();

    let path = root.join("meta");
    let metadata = path.metadata().unwrap();
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
    assert_eq!(
        metadata
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        1_700_000_123
    );
    assert_eq!(
        xattr::get(&path, "user.gsb-meta").unwrap().as_deref(),
        Some(b"kept".as_slice())
    );
    let record = fs::read_to_string(root.join(".tar-security-record")).unwrap();
    assert!(record.contains("xattr_keys=[user.gsb-meta]"));
    assert!(record.contains("verdict=committed-current-entry-identity"));
}

#[test]
fn metadata_collision_with_external_directory_is_blocked_and_recorded() {
    use std::os::unix::fs::PermissionsExt;

    let td = temp_root();
    let root = td.path().join("extract");
    fs::create_dir(&root).unwrap();
    let outside = td.path().join("outside-dir");
    fs::create_dir(&outside).unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o700)).unwrap();

    let mut ar = tar::Builder::new(Vec::new());
    let mut symlink = tar::Header::new_gnu();
    symlink.set_size(0);
    symlink.set_entry_type(tar::EntryType::Symlink);
    symlink.set_path("collision").unwrap();
    symlink.set_link_name(&outside).unwrap();
    symlink.set_cksum();
    ar.append(&symlink, &[][..]).unwrap();

    let mut dir = tar::Header::new_gnu();
    dir.set_size(0);
    dir.set_entry_type(tar::EntryType::Directory);
    dir.set_path("collision").unwrap();
    dir.set_mode(0o777);
    dir.set_cksum();
    ar.append(&dir, &[][..]).unwrap();
    let bytes = ar.into_inner().unwrap();

    assert!(tar::Archive::new(&bytes[..]).unpack(&root).is_err());
    assert_eq!(
        fs::metadata(&outside).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    let record = fs::read_to_string(root.join(".tar-security-record")).unwrap();
    assert!(record.contains("security-blocked-or-failed"));
}

#[test]
fn security_record_hardlink_is_replaced_instead_of_appending_outside_inode() {
    let td = temp_root();
    let root = td.path().join("extract");
    fs::create_dir(&root).unwrap();
    let outside_record = td.path().join("outside-record");
    fs::write(&outside_record, b"outside-audit").unwrap();
    fs::hard_link(&outside_record, root.join(".tar-security-record")).unwrap();

    let mut ar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(2);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("file").unwrap();
    header.set_cksum();
    ar.append(&header, &b"ok"[..]).unwrap();
    let bytes = ar.into_inner().unwrap();

    tar::Archive::new(&bytes[..]).unpack(&root).unwrap();

    assert_eq!(fs::read(&outside_record).unwrap(), b"outside-audit");
    let record = fs::read_to_string(root.join(".tar-security-record")).unwrap();
    assert!(record.contains("tar-rs extraction security record"));
    assert!(record.contains("committed-current-entry-identity"));
}
