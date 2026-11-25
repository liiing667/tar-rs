extern crate tar;
extern crate tempfile;

use std::fs;
use std::fs::create_dir;
use std::fs::File;
use std::io::Read;

use tempfile::Builder;

#[test]
fn absolute_symlink() {
    let mut ar = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_path("foo").unwrap();
    header.set_link_name("/bar").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    ar.unpack(td.path()).unwrap();

    td.path().join("foo").symlink_metadata().unwrap();

    let mut ar = tar::Archive::new(&bytes[..]);
    let mut entries = ar.entries().unwrap();
    let entry = entries.next().unwrap().unwrap();
    assert_eq!(&*entry.link_name_bytes().unwrap(), b"/bar");
}

#[test]
fn absolute_hardlink() {
    let td = Builder::new().prefix("tar").tempdir().unwrap();
    let mut ar = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("foo").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Link);
    header.set_path("bar").unwrap();
    // This absolute path under tempdir will be created at unpack time
    header.set_link_name(td.path().join("foo")).unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);

    ar.unpack(td.path()).unwrap();
    td.path().join("foo").metadata().unwrap();
    td.path().join("bar").metadata().unwrap();
}

#[test]
fn relative_hardlink() {
    let mut ar = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("foo").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Link);
    header.set_path("bar").unwrap();
    header.set_link_name("foo").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    ar.unpack(td.path()).unwrap();
    td.path().join("foo").metadata().unwrap();
    td.path().join("bar").metadata().unwrap();
}

#[test]
fn absolute_link_deref_error() {
    let mut ar = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_path("foo").unwrap();
    header.set_link_name("/").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("foo/bar").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    assert!(ar.unpack(td.path()).is_err());
    td.path().join("foo").symlink_metadata().unwrap();
    assert!(File::open(td.path().join("foo").join("bar")).is_err());
}

#[test]
fn relative_link_deref_error() {
    let mut ar = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_path("foo").unwrap();
    header.set_link_name("../../../../").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("foo/bar").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    assert!(ar.unpack(td.path()).is_err());
    td.path().join("foo").symlink_metadata().unwrap();
    assert!(File::open(td.path().join("foo").join("bar")).is_err());
}

#[test]
#[cfg(unix)]
fn directory_maintains_permissions() {
    use ::std::os::unix::fs::PermissionsExt;

    let mut ar = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Directory);
    header.set_path("foo").unwrap();
    header.set_mode(0o777);
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    ar.unpack(td.path()).unwrap();
    let f = File::open(td.path().join("foo")).unwrap();
    let md = f.metadata().unwrap();
    assert!(md.is_dir());
    assert_eq!(md.permissions().mode(), 0o40777);
}

#[test]
#[cfg(unix)]
fn set_entry_mask() {
    use ::std::os::unix::fs::PermissionsExt;

    let mut ar = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("foo").unwrap();
    header.set_mode(0o777);
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);
    let td = Builder::new().prefix("tar").tempdir().unwrap();
    let foo_path = td.path().join("foo");

    let mut entries = ar.entries().unwrap();
    let mut foo = entries.next().unwrap().unwrap();
    foo.set_mask(0o027);
    foo.unpack(&foo_path).unwrap();

    let f = File::open(foo_path).unwrap();
    let md = f.metadata().unwrap();
    assert!(md.is_file());
    assert_eq!(md.permissions().mode(), 0o100750);
}

#[test]
#[cfg(not(windows))] // dangling symlinks have weird permissions
fn modify_link_just_created() {
    let mut ar = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_path("foo").unwrap();
    header.set_link_name("bar").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("bar/foo").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("foo/bar").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    ar.unpack(td.path()).unwrap();

    File::open(td.path().join("bar/foo")).unwrap();
    File::open(td.path().join("bar/bar")).unwrap();
    File::open(td.path().join("foo/foo")).unwrap();
    File::open(td.path().join("foo/bar")).unwrap();
}

#[test]
#[cfg(not(windows))] // dangling symlinks have weird permissions
fn modify_outside_with_relative_symlink() {
    let mut ar = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_path("symlink").unwrap();
    header.set_link_name("..").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("symlink/foo/bar").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    let tar_dir = td.path().join("tar");
    create_dir(&tar_dir).unwrap();
    assert!(ar.unpack(tar_dir).is_err());
    assert!(!td.path().join("foo").exists());
}

#[test]
fn parent_paths_error() {
    let mut ar = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_path("foo").unwrap();
    header.set_link_name("..").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("foo/bar").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    assert!(ar.unpack(td.path()).is_err());
    td.path().join("foo").symlink_metadata().unwrap();
    assert!(File::open(td.path().join("foo").join("bar")).is_err());
}

#[test]
#[cfg(unix)]
fn good_parent_paths_ok() {
    use std::path::PathBuf;
    let mut ar = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_path(PathBuf::from("foo").join("bar")).unwrap();
    header
        .set_link_name(PathBuf::from("..").join("bar"))
        .unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("bar").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    ar.unpack(td.path()).unwrap();
    td.path().join("foo").join("bar").read_link().unwrap();
    let dst = td.path().join("foo").join("bar").canonicalize().unwrap();
    File::open(dst).unwrap();
}

#[test]
fn modify_hard_link_just_created() {
    let mut ar = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Link);
    header.set_path("foo").unwrap();
    header.set_link_name("../test").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let mut header = tar::Header::new_gnu();
    header.set_size(1);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("foo").unwrap();
    header.set_cksum();
    ar.append(&header, &b"x"[..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);

    let td = Builder::new().prefix("tar").tempdir().unwrap();

    let test = td.path().join("test");
    File::create(&test).unwrap();

    let dir = td.path().join("dir");
    assert!(ar.unpack(&dir).is_err());

    let mut contents = Vec::new();
    File::open(&test)
        .unwrap()
        .read_to_end(&mut contents)
        .unwrap();
    assert_eq!(contents.len(), 0);
}

#[test]
fn modify_symlink_just_created() {
    let mut ar = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_path("foo").unwrap();
    header.set_link_name("../test").unwrap();
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let mut header = tar::Header::new_gnu();
    header.set_size(1);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_path("foo").unwrap();
    header.set_cksum();
    ar.append(&header, &b"x"[..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);

    let td = Builder::new().prefix("tar").tempdir().unwrap();

    let test = td.path().join("test");
    File::create(&test).unwrap();

    let dir = td.path().join("dir");
    ar.unpack(&dir).unwrap();

    let mut contents = Vec::new();
    File::open(&test)
        .unwrap()
        .read_to_end(&mut contents)
        .unwrap();
    assert_eq!(contents.len(), 0);
}

/// Test that unpacking a tarball with a symlink followed by a directory entry
/// with the same name does not allow modifying permissions of arbitrary directories
/// outside the extraction path.
#[test]
#[cfg(unix)]
fn symlink_dir_collision_does_not_modify_external_dir_permissions() {
    use ::std::fs;
    use ::std::os::unix::fs::PermissionsExt;

    let td = Builder::new().prefix("tar").tempdir().unwrap();

    let target_dir = td.path().join("target-dir");
    fs::create_dir(&target_dir).unwrap();
    fs::set_permissions(&target_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let before_mode = fs::metadata(&target_dir).unwrap().permissions().mode() & 0o7777;
    assert_eq!(before_mode, 0o700);

    let extract_dir = td.path().join("extract-dir");
    fs::create_dir(&extract_dir).unwrap();

    let mut ar = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_path("foo").unwrap();
    header.set_link_name(&target_dir).unwrap();
    header.set_mode(0o777);
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let mut header = tar::Header::new_gnu();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Directory);
    header.set_path("foo").unwrap();
    header.set_mode(0o777);
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);

    let result = ar.unpack(&extract_dir);
    assert!(result.is_err());

    let symlink_path = extract_dir.join("foo");
    assert!(symlink_path
        .symlink_metadata()
        .unwrap()
        .file_type()
        .is_symlink());

    let after_mode = fs::metadata(&target_dir).unwrap().permissions().mode() & 0o7777;
    assert_eq!(after_mode, 0o700);
}

// ---------------------------------------------------------------------------
// PAX vs USTAR path interpretation (single-source-of-truth hardening)
//
// A malicious archive can declare one path in a PAX `path` record and a
// different one in the USTAR header. The public `Entry::path` view and the
// on-disk destination chosen by `unpack_in` must always be the same
// interpretation. Disagreements that are not explainable by a legitimate
// long-name truncation must be rejected, and every accepted PAX override must
// leave an auditable record in the extraction root.
// ---------------------------------------------------------------------------

/// Build an archive whose single regular entry carries both a PAX `path`
/// extension and an independently controlled USTAR header path.
fn build_pax_ustar_path_archive(pax_path: &[u8], ustar_path: &str) -> Vec<u8> {
    let mut ar = tar::Builder::new(Vec::new());

    // PAX local extension header describing the next entry.
    ar.append_pax_extensions([("path", pax_path)]).unwrap();

    let mut header = tar::Header::new_ustar();
    header.set_path(ustar_path).unwrap();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    ar.into_inner().unwrap()
}

#[test]
fn benign_pax_long_path_truncation_is_accepted() {
    // Real-world writers (GNU/BSD tar) keep the first 100 bytes of an
    // over-long path in the USTAR name field and the full path in PAX.
    let long = "a".repeat(140);
    let truncated = long[..100].to_owned();
    let bytes = build_pax_ustar_path_archive(long.as_bytes(), &truncated);

    let mut ar = tar::Archive::new(&bytes[..]);
    let entry = ar.entries().unwrap().next().unwrap().unwrap();
    assert_eq!(entry.path().unwrap().to_str().unwrap(), long);
}

#[test]
fn ustar_prefix_reconstruction_with_matching_pax_is_accepted() {
    // A 121-byte path cannot fit in the 100-byte USTAR name field, but it CAN
    // be represented losslessly by splitting it across the USTAR prefix(155)
    // and name(100) fields. In that case the reconstructed USTAR name is
    // *equal* to the PAX path (not a truncation), so it must be accepted
    // without either an error or an override record.
    let full = format!("{}/{}", "d".repeat(60), "f".repeat(60));
    assert_eq!(full.len(), 121);

    let mut ar = tar::Builder::new(Vec::new());
    let pax: &[u8] = full.as_bytes();
    ar.append_pax_extensions([("path", pax)]).unwrap();

    let mut header = tar::Header::new_ustar();
    header.set_path(&full).unwrap();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    assert_eq!(&*header.path_bytes(), full.as_bytes());
    ar.append(&header, &[][..]).unwrap();
    let bytes = ar.into_inner().unwrap();

    let mut archive = tar::Archive::new(&bytes[..]);
    let entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert_eq!(entry.path().unwrap().to_str().unwrap(), full);
    assert_eq!(&*entry.path_bytes(), full.as_bytes());

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    let mut archive = tar::Archive::new(&bytes[..]);
    let mut entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert!(entry.unpack_in(td.path()).unwrap());
    assert!(td.path().join(&full).is_file());
    assert!(!td.path().join(".tar-security-record").exists());
}

#[test]
fn short_non_saturated_prefix_is_not_accepted_as_truncation() {
    // A USTAR name that is a byte prefix of the PAX name but does NOT fill the
    // 100-byte field is not a legitimate long-name truncation: the whole name
    // would have fit, so a real writer would store it losslessly. Accepting
    // such a pair would re-open a parser differential and must be rejected.
    let mut ar = tar::Builder::new(Vec::new());
    ar.append_pax_extensions([("path", b"abcdef".as_slice())])
        .unwrap();

    let mut header = tar::Header::new_ustar();
    // "abc" is a prefix of "abcdef" but leaves the 100-byte field unfilled.
    header.set_path("abc").unwrap();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();
    let bytes = ar.into_inner().unwrap();

    let mut archive = tar::Archive::new(&bytes[..]);
    let entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert!(
        entry.path().is_err(),
        "a short, non-saturated prefix must not be treated as benign truncation"
    );
}

#[test]
fn saturated_field_truncation_is_still_accepted() {
    // The genuine long-name case: a full 100-byte USTAR name that is a prefix
    // of a longer PAX path must remain accepted.
    let long = format!("{}/tail.txt", "q".repeat(120));
    assert!(long.len() > 100);
    let truncated = long[..100].to_owned();
    assert_eq!(truncated.len(), 100);
    let bytes = build_pax_ustar_path_archive(long.as_bytes(), &truncated);

    let mut archive = tar::Archive::new(&bytes[..]);
    let entry = archive.entries().unwrap().next().unwrap().unwrap();
    assert_eq!(entry.path().unwrap().to_str().unwrap(), long);
}

#[test]
fn divergent_pax_and_ustar_paths_are_rejected_by_public_path() {
    // The PAX extension points at a benign name while the USTAR header points
    // somewhere entirely unrelated. Neither is a prefix of the other, so this
    // must be refused rather than resolved. (The USTAR spelling itself stays
    // well-formed so the archive can be constructed; the danger is the
    // disagreement between two independently controlled names.)
    let bytes = build_pax_ustar_path_archive(b"benign.txt", "other/place.txt");

    let mut ar = tar::Archive::new(&bytes[..]);
    let entry = ar.entries().unwrap().next().unwrap().unwrap();
    assert!(
        entry.path().is_err(),
        "public path() must reject disagreeing PAX/USTAR names"
    );
}

#[test]
fn divergent_pax_and_ustar_paths_are_rejected_during_unpack() {
    let bytes = build_pax_ustar_path_archive(b"benign.txt", "totally/different/name");

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);
    let mut entry = ar.entries().unwrap().next().unwrap().unwrap();

    let result = entry.unpack_in(td.path());
    assert!(
        result.is_err(),
        "unpack_in must refuse to write an entry whose PAX/USTAR names disagree"
    );

    // Nothing matching either spelling may have been created.
    assert!(!td.path().join("benign.txt").exists());
    assert!(!td.path().join("totally").exists());
}

#[test]
fn unpack_uses_the_pax_path_and_records_the_override() {
    // A legitimate long path: the USTAR name is a truncated prefix of the PAX
    // path. Extraction must follow the PAX spelling and audit the override.
    let long = format!("{}/payload.txt", "nested".repeat(20));
    assert!(long.len() > 100, "test requires an over-long path");
    let truncated = long[..100].to_owned();
    let bytes = build_pax_ustar_path_archive(long.as_bytes(), &truncated);

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);
    let mut entry = ar.entries().unwrap().next().unwrap().unwrap();

    // The publicly visible path and the extracted location must agree.
    let public_path = entry.path().unwrap().to_path_buf();
    assert!(entry.unpack_in(td.path()).unwrap());
    let on_disk = td.path().join(&public_path);
    assert!(on_disk.is_file(), "expected file at the public path");

    // The override must be reviewable from inside the extraction root.
    let record = td.path().join(".tar-security-record");
    let contents = fs::read_to_string(&record).expect("security record must be written");
    assert!(contents.contains("path conflict"), "record: {contents}");
    assert!(
        contents.contains("benign_truncation=true"),
        "record: {contents}"
    );
    assert!(
        contents.contains(long.as_str()),
        "record must contain the full PAX path: {contents}"
    );
}

#[test]
fn no_security_record_when_header_and_pax_agree() {
    // When the PAX path duplicates the USTAR path there is no override to
    // audit: the record (if created) must never claim a benign truncation.
    let bytes = build_pax_ustar_path_archive(b"same.txt", "same.txt");

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);
    let mut entry = ar.entries().unwrap().next().unwrap().unwrap();
    assert!(entry.unpack_in(td.path()).unwrap());
    assert!(td.path().join("same.txt").is_file());
    assert!(
        !td.path().join(".tar-security-record").exists(),
        "equal PAX/USTAR names must not create an override record"
    );
}

/// Build an archive with a symlink whose PAX `linkpath` and USTAR linkname
/// disagree.
fn build_divergent_linkpath_archive(pax_link: &[u8], ustar_link: &str) -> Vec<u8> {
    let mut ar = tar::Builder::new(Vec::new());
    ar.append_pax_extensions([("linkpath", pax_link)]).unwrap();

    let mut header = tar::Header::new_ustar();
    header.set_path("link").unwrap();
    header.set_link_name(ustar_link).unwrap();
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_mode(0o777);
    header.set_cksum();
    ar.append(&header, &[][..]).unwrap();

    ar.into_inner().unwrap()
}

#[test]
fn divergent_pax_and_ustar_linkpaths_are_rejected() {
    // Both spellings stay well-formed; the disagreement itself is the attack.
    let bytes = build_divergent_linkpath_archive(b"safe_target", "other_target");

    let mut ar = tar::Archive::new(&bytes[..]);
    let entry = ar.entries().unwrap().next().unwrap().unwrap();
    assert!(
        entry.link_name().is_err(),
        "conflicting link names must not be silently accepted"
    );

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);
    let mut entry = ar.entries().unwrap().next().unwrap().unwrap();
    assert!(entry.unpack_in(td.path()).is_err());
    assert!(!td.path().join("link").exists());
}

#[test]
fn benign_long_linkpath_truncation_is_accepted_and_recorded() {
    let long_link = format!("{}/target", "d".repeat(110));
    assert!(long_link.len() > 100);
    let truncated = long_link[..100].to_owned();
    let bytes = build_divergent_linkpath_archive(long_link.as_bytes(), &truncated);

    let td = Builder::new().prefix("tar").tempdir().unwrap();
    let mut ar = tar::Archive::new(&bytes[..]);
    let mut entry = ar.entries().unwrap().next().unwrap().unwrap();

    assert_eq!(
        entry.link_name().unwrap().unwrap().to_str().unwrap(),
        long_link
    );
    assert!(entry.unpack_in(td.path()).unwrap());

    let record = fs::read_to_string(td.path().join(".tar-security-record")).unwrap();
    assert!(record.contains("link name conflict"), "record: {record}");
    assert!(
        record.contains("benign_truncation=true"),
        "record: {record}"
    );
}

#[test]
fn pax_traversal_path_cannot_escape_and_views_agree() {
    // The PAX path is authoritative and contains a parent component. The
    // public `path()` view and extraction must agree on this exact spelling,
    // and extraction must not leave the destination root (it returns `false`
    // for a traversal entry). The USTAR name is a valid truncated prefix so
    // the archive is well-formed; the traversal lives only in the PAX path.
    let pax_path = format!("{}/../../escape.txt", "a".repeat(110));
    let truncated = pax_path[..100].to_owned();
    assert!(pax_path.len() > 100);
    let bytes = build_pax_ustar_path_archive(pax_path.as_bytes(), &truncated);

    let td = Builder::new().prefix("tar").tempdir().unwrap();

    // Both accessors expose the same authoritative (PAX) spelling.
    {
        let mut ar = tar::Archive::new(&bytes[..]);
        let entry = ar.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(entry.path().unwrap().to_str().unwrap(), pax_path);
        assert_eq!(&*entry.path_bytes(), pax_path.as_bytes());
    }

    let mut ar = tar::Archive::new(&bytes[..]);
    let mut entry = ar.entries().unwrap().next().unwrap().unwrap();
    // Parent components are skipped: nothing is extracted and nothing escapes.
    assert!(!entry.unpack_in(td.path()).unwrap());
    assert!(!td.path().join("escape.txt").exists());
    assert!(!td.path().parent().unwrap().join("escape.txt").exists());

    // The entry was skipped for traversal, so no misleading "accepted" audit
    // line must be written for it.
    assert!(!td.path().join(".tar-security-record").exists());
}

#[test]
fn validator_and_consumer_resolve_every_entry_identically() {
    // Models a real defense-in-depth workflow: a validator first walks every
    // entry and records what `path()` says, then extraction runs separately.
    // The archive mixes a benign long-path entry and a malicious divergent
    // entry; extraction must reject exactly the entry the validator flagged.
    let mut ar_bytes: Vec<u8> = Vec::new();
    {
        let mut ar = tar::Builder::new(&mut ar_bytes);

        // Entry 1: legitimate long path (truncated USTAR prefix).
        let good_long = format!("{}/ok.txt", "g".repeat(110));
        let good_long_bytes: &[u8] = good_long.as_bytes();
        ar.append_pax_extensions([("path", good_long_bytes)])
            .unwrap();
        let mut h = tar::Header::new_ustar();
        h.set_path(&good_long[..100]).unwrap();
        h.set_size(0);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        ar.append(&h, &[][..]).unwrap();

        // Entry 2: PAX and USTAR names disagree with no prefix relationship.
        ar.append_pax_extensions([("path", b"innocent.txt".as_slice())])
            .unwrap();
        let mut h = tar::Header::new_ustar();
        h.set_path("hidden/evil").unwrap();
        h.set_size(0);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        ar.append(&h, &[][..]).unwrap();
    }

    // Validator pass: classify each entry purely from the public `path()`.
    let mut verdicts: Vec<Result<String, ()>> = Vec::new();
    {
        let mut ar = tar::Archive::new(&ar_bytes[..]);
        for entry in ar.entries().unwrap() {
            verdicts.push(
                entry
                    .unwrap()
                    .path()
                    .map(|p| p.to_str().unwrap().to_owned())
                    .map_err(|_| ()),
            );
        }
    }
    assert!(verdicts[0].is_ok(), "long path must validate");
    assert!(verdicts[1].is_err(), "divergent path must be flagged");

    // Consumer pass: extraction must behave consistently with the verdicts.
    let td = Builder::new().prefix("tar").tempdir().unwrap();
    let mut outcomes = Vec::new();
    {
        let mut ar = tar::Archive::new(&ar_bytes[..]);
        for entry in ar.entries().unwrap() {
            outcomes.push(entry.unwrap().unpack_in(td.path()).is_ok());
        }
    }
    assert!(outcomes[0], "validated long path must extract");
    assert!(!outcomes[1], "flagged entry must not extract");

    // Only the benign entry exists on disk, under its public PAX spelling.
    let good_relative: &str = verdicts[0].as_ref().unwrap();
    assert!(td.path().join(good_relative).is_file());
    assert!(!td.path().join("innocent.txt").exists());
    assert!(!td.path().join("hidden").exists());
}

#[cfg(unix)]
#[test]
fn security_record_refuses_to_follow_a_symlink() {
    // Attack: the archive first places a symlink at the well-known security
    // record path pointing at a file outside the extraction root. A later
    // entry carries a benign PAX long-name override, which would normally be
    // appended to the record. The write must fail (or be contained) instead of
    // following the symlink to the external target.
    let td = Builder::new().prefix("tar").tempdir().unwrap();
    let outside = td.path().join("outside-target.txt");
    fs::write(&outside, b"untouched").unwrap();

    let mut ar = tar::Builder::new(Vec::new());

    // Entry 1: symlink at the record path -> absolute external target.
    let mut link_header = tar::Header::new_ustar();
    link_header.set_path(".tar-security-record").unwrap();
    link_header.set_link_name(&outside).unwrap();
    link_header.set_size(0);
    link_header.set_entry_type(tar::EntryType::Symlink);
    link_header.set_mode(0o777);
    link_header.set_cksum();
    ar.append(&link_header, &[][..]).unwrap();

    // Entry 2: benign PAX long path (truncated USTAR prefix) requiring a
    // security record write.
    let long = format!("{}/payload.txt", "z".repeat(110));
    let truncated = long[..100].to_owned();
    let long_bytes: &[u8] = long.as_bytes();
    ar.append_pax_extensions([("path", long_bytes)]).unwrap();
    let mut file_header = tar::Header::new_ustar();
    file_header.set_path(&truncated).unwrap();
    file_header.set_size(0);
    file_header.set_entry_type(tar::EntryType::Regular);
    file_header.set_cksum();
    ar.append(&file_header, &[][..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut archive = tar::Archive::new(&bytes[..]);

    // Extraction of the record-writing entry must surface an error rather
    // than silently writing through the symlink. We iterate so the earlier
    // symlink entry is created first.
    let mut saw_record_error = false;
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry.unpack_in(td.path()).is_err() {
            saw_record_error = true;
        }
    }
    assert!(
        saw_record_error,
        "writing the record through a symlink must be rejected"
    );

    // The external file must be completely untouched.
    assert_eq!(fs::read(&outside).unwrap(), b"untouched");

    // The planted symlink remains a symlink (it was not replaced by a file).
    let meta = fs::symlink_metadata(td.path().join(".tar-security-record")).unwrap();
    assert!(meta.file_type().is_symlink());
}

#[test]
fn security_record_keeps_audit_lines_on_their_own_lines() {
    // An archive may contain a regular file using the manifest name. Audit
    // lines must never be silently glued onto that pre-existing content (which
    // may not even end in a newline); a separator is inserted instead.
    let td = Builder::new().prefix("tar").tempdir().unwrap();
    let mut ar = tar::Builder::new(Vec::new());

    // Pre-existing archive file with content lacking a trailing newline.
    let mut data_header = tar::Header::new_ustar();
    data_header.set_path(".tar-security-record").unwrap();
    data_header.set_size(4);
    data_header.set_entry_type(tar::EntryType::Regular);
    data_header.set_cksum();
    ar.append(&data_header, &b"data"[..]).unwrap();

    // Benign long path that triggers an audit record.
    let long = format!("{}/p.txt", "m".repeat(110));
    let truncated = long[..100].to_owned();
    let long_bytes: &[u8] = long.as_bytes();
    ar.append_pax_extensions([("path", long_bytes)]).unwrap();
    let mut long_header = tar::Header::new_ustar();
    long_header.set_path(&truncated).unwrap();
    long_header.set_size(0);
    long_header.set_entry_type(tar::EntryType::Regular);
    long_header.set_cksum();
    ar.append(&long_header, &[][..]).unwrap();

    let bytes = ar.into_inner().unwrap();
    let mut archive = tar::Archive::new(&bytes[..]);
    archive.unpack(td.path()).unwrap();

    let content = fs::read_to_string(td.path().join(".tar-security-record")).unwrap();
    // The original bytes are preserved and immediately followed by a newline
    // separator rather than being concatenated with the audit text.
    assert!(content.starts_with("data\n"), "content was: {content:?}");
    assert!(
        content.contains("path conflict:") && content.contains("benign_truncation=true"),
        "audit line missing: {content:?}"
    );
    // Every audit record occupies its own line.
    assert!(content.lines().any(|l| l.starts_with("header_offset=")));
}
