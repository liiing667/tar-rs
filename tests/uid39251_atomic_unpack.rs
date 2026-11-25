use std::fs;
use std::io::{self, Chain, Cursor, Read};
use std::path::Path;

use tar::{Archive, Header};
use tempfile::tempdir;

const RECORD_FILE: &str = ".tar-security-record";

fn malformed_archive(declared_size: u64, body: &[u8]) -> Vec<u8> {
    let mut header = Header::new_gnu();
    header.set_path("partial.txt").unwrap();
    header.set_size(declared_size);
    header.set_cksum();

    let mut bytes = header.as_bytes().to_vec();
    bytes.extend_from_slice(body);
    bytes
}

fn valid_archive(content: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = Header::new_gnu();
    header.set_path("stream.bin").unwrap();
    header.set_size(content.len() as u64);
    header.set_cksum();
    builder.append(&header, content).unwrap();
    builder.into_inner().unwrap()
}

fn assert_no_staging_files(root: &Path) {
    let mut staging = Vec::new();
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            let file_type = entry.file_type().unwrap();
            let path = entry.path();
            if file_type.is_dir() {
                directories.push(path);
            } else if entry
                .file_name()
                .to_string_lossy()
                .starts_with(".tar-rs-staging-")
            {
                staging.push(entry.file_name());
            }
        }
    }
    assert!(staging.is_empty(), "staging files left behind: {staging:?}");
}

struct PartialThenError {
    body: Cursor<Vec<u8>>,
}

impl Read for PartialThenError {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.body.read(buf)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "body ended before the declared header size",
            ));
        }
        Ok(n)
    }
}

struct OneByteReader<R>(R);

impl<R: Read> Read for OneByteReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return self.0.read(buf);
        }
        self.0.read(&mut buf[..1])
    }
}

#[test]
fn unpack_in_rolls_back_short_body_and_writes_security_record() {
    let archive = malformed_archive(11, b"hello");
    let dir = tempdir().unwrap();

    let mut ar = Archive::new(Cursor::new(archive));
    let mut entry = ar.entries().unwrap().next().unwrap().unwrap();
    let err = entry.unpack_in(dir.path()).unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::Other);
    let target = dir.path().join("partial.txt");
    assert!(!target.exists(), "partial member was published");
    assert_no_staging_files(dir.path());

    let record = fs::read_to_string(dir.path().join(RECORD_FILE)).unwrap();
    assert!(record.contains("event=\"atomic_file_publication\""));
    assert!(record.contains("decision=\"rejected\""));
    assert!(record.contains("entry_path=\"partial.txt\""));
    assert!(record.contains("declared_size=11"));
    assert!(record.contains("staged_bytes=5"));
    assert!(record.contains("failed to write entire file"));
    assert!(record.contains("target_published=\"false\""));
}

#[test]
fn unpack_in_preserves_underlying_unexpected_eof_kind() {
    let mut header = Header::new_gnu();
    header.set_path("eof.txt").unwrap();
    header.set_size(10);
    header.set_cksum();
    let header_bytes = header.as_bytes().to_vec();

    let reader: Chain<Cursor<Vec<u8>>, PartialThenError> =
        Cursor::new(header_bytes).chain(PartialThenError {
            body: Cursor::new(b"abc".to_vec()),
        });
    let dir = tempdir().unwrap();

    let mut ar = Archive::new(reader);
    let mut entry = ar.entries().unwrap().next().unwrap().unwrap();
    let err = entry.unpack_in(dir.path()).unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    assert!(!dir.path().join("eof.txt").exists());
    assert_no_staging_files(dir.path());

    let record = fs::read_to_string(dir.path().join(RECORD_FILE)).unwrap();
    assert!(record.contains("error_kind=UnexpectedEof"));
}

#[test]
fn unpack_in_publishes_complete_streaming_entry() {
    let content: Vec<u8> = (0..128 * 1024).map(|i| (i % 251) as u8).collect();
    let archive = valid_archive(&content);
    let dir = tempdir().unwrap();

    let mut ar = Archive::new(OneByteReader(Cursor::new(archive)));
    let mut entry = ar.entries().unwrap().next().unwrap().unwrap();
    assert!(entry.unpack_in(dir.path()).unwrap());

    assert_eq!(fs::read(dir.path().join("stream.bin")).unwrap(), content);
    assert_no_staging_files(dir.path());
}

#[test]
fn failed_replacement_preserves_existing_published_file() {
    let archive = malformed_archive(11, b"hello");
    let dir = tempdir().unwrap();
    let target = dir.path().join("partial.txt");
    fs::write(&target, b"previously valid content").unwrap();

    let mut ar = Archive::new(Cursor::new(archive));
    let mut entry = ar.entries().unwrap().next().unwrap().unwrap();
    entry.unpack_in(dir.path()).unwrap_err();

    assert_eq!(fs::read(&target).unwrap(), b"previously valid content");
    assert_no_staging_files(dir.path());
}

#[test]
fn overwrite_false_conflict_keeps_already_exists_kind() {
    let archive = valid_archive(b"new content");
    let dir = tempdir().unwrap();
    let target = dir.path().join("stream.bin");
    fs::write(&target, b"old content").unwrap();

    let mut ar = Archive::new(Cursor::new(archive));
    ar.set_overwrite(false);
    let mut entry = ar.entries().unwrap().next().unwrap().unwrap();
    let err = entry.unpack_in(dir.path()).unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&target).unwrap(), b"old content");
    assert_no_staging_files(dir.path());

    let record = fs::read_to_string(dir.path().join(RECORD_FILE)).unwrap();
    assert!(record.contains("error_kind=AlreadyExists"));
}

#[test]
fn archive_unpack_is_atomic_for_short_body() {
    let archive = malformed_archive(32, b"only five bytes");
    let dir = tempdir().unwrap();

    let mut ar = Archive::new(Cursor::new(archive));
    ar.unpack(dir.path()).unwrap_err();

    assert!(!dir.path().join("partial.txt").exists());
    assert_no_staging_files(dir.path());
    assert!(dir.path().join(RECORD_FILE).is_file());
}

#[test]
fn nested_short_body_removes_sibling_staging_file() {
    let mut header = Header::new_gnu();
    header.set_path("dir/partial.txt").unwrap();
    header.set_size(11);
    header.set_cksum();
    let mut archive = header.as_bytes().to_vec();
    archive.extend_from_slice(b"hello");

    let dir = tempdir().unwrap();
    let mut ar = Archive::new(Cursor::new(archive));
    let mut entry = ar.entries().unwrap().next().unwrap().unwrap();
    entry.unpack_in(dir.path()).unwrap_err();

    assert!(!dir.path().join("dir/partial.txt").exists());
    assert_no_staging_files(dir.path());
    assert!(dir.path().join(RECORD_FILE).is_file());
}

#[cfg(unix)]
#[test]
fn security_record_replaces_symlink_instead_of_writing_outside_root() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempdir().unwrap();
    let outside = dir.path().join("outside-audit");
    fs::write(&outside, b"outside").unwrap();
    std::os::unix::fs::symlink(&outside, dir.path().join(RECORD_FILE)).unwrap();

    let archive = malformed_archive(11, b"hello");
    let mut ar = Archive::new(Cursor::new(archive));
    let mut entry = ar.entries().unwrap().next().unwrap().unwrap();
    entry.unpack_in(dir.path()).unwrap_err();

    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    let record_path = dir.path().join(RECORD_FILE);
    let metadata = record_path.symlink_metadata().unwrap();
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.nlink(), 1);
    assert!(fs::read_to_string(record_path)
        .unwrap()
        .contains("decision=\"rejected\""));
}

#[cfg(unix)]
#[test]
fn security_record_replaces_external_hardlink() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempdir().unwrap();
    let outside = dir.path().join("outside-hardlink");
    fs::write(&outside, b"outside").unwrap();
    fs::hard_link(&outside, dir.path().join(RECORD_FILE)).unwrap();

    let archive = malformed_archive(11, b"hello");
    let mut ar = Archive::new(Cursor::new(archive));
    ar.unpack(dir.path()).unwrap_err();

    assert_eq!(fs::read(&outside).unwrap(), b"outside");
    let record_path = dir.path().join(RECORD_FILE);
    let metadata = record_path.metadata().unwrap();
    assert_eq!(metadata.nlink(), 1);
    assert!(fs::read_to_string(record_path)
        .unwrap()
        .contains("atomic_file_publication"));
}
