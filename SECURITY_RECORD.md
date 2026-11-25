# Atomic extraction security record

Reference baseline: `composefs/tar-rs@2c19ee2fbd01a306127e027cb05a02568ccda1b3`.
Workspace snapshot: `82ec0b6a786c37bcebd29fcececc056e2a40f9f2`.

## Incident reproduced

A regular-file header declares a body size larger than the bytes actually
supplied by the reader. Before this change, `Entry::unpack_in` opened the final
destination and copied the stream directly into it. A truncated in-memory body
therefore produced a partial destination file before returning:

```text
error kind: Other
error: failed to unpack `<root>/partial.txt`
`<root>/partial.txt` contents: b"hello"
```

A reader that returns `UnexpectedEof` instead of a clean EOF retained that
underlying error kind, but likewise left the partial final file.

## Publication boundary

For calls through the security-checked `Entry::unpack_in` API (including
`Archive::unpack`), regular and unknown file types now follow this sequence:

1. Create a unique `O_CREAT | O_EXCL` sibling staging file named
   `.tar-rs-staging-<pid>-<sequence>` in the final member's parent directory.
2. Stream all existing `EntryIo` data and sparse-hole blocks into that file.
   The complete entry is never buffered in memory.
3. Verify every `Take` fragment's copied length and verify the staging inode
   size equals the header/PAX/sparse logical size.
4. Apply mtime, ownership, permissions and xattrs to the staging file or its
   open descriptor before publication.
5. Publish only after verification:
   - with overwrite enabled, rename the staging file over the destination;
   - with overwrite disabled, atomically hard-link the staging file to the new
     destination so an existing path still produces `AlreadyExists`, then
     remove the staging name.
6. Remove the staging path on every error path. A failed replacement leaves
   the previous destination file intact.

Direct `Entry::unpack` intentionally keeps its historical rootless,
direct-write behavior and API return type.

## Compatibility notes

- Short clean EOF still produces `ErrorKind::Other` with the historical
  `failed to write entire file` cause.
- A failing reader's error kind (for example `UnexpectedEof`) is preserved.
- Valid regular, large/short-read and sparse streaming entries continue to
  extract with the same content and metadata.
- No new runtime dependencies are introduced.

## Reviewable extraction-root record

Rejected atomic publications append one event per line to:

```text
<extraction-root>/.tar-security-record
```

The event records the archive header offset, member path, declared size, error
kind, error/source chain and `target_published="false"`. The writer refuses to
append through a symlink or a Unix multi-link inode that may share data outside
the root; such a directory entry is replaced with a fresh regular audit file.

A local reproduction with an 11-byte header and five streamed bytes produced:

```text
error kind: Other
target exists: false
event="atomic_file_publication" decision="rejected" header_offset=0 \
declared_size=11 staged_bytes=5 entry_path="partial.txt" \
error_kind=Other error="failed to write entire file" \
error_chain="failed to write entire file" target_published="false"
```

## Regression coverage

`tests/uid39251_atomic_unpack.rs` covers:

- clean short-body rollback and audit record content;
- preservation of `UnexpectedEof`;
- valid large streaming extraction through a one-byte reader;
- preservation of an existing file when its replacement is invalid;
- `AlreadyExists` compatibility with overwrite disabled;
- `Archive::unpack` rollback;
- symlink and external-hard-link attempts against the audit record.
