# Security Records

This file records security-relevant behavior changes in this crate so that
downstream consumers can audit the security conclusions they inherit,
instead of receiving them as unreviewable statements.

## 2026-11-25: Sparse entry expansion quota

**Issue.** A GNU sparse entry declares a logical size (`real_size`) that
may be vastly larger than the data stored in the archive; the holes are
recreated on unpack via `seek` + `set_len`. Before this change, nothing
bounded the total expansion when unpacking (`Archive::unpack`,
`Entry::unpack`, `Entry::unpack_in`), so a tiny malicious archive could
declare petabytes of logical size and exhaust the consumer's disk
("sparse bomb"). Downstream consumers of the unpacked files would inherit
files they never budgeted for.

**Fix.** Based on composefs/tar-rs@`2c19ee2fbd01a306127e027cb05a02568ccda1b3`,
the public unpack path now validates the total expansion of a sparse entry
(data + holes) against a writable quota *before* the destination file is
created, and rejects the entry if it exceeds it. A rejected entry is never
published to the destination. The quota:

- defaults to 1 TiB (`DEFAULT_MAX_SPARSE_UNPACKED_SIZE`),
- is configurable via `Archive::set_max_sparse_unpacked_size` and
  `Entry::set_max_sparse_unpacked_size`,
- can be disabled by setting it to `u64::MAX`,
- applies only to sparse entries; the expansion of regular files is
  bounded by the archive itself.

Legitimate sparse files and small holes are unaffected.

**Verification.** `cargo test sparse` covers:

- `sparse_bomb_rejected_by_default_quota`: a tiny archive declaring a
  2 TiB sparse file is rejected by the default quota and nothing is
  published to the destination;
- `sparse_expansion_quota`: table-driven accept/reject at the quota
  boundary, including a disabled quota;
- `sparse_quota_configurable_per_entry`: the entry-level override;
- `regular_file_not_subject_to_sparse_quota`: regular files are
  unaffected even with a zero quota;
- pre-existing `extract_sparse`, `large_sparse`, `sparse_with_trailing`,
  `writing_sparse`: legitimate sparse files keep working.

**Residual considerations.**

- The quota is a static bound, not free-space detection; consumers should
  size it to their actual writable budget.
- On filesystems without sparse-file support, holes consume real blocks,
  so the 1 TiB default may still be too generous there.
- Reading (rather than unpacking) sparse entries is not quota-checked.
- A rejected entry may still leave behind empty parent directories created
  earlier in the unpack walk; the file itself is never published.
