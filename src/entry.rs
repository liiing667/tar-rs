use std::borrow::Cow;
use std::cmp;
use std::fs;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::{self, Error, ErrorKind, SeekFrom};
use std::marker;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use filetime::{self, FileTime};

use crate::archive::ArchiveInner;
use crate::error::TarError;
use crate::header::bytes2path;
use crate::other;
use crate::{Archive, Header, PaxExtensions};

/// A read-only view into an entry of an archive.
///
/// This structure is a window into a portion of a borrowed archive which can
/// be inspected. It acts as a file handle by implementing the Reader trait. An
/// entry cannot be rewritten once inserted into an archive.
pub struct Entry<'a, R: 'a + Read> {
    fields: EntryFields<'a>,
    _ignored: marker::PhantomData<&'a Archive<R>>,
}

// private implementation detail of `Entry`, but concrete (no type parameters)
// and also all-public to be constructed from other modules.
pub struct EntryFields<'a> {
    pub long_pathname: Option<Vec<u8>>,
    pub long_linkname: Option<Vec<u8>>,
    pub pax_extensions: Option<Vec<u8>>,
    pub mask: u32,
    pub header: Header,
    pub size: u64,
    pub header_pos: u64,
    pub file_pos: u64,
    pub data: Vec<EntryIo<'a>>,
    pub unpack_xattrs: bool,
    pub preserve_permissions: bool,
    pub preserve_ownerships: bool,
    pub preserve_mtime: bool,
    pub overwrite: bool,
}

pub enum EntryIo<'a> {
    Pad(io::Take<io::Repeat>),
    Data(io::Take<&'a ArchiveInner<dyn Read + 'a>>),
}

/// When unpacking items the unpacked thing is returned to allow custom
/// additional handling by users. Today the File is returned, in future
/// the enum may be extended with kinds for links, directories etc.
#[derive(Debug)]
pub enum Unpacked {
    /// A file was unpacked.
    File(std::fs::File),
    /// A directory, hardlink, symlink, or other node was unpacked.
    #[doc(hidden)]
    __Nonexhaustive,
}

impl<'a, R: Read> Entry<'a, R> {
    /// Returns the path name for this entry.
    ///
    /// This method may fail if the pathname is not valid Unicode and this is
    /// called on a Windows platform.
    ///
    /// Note that this function will convert any `\` characters to directory
    /// separators, and it will not always return the same value as
    /// `self.header().path()` as some archive formats have support for longer
    /// path names described in separate entries.
    ///
    /// It is recommended to use this method instead of inspecting the `header`
    /// directly to ensure that various archive formats are handled correctly.
    pub fn path(&self) -> io::Result<Cow<'_, Path>> {
        self.fields.path()
    }

    /// Returns the raw bytes listed for this entry.
    ///
    /// Note that this function will convert any `\` characters to directory
    /// separators, and it will not always return the same value as
    /// `self.header().path_bytes()` as some archive formats have support for
    /// longer path names described in separate entries.
    pub fn path_bytes(&self) -> Cow<'_, [u8]> {
        self.fields.path_bytes()
    }

    /// Returns the link name for this entry, if any is found.
    ///
    /// This method may fail if the pathname is not valid Unicode and this is
    /// called on a Windows platform. `Ok(None)` being returned, however,
    /// indicates that the link name was not present.
    ///
    /// Note that this function will convert any `\` characters to directory
    /// separators, and it will not always return the same value as
    /// `self.header().link_name()` as some archive formats have support for
    /// longer path names described in separate entries.
    ///
    /// It is recommended to use this method instead of inspecting the `header`
    /// directly to ensure that various archive formats are handled correctly.
    pub fn link_name(&self) -> io::Result<Option<Cow<'_, Path>>> {
        self.fields.link_name()
    }

    /// Returns the link name for this entry, in bytes, if listed.
    ///
    /// Note that this will not always return the same value as
    /// `self.header().link_name_bytes()` as some archive formats have support for
    /// longer path names described in separate entries.
    pub fn link_name_bytes(&self) -> Option<Cow<'_, [u8]>> {
        self.fields.link_name_bytes()
    }

    /// Returns an iterator over the pax extensions contained in this entry.
    ///
    /// Pax extensions are a form of archive where extra metadata is stored in
    /// key/value pairs in entries before the entry they're intended to
    /// describe. For example this can be used to describe long file name or
    /// other metadata like atime/ctime/mtime in more precision.
    ///
    /// The returned iterator will yield key/value pairs for each extension.
    ///
    /// `None` will be returned if this entry does not indicate that it itself
    /// contains extensions, or if there were no previous extensions describing
    /// it.
    ///
    /// Note that global pax extensions are intended to be applied to all
    /// archive entries.
    ///
    /// Also note that this function will read the entire entry if the entry
    /// itself is a list of extensions.
    pub fn pax_extensions(&mut self) -> io::Result<Option<PaxExtensions<'_>>> {
        self.fields.pax_extensions()
    }

    /// Returns access to the header of this entry in the archive.
    ///
    /// This provides access to the metadata for this entry in the archive.
    pub fn header(&self) -> &Header {
        &self.fields.header
    }

    /// Returns access to the size of this entry in the archive.
    ///
    /// In the event the size is stored in a pax extension, that size value
    /// will be referenced. Otherwise, the entry size will be stored in the header.
    pub fn size(&self) -> u64 {
        self.fields.size
    }

    /// Returns the starting position, in bytes, of the header of this entry in
    /// the archive.
    ///
    /// The header is always a contiguous section of 512 bytes, so if the
    /// underlying reader implements `Seek`, then the slice from `header_pos` to
    /// `header_pos + 512` contains the raw header bytes.
    pub fn raw_header_position(&self) -> u64 {
        self.fields.header_pos
    }

    /// Returns the starting position, in bytes, of the file of this entry in
    /// the archive.
    ///
    /// If the file of this entry is continuous (e.g. not a sparse file), and
    /// if the underlying reader implements `Seek`, then the slice from
    /// `file_pos` to `file_pos + entry_size` contains the raw file bytes.
    pub fn raw_file_position(&self) -> u64 {
        self.fields.file_pos
    }

    /// Writes this file to the specified location.
    ///
    /// This function will write the entire contents of this file into the
    /// location specified by `dst`. Metadata will also be propagated to the
    /// path `dst`.
    ///
    /// This function will create a file at the path `dst`, and it is required
    /// that the intermediate directories are created. Any existing file at the
    /// location `dst` will be overwritten.
    ///
    /// > **Note**: This function does not have as many sanity checks as
    /// > [`Archive::unpack`] or [`Entry::unpack_in`], and does not prevent
    /// > writes outside `dst`. See the [crate-level security
    /// > documentation][crate#security]. If you're unpacking untrusted
    /// > archives, prefer [`Entry::unpack_in`] instead.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use tar::Archive;
    ///
    /// let mut ar = Archive::new(File::open("foo.tar").unwrap());
    ///
    /// for (i, file) in ar.entries().unwrap().enumerate() {
    ///     let mut file = file.unwrap();
    ///     file.unpack(format!("file-{}", i)).unwrap();
    /// }
    /// ```
    pub fn unpack<P: AsRef<Path>>(&mut self, dst: P) -> io::Result<Unpacked> {
        self.fields.unpack(None, dst.as_ref(), false)
    }

    /// Extracts this file under the specified path, avoiding security issues.
    ///
    /// This function will write the entire contents of this file into the
    /// location obtained by appending the path of this file in the archive to
    /// `dst`, creating any intermediate directories if needed. Metadata will
    /// also be propagated to the path `dst`. Any existing file at the location
    /// `dst` is replaced according to [`Archive::set_overwrite`].
    ///
    /// Regular files are streamed to a unique temporary file in the destination
    /// directory and are published at their final path only after every
    /// declared data block and the expanded logical size have been verified.
    /// A body whose length does not match its header therefore returns an
    /// error without creating or replacing the final member; its temporary
    /// file is removed. Such rejected publications are recorded in
    /// `.tar-security-record` at the canonical extraction root.
    ///
    /// # Security
    ///
    /// See the [crate-level security documentation][crate#security].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::File;
    /// use tar::Archive;
    ///
    /// let mut ar = Archive::new(File::open("foo.tar").unwrap());
    ///
    /// for (i, file) in ar.entries().unwrap().enumerate() {
    ///     let mut file = file.unwrap();
    ///     file.unpack_in("target").unwrap();
    /// }
    /// ```
    pub fn unpack_in<P: AsRef<Path>>(&mut self, dst: P) -> io::Result<bool> {
        self.fields.unpack_in(dst.as_ref())
    }

    /// Set the mask of the permission bits when unpacking this entry.
    ///
    /// The mask will be inverted when applying against a mode, similar to how
    /// `umask` works on Unix. In logical notation it looks like:
    ///
    /// ```text
    /// new_mode = old_mode & (~mask)
    /// ```
    ///
    /// The mask is 0 by default and is currently only implemented on Unix.
    pub fn set_mask(&mut self, mask: u32) {
        self.fields.mask = mask;
    }

    /// Indicate whether extended file attributes (xattrs on Unix) are preserved
    /// when unpacking this entry.
    ///
    /// This flag is disabled by default and is currently only implemented on
    /// Unix using xattr support. This may eventually be implemented for
    /// Windows, however, if other archive implementations are found which do
    /// this as well.
    pub fn set_unpack_xattrs(&mut self, unpack_xattrs: bool) {
        self.fields.unpack_xattrs = unpack_xattrs;
    }

    /// Indicate whether extended permissions (like suid on Unix) are preserved
    /// when unpacking this entry.
    ///
    /// This flag is disabled by default and is currently only implemented on
    /// Unix.
    pub fn set_preserve_permissions(&mut self, preserve: bool) {
        self.fields.preserve_permissions = preserve;
    }

    /// Indicate whether access time information is preserved when unpacking
    /// this entry.
    ///
    /// This flag is enabled by default.
    pub fn set_preserve_mtime(&mut self, preserve: bool) {
        self.fields.preserve_mtime = preserve;
    }
}

impl<'a, R: Read> Read for Entry<'a, R> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        self.fields.read(into)
    }
}

impl<'a> EntryFields<'a> {
    pub fn from<R: Read>(entry: Entry<R>) -> EntryFields {
        entry.fields
    }

    pub fn into_entry<R: Read>(self) -> Entry<'a, R> {
        Entry {
            fields: self,
            _ignored: marker::PhantomData,
        }
    }

    pub fn read_all(&mut self) -> io::Result<Vec<u8>> {
        // Preallocate some data but don't let ourselves get too crazy now.
        let cap = cmp::min(self.size, 128 * 1024);
        let mut v = Vec::with_capacity(cap as usize);
        self.read_to_end(&mut v).map(|_| v)
    }

    fn path(&self) -> io::Result<Cow<'_, Path>> {
        bytes2path(self.path_bytes())
    }

    fn path_bytes(&self) -> Cow<'_, [u8]> {
        match self.long_pathname {
            Some(ref bytes) => {
                if let Some(&0) = bytes.last() {
                    Cow::Borrowed(&bytes[..bytes.len() - 1])
                } else {
                    Cow::Borrowed(bytes)
                }
            }
            None => {
                if let Some(ref pax) = self.pax_extensions {
                    let pax = PaxExtensions::new(pax)
                        .filter_map(|f| f.ok())
                        .find(|f| f.key_bytes() == b"path")
                        .map(|f| f.value_bytes());
                    if let Some(field) = pax {
                        return Cow::Borrowed(field);
                    }
                }
                self.header.path_bytes()
            }
        }
    }

    /// Gets the path in a "lossy" way, used for error reporting ONLY.
    fn path_lossy(&self) -> String {
        String::from_utf8_lossy(&self.path_bytes()).to_string()
    }

    fn link_name(&self) -> io::Result<Option<Cow<'_, Path>>> {
        match self.link_name_bytes() {
            Some(bytes) => bytes2path(bytes).map(Some),
            None => Ok(None),
        }
    }

    fn link_name_bytes(&self) -> Option<Cow<'_, [u8]>> {
        match self.long_linkname {
            Some(ref bytes) => {
                if let Some(&0) = bytes.last() {
                    Some(Cow::Borrowed(&bytes[..bytes.len() - 1]))
                } else {
                    Some(Cow::Borrowed(bytes))
                }
            }
            None => {
                if let Some(ref pax) = self.pax_extensions {
                    let pax = PaxExtensions::new(pax)
                        .filter_map(|f| f.ok())
                        .find(|f| f.key_bytes() == b"linkpath")
                        .map(|f| f.value_bytes());
                    if let Some(field) = pax {
                        return Some(Cow::Borrowed(field));
                    }
                }
                self.header.link_name_bytes()
            }
        }
    }

    fn pax_extensions(&mut self) -> io::Result<Option<PaxExtensions<'_>>> {
        if self.pax_extensions.is_none() {
            if !self.header.entry_type().is_pax_global_extensions()
                && !self.header.entry_type().is_pax_local_extensions()
            {
                return Ok(None);
            }
            self.pax_extensions = Some(self.read_all()?);
        }
        Ok(Some(PaxExtensions::new(
            self.pax_extensions.as_ref().unwrap(),
        )))
    }

    fn unpack_in(&mut self, dst: &Path) -> io::Result<bool> {
        // Notes regarding bsdtar 2.8.3 / libarchive 2.8.3:
        // * Leading '/'s are trimmed. For example, `///test` is treated as
        //   `test`.
        // * If the filename contains '..', then the file is skipped when
        //   extracting the tarball.
        // * '//' within a filename is effectively skipped. An error is
        //   logged, but otherwise the effect is as if any two or more
        //   adjacent '/'s within the filename were consolidated into one
        //   '/'.
        //
        // Most of this is handled by the `path` module of the standard
        // library, but we specially handle a few cases here as well.

        let mut file_dst = dst.to_path_buf();
        {
            let path = self.path().map_err(|e| {
                TarError::new(
                    format!("invalid path in entry header: {}", self.path_lossy()),
                    e,
                )
            })?;
            for part in path.components() {
                match part {
                    // Leading '/' characters, root paths, and '.'
                    // components are just ignored and treated as "empty
                    // components"
                    Component::Prefix(..) | Component::RootDir | Component::CurDir => continue,

                    // If any part of the filename is '..', then skip over
                    // unpacking the file to prevent directory traversal
                    // security issues.  See, e.g.: CVE-2001-1267,
                    // CVE-2002-0399, CVE-2005-1918, CVE-2007-4131
                    Component::ParentDir => return Ok(false),

                    Component::Normal(part) => file_dst.push(part),
                }
            }
        }

        // Skip cases where only slashes or '.' parts were seen, because
        // this is effectively an empty filename.
        if *dst == *file_dst {
            return Ok(true);
        }

        // Skip entries without a parent (i.e. outside of FS root)
        let parent = match file_dst.parent() {
            Some(p) => p,
            None => return Ok(false),
        };

        self.ensure_dir_created(dst, parent)
            .map_err(|e| TarError::new(format!("failed to create `{}`", parent.display()), e))?;

        let canon_target = self.validate_inside_dst(dst, parent)?;

        self.unpack(Some(&canon_target), &file_dst, true)
            .map_err(|e| TarError::new(format!("failed to unpack `{}`", file_dst.display()), e))?;

        Ok(true)
    }

    /// Unpack as destination directory `dst`.
    fn unpack_dir(&mut self, dst: &Path) -> io::Result<()> {
        // If the directory already exists just let it slide
        fs::create_dir(dst).or_else(|err| {
            if err.kind() == ErrorKind::AlreadyExists {
                let prev = fs::symlink_metadata(dst);
                if prev.map(|m| m.is_dir()).unwrap_or(false) {
                    return Ok(());
                }
            }
            Err(Error::new(
                err.kind(),
                format!("{} when creating dir {}", err, dst.display()),
            ))
        })
    }

    /// Returns access to the header of this entry in the archive.
    fn unpack(
        &mut self,
        target_base: Option<&Path>,
        dst: &Path,
        atomic_publish: bool,
    ) -> io::Result<Unpacked> {
        fn set_perms_ownerships(
            dst: &Path,
            f: Option<&mut std::fs::File>,
            header: &Header,
            mask: u32,
            perms: bool,
            ownerships: bool,
        ) -> io::Result<()> {
            // ownerships need to be set first to avoid stripping SUID bits in the permissions ...
            if ownerships {
                set_ownerships(dst, &f, header.uid()?, header.gid()?)?;
            }
            // ... then set permissions, SUID bits set here is kept
            if let Ok(mode) = header.mode() {
                set_perms(dst, f, mode, mask, perms)?;
            }

            Ok(())
        }

        fn get_mtime(header: &Header) -> Option<FileTime> {
            header.mtime().ok().map(|mtime| {
                // For some more information on this see the comments in
                // `Header::fill_platform_from`, but the general idea is that
                // we're trying to avoid 0-mtime files coming out of archives
                // since some tools don't ingest them well. Perhaps one day
                // when Cargo stops working with 0-mtime archives we can remove
                // this.
                let mtime = if mtime == 0 { 1 } else { mtime };
                FileTime::from_unix_time(mtime as i64, 0)
            })
        }

        let kind = self.header.entry_type();

        if kind.is_dir() {
            self.unpack_dir(dst)?;
            set_perms_ownerships(
                dst,
                None,
                &self.header,
                self.mask,
                self.preserve_permissions,
                self.preserve_ownerships,
            )?;
            return Ok(Unpacked::__Nonexhaustive);
        } else if kind.is_hard_link() || kind.is_symlink() {
            let src = match self.link_name()? {
                Some(name) => name,
                None => {
                    return Err(other(&format!(
                        "hard link listed for {} but no link name found",
                        String::from_utf8_lossy(self.header.as_bytes())
                    )));
                }
            };

            if src.iter().count() == 0 {
                return Err(other(&format!(
                    "symlink destination for {} is empty",
                    String::from_utf8_lossy(self.header.as_bytes())
                )));
            }

            if kind.is_hard_link() {
                let link_src = match target_base {
                    // If we're unpacking within a directory then ensure that
                    // the destination of this hard link is both present and
                    // inside our own directory. This is needed because we want
                    // to make sure to not overwrite anything outside the root.
                    //
                    // Note that this logic is only needed for hard links
                    // currently. With symlinks the `validate_inside_dst` which
                    // happens before this method as part of `unpack_in` will
                    // use canonicalization to ensure this guarantee. For hard
                    // links though they're canonicalized to their existing path
                    // so we need to validate at this time.
                    Some(p) => {
                        let link_src = p.join(src);
                        self.validate_inside_dst(p, &link_src)?;
                        link_src
                    }
                    None => src.into_owned(),
                };
                fs::hard_link(&link_src, dst).map_err(|err| {
                    Error::new(
                        err.kind(),
                        format!(
                            "{} when hard linking {} to {}",
                            err,
                            link_src.display(),
                            dst.display()
                        ),
                    )
                })?;
            } else {
                symlink(&src, dst)
                    .or_else(|err_io| {
                        if err_io.kind() == io::ErrorKind::AlreadyExists && self.overwrite {
                            // remove dest and try once more
                            std::fs::remove_file(dst).and_then(|()| symlink(&src, dst))
                        } else {
                            Err(err_io)
                        }
                    })
                    .map_err(|err| {
                        Error::new(
                            err.kind(),
                            format!(
                                "{} when symlinking {} to {}",
                                err,
                                src.display(),
                                dst.display()
                            ),
                        )
                    })?;
                // While permissions on symlinks are meaningless on most systems, the ownership
                // of symlinks is important as it dictates the access control to the symlink
                // itself.
                if self.preserve_ownerships {
                    set_ownerships(dst, &None, self.header.uid()?, self.header.gid()?)?;
                }
                if self.preserve_mtime {
                    if let Some(mtime) = get_mtime(&self.header) {
                        // filetime deprecates its API on Rust 1.99+ in favour of std, whose
                        // replacements need a newer Rust than our MSRV; see #458.
                        #[allow(deprecated)]
                        filetime::set_symlink_file_times(dst, mtime, mtime).map_err(|e| {
                            TarError::new(format!("failed to set mtime for `{}`", dst.display()), e)
                        })?;
                    }
                }
            }
            return Ok(Unpacked::__Nonexhaustive);

            #[cfg(target_arch = "wasm32")]
            #[allow(unused_variables)]
            fn symlink(src: &Path, dst: &Path) -> io::Result<()> {
                Err(io::Error::new(io::ErrorKind::Other, "Not implemented"))
            }

            #[cfg(windows)]
            fn symlink(src: &Path, dst: &Path) -> io::Result<()> {
                ::std::os::windows::fs::symlink_file(src, dst)
            }

            #[cfg(all(unix, not(target_arch = "wasm32")))]
            fn symlink(src: &Path, dst: &Path) -> io::Result<()> {
                ::std::os::unix::fs::symlink(src, dst)
            }
        } else if kind.is_pax_global_extensions()
            || kind.is_pax_local_extensions()
            || kind.is_gnu_longname()
            || kind.is_gnu_longlink()
        {
            return Ok(Unpacked::__Nonexhaustive);
        };

        // Old BSD-tar compatibility.
        // Names that have a trailing slash should be treated as a directory.
        // Only applies to old headers.
        if self.header.as_ustar().is_none() && self.path_bytes().ends_with(b"/") {
            self.unpack_dir(dst)?;
            set_perms_ownerships(
                dst,
                None,
                &self.header,
                self.mask,
                self.preserve_permissions,
                self.preserve_ownerships,
            )?;
            return Ok(Unpacked::__Nonexhaustive);
        }

        // Note the lack of `else` clause above. According to the FreeBSD
        // documentation:
        //
        // > A POSIX-compliant implementation must treat any unrecognized
        // > typeflag value as a regular file.
        //
        // As a result if we don't recognize the kind we just write out the file
        // as we would normally.

        // Ensure we write a new file rather than overwriting in-place which
        // is attackable; if an existing file is found unlink it.
        fn open(dst: &Path) -> io::Result<std::fs::File> {
            OpenOptions::new().write(true).create_new(true).open(dst)
        }

        let header_name = String::from_utf8_lossy(&self.header.path_bytes()).into_owned();
        let destination_name = dst.display().to_string();
        let wrap_error = move |e: io::Error| -> TarError {
            TarError::new(
                format!("failed to unpack `{header_name}` into `{destination_name}`"),
                e,
            )
        };

        // For security-checked unpacking, stream into a unique sibling
        // staging file. The final destination is not created or replaced
        // until every declared block has been copied and verified.
        let parent = dst.parent().unwrap_or_else(|| Path::new("."));
        let staging_allocation = if atomic_publish {
            Some(create_staging_file(parent, dst))
        } else {
            None
        };
        let (staging_path, staged_file) = match staging_allocation {
            None => (None, None),
            Some(Ok((path, file))) => (Some(path), Some(file)),
            Some(Err(error)) => {
                record_atomic_rejection(target_base, self, None, &error);
                return Err(wrap_error(error).into());
            }
        };
        let _staging_cleanup = staging_path
            .as_ref()
            .map(|path| StagingCleanup(path.clone()));
        let write_path = staging_path.as_deref().unwrap_or(dst);
        let mut staged_bytes: Option<u64> = None;

        let write_result = (|| -> io::Result<std::fs::File> {
            let mut f = match staged_file {
                Some(f) => f,
                None => open(dst).or_else(|err| {
                    if err.kind() != ErrorKind::AlreadyExists {
                        Err(err)
                    } else if self.overwrite {
                        match fs::remove_file(dst) {
                            Ok(()) => open(dst),
                            Err(ref e) if e.kind() == io::ErrorKind::NotFound => open(dst),
                            Err(e) => Err(e),
                        }
                    } else {
                        Err(err)
                    }
                })?,
            };
            for io in self.data.drain(..) {
                match io {
                    EntryIo::Data(mut d) => {
                        let expected = d.limit();
                        let copied = match io::copy(&mut d, &mut f) {
                            Ok(copied) => copied,
                            Err(error) => {
                                staged_bytes = f.metadata().ok().map(|m| m.len());
                                return Err(error);
                            }
                        };
                        if copied != expected {
                            // Keep the historical error message and kind; the
                            // atomic rollback is handled by the staging guard.
                            staged_bytes = f.metadata().ok().map(|m| m.len());
                            return Err(other("failed to write entire file"));
                        }
                    }
                    EntryIo::Pad(d) => {
                        // TODO: checked cast to i64
                        let to = SeekFrom::Current(d.limit() as i64);
                        let size = f.seek(to)?;
                        f.set_len(size)?;
                    }
                }
            }

            if atomic_publish {
                // The per-fragment limit checks archive data blocks; this
                // inode-size check also covers sparse holes and confirms that
                // the complete logical member was materialized before publish.
                let actual_size = match f.metadata() {
                    Ok(metadata) => metadata.len(),
                    Err(error) => {
                        staged_bytes = None;
                        return Err(error);
                    }
                };
                if actual_size != self.size {
                    staged_bytes = Some(actual_size);
                    return Err(other("failed to write entire file"));
                }
                staged_bytes = Some(actual_size);
            }
            Ok(f)
        })();
        let mut f = match write_result {
            Ok(f) => f,
            Err(error) => {
                record_atomic_rejection(target_base, self, staged_bytes, &error);
                return Err(wrap_error(error).into());
            }
        };

        let metadata_result: io::Result<()> = (|| {
            if self.preserve_mtime {
                if let Some(mtime) = get_mtime(&self.header) {
                    // filetime deprecates its API on Rust 1.99+ in favour of std, whose
                    // replacements need a newer Rust than our MSRV; see #458.
                    #[allow(deprecated)]
                    filetime::set_file_handle_times(&f, Some(mtime), Some(mtime)).map_err(|e| {
                        TarError::new(format!("failed to set mtime for `{}`", dst.display()), e)
                    })?;
                }
            }
            set_perms_ownerships(
                dst,
                Some(&mut f),
                &self.header,
                self.mask,
                self.preserve_permissions,
                self.preserve_ownerships,
            )?;
            if self.unpack_xattrs {
                set_xattrs(self, write_path)?;
            }
            Ok(())
        })();
        if let Err(error) = metadata_result {
            record_atomic_rejection(target_base, self, staged_bytes.or(Some(self.size)), &error);
            return Err(error);
        }

        if atomic_publish {
            let staging_path = staging_path
                .as_deref()
                .expect("atomic publication has a staging path");
            if let Err(error) = publish_staged_file(staging_path, dst, self.overwrite) {
                record_atomic_rejection(target_base, self, Some(self.size), &error);
                return Err(wrap_error(error).into());
            }
        }
        return Ok(Unpacked::File(f));

        fn set_ownerships(
            dst: &Path,
            f: &Option<&mut std::fs::File>,
            uid: u64,
            gid: u64,
        ) -> Result<(), TarError> {
            _set_ownerships(dst, f, uid, gid).map_err(|e| {
                TarError::new(
                    format!(
                        "failed to set ownerships to uid={:?}, gid={:?} \
                         for `{}`",
                        uid,
                        gid,
                        dst.display()
                    ),
                    e,
                )
            })
        }

        #[cfg(all(unix, not(target_arch = "wasm32")))]
        fn _set_ownerships(
            dst: &Path,
            f: &Option<&mut std::fs::File>,
            uid: u64,
            gid: u64,
        ) -> io::Result<()> {
            use std::os::unix::prelude::*;

            let uid: libc::uid_t = uid.try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, format!("UID {} is too large!", uid))
            })?;
            let gid: libc::gid_t = gid.try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, format!("GID {} is too large!", gid))
            })?;
            match f {
                Some(f) => unsafe {
                    let fd = f.as_raw_fd();
                    if libc::fchown(fd, uid, gid) != 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                },
                None => unsafe {
                    let path = std::ffi::CString::new(dst.as_os_str().as_bytes()).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("path contains null character: {:?}", e),
                        )
                    })?;
                    if libc::lchown(path.as_ptr(), uid, gid) != 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                },
            }
        }

        // Windows does not support posix numeric ownership IDs
        #[cfg(any(windows, target_arch = "wasm32"))]
        fn _set_ownerships(
            _: &Path,
            _: &Option<&mut std::fs::File>,
            _: u64,
            _: u64,
        ) -> io::Result<()> {
            Ok(())
        }

        fn set_perms(
            dst: &Path,
            f: Option<&mut std::fs::File>,
            mode: u32,
            mask: u32,
            preserve: bool,
        ) -> Result<(), TarError> {
            _set_perms(dst, f, mode, mask, preserve).map_err(|e| {
                TarError::new(
                    format!(
                        "failed to set permissions to {:o} \
                         for `{}`",
                        mode,
                        dst.display()
                    ),
                    e,
                )
            })
        }

        #[cfg(all(unix, not(target_arch = "wasm32")))]
        fn _set_perms(
            dst: &Path,
            f: Option<&mut std::fs::File>,
            mode: u32,
            mask: u32,
            preserve: bool,
        ) -> io::Result<()> {
            use std::os::unix::prelude::*;

            let mode = if preserve { mode } else { mode & 0o777 };
            let mode = mode & !mask;
            let perm = fs::Permissions::from_mode(mode as _);
            match f {
                Some(f) => f.set_permissions(perm),
                None => fs::set_permissions(dst, perm),
            }
        }

        #[cfg(windows)]
        fn _set_perms(
            dst: &Path,
            f: Option<&mut std::fs::File>,
            mode: u32,
            _mask: u32,
            _preserve: bool,
        ) -> io::Result<()> {
            if mode & 0o200 == 0o200 {
                return Ok(());
            }
            match f {
                Some(f) => {
                    let mut perm = f.metadata()?.permissions();
                    perm.set_readonly(true);
                    f.set_permissions(perm)
                }
                None => {
                    let mut perm = fs::metadata(dst)?.permissions();
                    perm.set_readonly(true);
                    fs::set_permissions(dst, perm)
                }
            }
        }

        #[cfg(target_arch = "wasm32")]
        #[allow(unused_variables)]
        fn _set_perms(
            dst: &Path,
            f: Option<&mut std::fs::File>,
            mode: u32,
            mask: u32,
            _preserve: bool,
        ) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::Other, "Not implemented"))
        }

        #[cfg(all(unix, not(target_arch = "wasm32"), feature = "xattr"))]
        fn set_xattrs(me: &mut EntryFields, dst: &Path) -> io::Result<()> {
            use std::ffi::OsStr;
            use std::os::unix::prelude::*;

            let exts = match me.pax_extensions() {
                Ok(Some(e)) => e,
                _ => return Ok(()),
            };
            let exts = exts
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let key = e.key_bytes();
                    let prefix = crate::pax::PAX_SCHILYXATTR.as_bytes();
                    key.strip_prefix(prefix).map(|rest| (rest, e))
                })
                .map(|(key, e)| (OsStr::from_bytes(key), e.value_bytes()));

            for (key, value) in exts {
                xattr::set(dst, key, value).map_err(|e| {
                    TarError::new(
                        format!(
                            "failed to set extended \
                             attributes to {}. \
                             Xattrs: key={:?}, value={:?}.",
                            dst.display(),
                            key,
                            String::from_utf8_lossy(value)
                        ),
                        e,
                    )
                })?;
            }

            Ok(())
        }
        // Windows does not completely support posix xattrs
        // https://en.wikipedia.org/wiki/Extended_file_attributes#Windows_NT
        #[cfg(any(windows, not(feature = "xattr"), target_arch = "wasm32"))]
        fn set_xattrs(_: &mut EntryFields, _: &Path) -> io::Result<()> {
            Ok(())
        }
    }

    fn ensure_dir_created(&self, dst: &Path, dir: &Path) -> io::Result<()> {
        let mut ancestor = dir;
        let mut dirs_to_create = Vec::new();
        while ancestor.symlink_metadata().is_err() {
            dirs_to_create.push(ancestor);
            if let Some(parent) = ancestor.parent() {
                ancestor = parent;
            } else {
                break;
            }
        }
        for ancestor in dirs_to_create.into_iter().rev() {
            if let Some(parent) = ancestor.parent() {
                self.validate_inside_dst(dst, parent)?;
            }
            fs::create_dir_all(ancestor)?;
        }
        Ok(())
    }

    fn validate_inside_dst(&self, dst: &Path, file_dst: &Path) -> io::Result<PathBuf> {
        // Abort if target (canonical) parent is outside of `dst`
        let canon_parent = file_dst.canonicalize().map_err(|err| {
            Error::new(
                err.kind(),
                format!("{} while canonicalizing {}", err, file_dst.display()),
            )
        })?;
        let canon_target = dst.canonicalize().map_err(|err| {
            Error::new(
                err.kind(),
                format!("{} while canonicalizing {}", err, dst.display()),
            )
        })?;
        if !canon_parent.starts_with(&canon_target) {
            let err = TarError::new(
                format!(
                    "trying to unpack outside of destination path: {}",
                    canon_target.display()
                ),
                // TODO: use ErrorKind::InvalidInput here? (minor breaking change)
                Error::new(ErrorKind::Other, "Invalid argument"),
            );
            return Err(err.into());
        }
        Ok(canon_target)
    }
}

/// Process-wide counter used to allocate unique staging file names.
static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Removes a staging file when an unpack attempt leaves this scope.
///
/// After a successful rename the path no longer exists. After a successful
/// no-overwrite hard-link publication, dropping this guard removes the extra
/// staging name while the published hard link keeps the inode alive.
struct StagingCleanup(PathBuf);

impl Drop for StagingCleanup {
    fn drop(&mut self) {
        // Cleanup is best-effort: the extraction result has already been
        // determined and a failed unlink must not replace that outcome.
        #[cfg(windows)]
        {
            // Windows refuses to delete a read-only staging file. Clear only
            // the read-only attribute before the best-effort unlink.
            if let Ok(metadata) = fs::symlink_metadata(&self.0) {
                let mut permissions = metadata.permissions();
                if permissions.readonly() {
                    permissions.set_readonly(false);
                    let _ = fs::set_permissions(&self.0, permissions);
                }
            }
        }
        let _ = fs::remove_file(&self.0);
    }
}

/// Best-effort append an audit event for a failed atomic publication.
///
/// Audit persistence must never replace or alter the original extraction
/// error. Direct, rootless [`Entry::unpack`] calls have no extraction-root
/// audit location (`root == None`) and are therefore not recorded here.
fn record_atomic_rejection(
    root: Option<&Path>,
    fields: &EntryFields<'_>,
    staged_bytes: Option<u64>,
    error: &io::Error,
) {
    let root = match root {
        Some(root) => root,
        None => return,
    };
    let entry_path = fields.path_lossy();
    let _ = crate::security_record::record_rejected_publication(
        root,
        &crate::security_record::RejectedPublication {
            header_offset: fields.header_pos,
            entry_path: &entry_path,
            declared_size: fields.size,
            staged_bytes,
            error,
        },
    );
}

/// Create a unique `O_CREAT | O_EXCL` staging file in `parent`.
///
/// The name is not derived from the archive member name so very long final
/// path components do not become longer than the filesystem's name limit.
/// Exclusive creation means an archive-planted symlink or file can never cause
/// this helper to truncate an existing path.
fn create_staging_file(parent: &Path, destination: &Path) -> io::Result<(PathBuf, fs::File)> {
    const ALLOCATION_ATTEMPTS: u32 = 4096;

    let pid = std::process::id();
    for _ in 0..ALLOCATION_ATTEMPTS {
        let sequence = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(".tar-rs-staging-{pid}-{sequence}"));

        // An archive member could have exactly the same name as the first
        // generated staging path. Never stage a file at its own destination.
        if path == destination {
            continue;
        }

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Keep partially streamed member data private until the requested
            // header mode is applied immediately before publication.
            options.mode(0o600);
        }

        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }

    Err(Error::new(
        ErrorKind::AlreadyExists,
        "failed to allocate a unique tar extraction staging file",
    ))
}

/// Atomically publish a fully verified staging file.
///
/// Overwriting extraction uses `rename`, which atomically replaces the final
/// path on Unix and maps to replace-existing move semantics on Windows.
/// Non-overwriting extraction uses a hard link: link creation fails with
/// [`ErrorKind::AlreadyExists`] if the destination appeared first, preserving
/// the historical `create_new` error kind without creating a partial final
/// file. The caller's cleanup guard then unlinks the staging name.
fn publish_staged_file(staging: &Path, destination: &Path, overwrite: bool) -> io::Result<()> {
    if overwrite {
        fs::rename(staging, destination)
    } else {
        fs::hard_link(staging, destination)
    }
}

impl<'a> Read for EntryFields<'a> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.data.get_mut(0).map(|io| io.read(into)) {
                Some(Ok(0)) => {
                    self.data.remove(0);
                }
                Some(r) => return r,
                None => return Ok(0),
            }
        }
    }
}

impl<'a> Read for EntryIo<'a> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        match *self {
            EntryIo::Pad(ref mut io) => io.read(into),
            EntryIo::Data(ref mut io) => io.read(into),
        }
    }
}
