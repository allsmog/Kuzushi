use super::{ensure_capacity, EntryIdentity, EntryRecord};
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::fs::File;

pub(super) fn entries(directory: &File, max_entries: usize) -> Result<Vec<EntryRecord>> {
    let mut stream = UnixDirectoryStream::open(directory)?;
    let mut entries = Vec::new();
    while let Some(name) = stream.next_entry()? {
        if name != "." && name != ".." {
            ensure_capacity(entries.len(), max_entries)?;
            entries.push(EntryRecord {
                identity: entry_identity(directory, &name)?,
                name,
            });
        }
    }
    Ok(entries)
}

struct UnixDirectoryStream(*mut libc::DIR);

impl UnixDirectoryStream {
    fn open(directory: &File) -> Result<Self> {
        use std::os::fd::{AsRawFd, FromRawFd};

        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        // SAFETY: the retained descriptor is live, `.` is NUL-terminated, and
        // the returned descriptor is transferred immediately into `File`.
        let descriptor = unsafe { libc::openat(directory.as_raw_fd(), c".".as_ptr(), flags) };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error())
                .context("could not reopen retained MCP directory handle");
        }
        // SAFETY: `openat` returned a fresh owned descriptor.
        let reopened = unsafe { File::from_raw_fd(descriptor) };
        Self::from_file(reopened)
    }

    fn from_file(directory: File) -> Result<Self> {
        use std::os::fd::IntoRawFd;

        let descriptor = directory.into_raw_fd();
        // SAFETY: `descriptor` is an owned directory descriptor. On success,
        // `fdopendir` assumes ownership; on failure, we close it below.
        let stream = unsafe { libc::fdopendir(descriptor) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            // SAFETY: `fdopendir` did not assume ownership on failure.
            unsafe { libc::close(descriptor) };
            return Err(error).context("could not enumerate retained MCP directory handle");
        }
        Ok(Self(stream))
    }

    fn next_entry(&mut self) -> Result<Option<OsString>> {
        use std::ffi::CStr;
        use std::os::unix::ffi::OsStringExt;

        clear_errno()?;
        // SAFETY: the stream is live and exclusively borrowed for this call.
        let entry = unsafe { libc::readdir(self.0) };
        if entry.is_null() {
            return end_of_directory();
        }
        // SAFETY: POSIX guarantees a NUL-terminated `d_name` for the returned
        // entry, valid until the next operation on this stream.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        Ok(Some(OsString::from_vec(name.to_bytes().to_vec())))
    }
}

impl Drop for UnixDirectoryStream {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns the stream returned by fdopendir.
        unsafe { libc::closedir(self.0) };
    }
}

fn end_of_directory() -> Result<Option<OsString>> {
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(0) {
        return Ok(None);
    }
    Err(error).context("could not enumerate retained MCP directory handle")
}

fn entry_identity(directory: &File, name: &std::ffi::OsStr) -> Result<EntryIdentity> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    let name = CString::new(name.as_bytes()).context("MCP directory entry contains a NUL byte")?;
    let mut stat = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: the retained directory descriptor is live, `name` is
    // NUL-terminated, and `stat` is writable for the exact result type.
    let status = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error())
            .context("could not inspect retained MCP directory entry");
    }
    // SAFETY: successful fstatat initialized the complete stat structure.
    let stat = unsafe { stat.assume_init() };
    anyhow::ensure!(
        stat.st_ino != 0,
        "MCP directory entry has no stable file identity"
    );
    Ok(EntryIdentity::Unix {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
        file_type: (stat.st_mode & libc::S_IFMT) as u32,
    })
}

#[cfg(any(
    target_os = "linux",
    target_os = "dragonfly",
    target_os = "emscripten",
    target_os = "hurd",
    target_os = "l4re",
    target_os = "redox"
))]
fn clear_errno() -> Result<()> {
    // SAFETY: errno is thread-local and this call immediately precedes readdir.
    unsafe { *libc::__errno_location() = 0 };
    Ok(())
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos"
))]
fn clear_errno() -> Result<()> {
    // SAFETY: errno is thread-local and this call immediately precedes readdir.
    unsafe { *libc::__error() = 0 };
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "netbsd", target_os = "openbsd"))]
fn clear_errno() -> Result<()> {
    // SAFETY: errno is thread-local and this call immediately precedes readdir.
    unsafe { *libc::__errno() = 0 };
    Ok(())
}

#[cfg(any(target_os = "illumos", target_os = "solaris"))]
fn clear_errno() -> Result<()> {
    // SAFETY: errno is thread-local and this call immediately precedes readdir.
    unsafe { *libc::___errno() = 0 };
    Ok(())
}

#[cfg(target_os = "haiku")]
fn clear_errno() -> Result<()> {
    // SAFETY: errno is thread-local and this call immediately precedes readdir.
    unsafe { *libc::_errnop() = 0 };
    Ok(())
}

#[cfg(target_os = "aix")]
fn clear_errno() -> Result<()> {
    // SAFETY: errno is thread-local and this call immediately precedes readdir.
    unsafe { *libc::_Errno() = 0 };
    Ok(())
}

#[cfg(target_os = "nto")]
fn clear_errno() -> Result<()> {
    // SAFETY: errno is thread-local and this call immediately precedes readdir.
    unsafe { *libc::__get_errno_ptr() = 0 };
    Ok(())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "aix",
    target_os = "dragonfly",
    target_os = "emscripten",
    target_os = "freebsd",
    target_os = "haiku",
    target_os = "hurd",
    target_os = "illumos",
    target_os = "ios",
    target_os = "l4re",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "nto",
    target_os = "openbsd",
    target_os = "redox",
    target_os = "solaris",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos"
)))]
fn clear_errno() -> Result<()> {
    anyhow::bail!("retained MCP directory enumeration is unsupported on this Unix platform")
}

pub(super) fn open_child(directory: &File, record: &EntryRecord) -> Result<File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let EntryIdentity::Unix { file_type, .. } = &record.identity;
    anyhow::ensure!(
        *file_type != libc::S_IFLNK as u32,
        "MCP directory entry is a symbolic link"
    );
    anyhow::ensure!(
        matches!(
            *file_type,
            value if value == libc::S_IFREG as u32 || value == libc::S_IFDIR as u32
        ),
        "MCP directory entry is not a regular file or directory"
    );
    let name =
        CString::new(record.name.as_bytes()).context("MCP directory entry contains a NUL byte")?;
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    // SAFETY: the retained parent descriptor is live, the name is
    // NUL-terminated, and the fresh descriptor is transferred into `File`.
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error())
            .context("could not open retained MCP directory entry");
    }
    // SAFETY: `openat` returned a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

pub(super) fn opened_entry_matches(identity: &EntryIdentity, file: &File) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let EntryIdentity::Unix {
        device,
        inode,
        file_type,
    } = identity;
    let metadata = file.metadata()?;
    Ok(metadata.dev() == *device
        && metadata.ino() == *inode
        && metadata.mode() & libc::S_IFMT as u32 == *file_type)
}
