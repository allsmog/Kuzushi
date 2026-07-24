use super::{
    absolute_path, entry_limit_error, invalid_root, non_regular_entry, SecureDirectory, SecureEntry,
};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

pub(super) fn open_root_directory(path: &Path) -> io::Result<SecureDirectory> {
    let absolute = canonical_parent_with_leaf(path)?;
    let mut directory = open_directory_path(Path::new("/"))?;
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => directory = open_directory_at(&directory, name)?,
            _ => return Err(invalid_root(&absolute)),
        }
    }
    Ok(SecureDirectory {
        handle: directory,
        path: absolute,
    })
}

fn canonical_parent_with_leaf(path: &Path) -> io::Result<PathBuf> {
    let requested = absolute_path(path)?;
    let parent = requested.parent().ok_or_else(|| invalid_root(&requested))?;
    let leaf = requested
        .file_name()
        .ok_or_else(|| invalid_root(&requested))?;
    Ok(fs::canonicalize(parent)?.join(leaf))
}

pub(super) fn directory_entry_names(
    directory: &SecureDirectory,
    limit: usize,
) -> io::Result<Vec<OsString>> {
    use std::os::fd::AsRawFd;

    let duplicate = unsafe { libc::fcntl(directory.handle.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        unsafe { libc::close(duplicate) };
        return Err(io::Error::last_os_error());
    }
    read_directory_stream(stream, limit)
}

fn read_directory_stream(stream: *mut libc::DIR, limit: usize) -> io::Result<Vec<OsString>> {
    let stream = OwnedDirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        let Some(name) = next_entry_name(stream.as_ptr())? else {
            return Ok(names);
        };
        append_entry_name(&mut names, name, limit)?;
    }
}

struct OwnedDirectoryStream(*mut libc::DIR);

impl OwnedDirectoryStream {
    fn as_ptr(&self) -> *mut libc::DIR {
        self.0
    }
}

impl Drop for OwnedDirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

fn next_entry_name(stream: *mut libc::DIR) -> io::Result<Option<OsString>> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStringExt;

    clear_errno();
    let entry = unsafe { libc::readdir(stream) };
    if entry.is_null() {
        return end_of_directory();
    }
    let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
    Ok(Some(OsString::from_vec(bytes.to_vec())))
}

fn end_of_directory() -> io::Result<Option<OsString>> {
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(0) {
        return Ok(None);
    }
    Err(error)
}

fn append_entry_name(names: &mut Vec<OsString>, name: OsString, limit: usize) -> io::Result<()> {
    if is_dot_entry(&name) {
        return Ok(());
    }
    if names.len() >= limit {
        return Err(entry_limit_error());
    }
    names.push(name);
    Ok(())
}

fn is_dot_entry(name: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;
    matches!(name.as_bytes(), b"." | b"..")
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn clear_errno() {
    unsafe { *libc::__error() = 0 };
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn clear_errno() {}

pub(super) fn open_child_entry(
    directory: &SecureDirectory,
    name: &OsStr,
) -> io::Result<SecureEntry> {
    let file = open_at(
        &directory.handle,
        name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )?;
    let metadata = file.metadata()?;
    if metadata.is_dir() {
        return Ok(SecureEntry::Directory(SecureDirectory {
            handle: file,
            path: directory.path.join(name),
        }));
    }
    if metadata.is_file() {
        return Ok(SecureEntry::File(file, metadata));
    }
    Err(non_regular_entry(&directory.path.join(name)))
}

fn open_directory_path(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(map_no_follow_error)
}

fn open_directory_at(directory: &fs::File, name: &OsStr) -> io::Result<fs::File> {
    open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
    )
}

fn open_at(directory: &fs::File, name: &OsStr, flags: i32) -> io::Result<fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(map_no_follow_error(io::Error::last_os_error()));
    }
    Ok(unsafe { fs::File::from_raw_fd(descriptor) })
}

fn map_no_follow_error(error: io::Error) -> io::Error {
    if error
        .raw_os_error()
        .is_some_and(|code| code == libc::ELOOP || code == libc::ENOTDIR)
    {
        return io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to follow a symlinked database path component",
        );
    }
    error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_entries_do_not_consume_the_limit() {
        let mut names = Vec::new();

        append_entry_name(&mut names, OsString::from("."), 0).unwrap();
        append_entry_name(&mut names, OsString::from(".."), 0).unwrap();

        assert!(names.is_empty());
    }

    #[test]
    fn observed_entry_beyond_the_limit_fails_closed() {
        let mut names = Vec::new();

        let error = append_entry_name(&mut names, OsString::from("entry"), 0).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
