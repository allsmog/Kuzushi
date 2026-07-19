use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

pub(super) struct SecureDirectory {
    handle: fs::File,
    path: PathBuf,
    #[cfg(windows)]
    final_path: PathBuf,
    #[cfg(windows)]
    _retained_ancestors: Vec<fs::File>,
}

pub(super) enum SecureEntry {
    Directory(SecureDirectory),
    File(fs::File, fs::Metadata),
}

impl SecureDirectory {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        open_root_directory(path)
    }

    pub(super) fn entry_names(&self, limit: usize) -> io::Result<Vec<OsString>> {
        let mut names = directory_entry_names(self, limit)?;
        names.sort();
        Ok(names)
    }

    pub(super) fn open_entry(&self, name: &OsStr) -> io::Result<SecureEntry> {
        validate_entry_name(name)?;
        open_child_entry(self, name)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

fn validate_entry_name(name: &OsStr) -> io::Result<()> {
    let mut components = Path::new(name).components();
    let valid =
        matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none();
    if valid {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "database entry is not a single path component",
    ))
}

fn absolute_path(path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(path))
}

#[cfg(unix)]
fn open_root_directory(path: &Path) -> io::Result<SecureDirectory> {
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

#[cfg(unix)]
fn canonical_parent_with_leaf(path: &Path) -> io::Result<PathBuf> {
    let requested = absolute_path(path)?;
    let parent = requested.parent().ok_or_else(|| invalid_root(&requested))?;
    let leaf = requested
        .file_name()
        .ok_or_else(|| invalid_root(&requested))?;
    Ok(fs::canonicalize(parent)?.join(leaf))
}

#[cfg(unix)]
fn directory_entry_names(directory: &SecureDirectory, limit: usize) -> io::Result<Vec<OsString>> {
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

#[cfg(unix)]
fn read_directory_stream(stream: *mut libc::DIR, limit: usize) -> io::Result<Vec<OsString>> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStringExt;

    let mut names = Vec::new();
    loop {
        clear_errno();
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            unsafe { libc::closedir(stream) };
            return if error.raw_os_error() == Some(0) {
                Ok(names)
            } else {
                Err(error)
            };
        }
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes != b"." && bytes != b".." {
            if names.len() >= limit {
                unsafe { libc::closedir(stream) };
                return Err(entry_limit_error());
            }
            names.push(OsString::from_vec(bytes.to_vec()));
        }
    }
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

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))
))]
fn clear_errno() {}

#[cfg(unix)]
fn open_child_entry(directory: &SecureDirectory, name: &OsStr) -> io::Result<SecureEntry> {
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

#[cfg(unix)]
fn open_directory_path(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(map_no_follow_error)
}

#[cfg(unix)]
fn open_directory_at(directory: &fs::File, name: &OsStr) -> io::Result<fs::File> {
    open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
    )
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(windows)]
fn open_root_directory(path: &Path) -> io::Result<SecureDirectory> {
    let absolute = absolute_path(path)?;
    let mut current = PathBuf::new();
    let mut retained = Vec::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        match component {
            Component::Prefix(_) | Component::CurDir => {}
            Component::RootDir | Component::Normal(_) => {
                let directory = open_windows_directory(&current)?;
                retain_windows_root_component(&mut retained, directory, &current)?;
            }
            Component::ParentDir => return Err(invalid_root(&absolute)),
        }
    }
    let handle = retained.pop().ok_or_else(|| invalid_root(&absolute))?;
    let final_path = crate::file_lock::windows_final_path(&handle)?;
    Ok(SecureDirectory {
        handle,
        path: absolute,
        final_path,
        _retained_ancestors: retained,
    })
}

#[cfg(windows)]
fn directory_entry_names(directory: &SecureDirectory, limit: usize) -> io::Result<Vec<OsString>> {
    verify_visible_windows_directory(directory)?;
    let names = collect_entry_names(fs::read_dir(&directory.path)?, limit)?;
    verify_visible_windows_directory(directory)?;
    Ok(names)
}

#[cfg(windows)]
fn open_child_entry(directory: &SecureDirectory, name: &OsStr) -> io::Result<SecureEntry> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let path = directory.path.join(name);
    let file = open_windows_entry(&path)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(symlink_entry(&path));
    }
    let final_path = crate::file_lock::windows_final_path(&file)?;
    ensure_windows_child_contained(directory, &final_path)?;
    if metadata.is_dir() {
        return Ok(SecureEntry::Directory(SecureDirectory {
            handle: file,
            path,
            final_path,
            _retained_ancestors: Vec::new(),
        }));
    }
    if metadata.is_file() {
        return Ok(SecureEntry::File(file, metadata));
    }
    Err(non_regular_entry(&path))
}

#[cfg(windows)]
fn verify_visible_windows_directory(directory: &SecureDirectory) -> io::Result<()> {
    let visible = open_windows_directory(&directory.path)?;
    let same_identity = crate::file_lock::windows_file_identity(&visible)?
        == crate::file_lock::windows_file_identity(&directory.handle)?;
    let same_path = crate::file_lock::windows_final_path(&visible)? == directory.final_path;
    if same_identity && same_path {
        return Ok(());
    }
    Err(windows_path_changed(&directory.path))
}

#[cfg(windows)]
fn ensure_windows_child_contained(
    directory: &SecureDirectory,
    child_final_path: &Path,
) -> io::Result<()> {
    if windows_child_is_contained(&directory.final_path, child_final_path) {
        return Ok(());
    }
    Err(windows_path_changed(&directory.path))
}

#[cfg(windows)]
fn windows_child_is_contained(directory: &Path, child: &Path) -> bool {
    child.parent() == Some(directory)
}

#[cfg(windows)]
fn windows_path_changed(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "database path changed during secure traversal: {}",
            path.display()
        ),
    )
}

#[cfg(windows)]
fn retain_windows_root_component(
    retained: &mut Vec<fs::File>,
    directory: fs::File,
    requested: &Path,
) -> io::Result<()> {
    let Some(parent) = retained.last() else {
        // A drive root or UNC share root bootstraps the retained handle chain.
        retained.push(directory);
        return Ok(());
    };
    ensure_windows_direct_child(parent, &directory, requested)?;
    retained.push(directory);
    Ok(())
}

#[cfg(windows)]
fn ensure_windows_direct_child(
    parent: &fs::File,
    child: &fs::File,
    requested: &Path,
) -> io::Result<()> {
    let child_path = crate::file_lock::windows_final_path(child)?;
    let parent_path = child_path
        .parent()
        .ok_or_else(|| windows_path_changed(requested))?;
    let resolved_parent = open_windows_directory(parent_path)?;
    let expected = crate::file_lock::windows_file_identity(parent)?;
    let actual = crate::file_lock::windows_file_identity(&resolved_parent)?;
    if actual == expected {
        return Ok(());
    }
    Err(windows_path_changed(requested))
}

#[cfg(windows)]
fn open_windows_directory(path: &Path) -> io::Result<fs::File> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let file = open_windows_handle(path, 0)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(symlink_entry(path));
    }
    if metadata.is_dir() {
        return Ok(file);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{} is not a directory", path.display()),
    ))
}

#[cfg(windows)]
fn open_windows_entry(path: &Path) -> io::Result<fs::File> {
    use windows_sys::Win32::Foundation::GENERIC_READ;
    open_windows_handle(path, GENERIC_READ)
}

#[cfg(windows)]
fn open_windows_handle(path: &Path, desired_access: u32) -> io::Result<fs::File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { fs::File::from_raw_handle(handle) })
}

#[cfg(not(any(unix, windows)))]
fn open_root_directory(path: &Path) -> io::Result<SecureDirectory> {
    let path = absolute_path(path)?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid_root(&path));
    }
    Ok(SecureDirectory {
        handle: fs::File::open(&path)?,
        path,
    })
}

#[cfg(not(any(unix, windows)))]
fn directory_entry_names(directory: &SecureDirectory, limit: usize) -> io::Result<Vec<OsString>> {
    collect_entry_names(fs::read_dir(&directory.path)?, limit)
}

#[cfg(not(any(unix, windows)))]
fn open_child_entry(directory: &SecureDirectory, name: &OsStr) -> io::Result<SecureEntry> {
    let path = directory.path.join(name);
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() {
        return Err(symlink_entry(&path));
    }
    if metadata.is_dir() {
        return open_root_directory(&path).map(SecureEntry::Directory);
    }
    if metadata.is_file() {
        return Ok(SecureEntry::File(fs::File::open(path)?, metadata));
    }
    Err(non_regular_entry(&path))
}

fn invalid_root(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{} is not a safe absolute directory", path.display()),
    )
}

#[cfg(any(windows, not(any(unix, windows))))]
fn symlink_entry(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("refusing to follow database link {}", path.display()),
    )
}

fn non_regular_entry(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "CodeQL database contains non-regular entry {}",
            path.display()
        ),
    )
}

#[cfg(not(unix))]
fn collect_entry_names(entries: fs::ReadDir, limit: usize) -> io::Result<Vec<OsString>> {
    let mut names = Vec::new();
    for entry in entries {
        if names.len() >= limit {
            return Err(entry_limit_error());
        }
        names.push(entry?.file_name());
    }
    Ok(names)
}

fn entry_limit_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "CodeQL database exceeds the file-count limit",
    )
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn drive_and_unc_roots_bootstrap_without_a_parent_handle() {
        let temp = tempfile::tempdir().unwrap();
        for requested in [Path::new(r"C:\"), Path::new(r"\\server\share\")] {
            let root = open_windows_directory(temp.path()).unwrap();
            let mut retained = Vec::new();

            retain_windows_root_component(&mut retained, root, requested).unwrap();

            assert_eq!(retained.len(), 1);
        }
    }

    #[test]
    fn intermediate_junction_rebase_cannot_escape_the_retained_root_chain() {
        let temp = tempfile::tempdir().unwrap();
        let expected_parent = temp.path().join("repository").join(".kuzushi");
        let expected_child = expected_parent.join("codeql-db");
        let outside_child = temp.path().join("outside").join("codeql-db");
        fs::create_dir_all(&expected_child).unwrap();
        fs::create_dir_all(&outside_child).unwrap();

        let mut valid_chain = vec![open_windows_directory(&expected_parent).unwrap()];
        let expected = open_windows_directory(&expected_child).unwrap();
        retain_windows_root_component(&mut valid_chain, expected, &expected_child).unwrap();
        assert_eq!(valid_chain.len(), 2);

        let mut retained = vec![open_windows_directory(&expected_parent).unwrap()];
        let escaped = open_windows_directory(&outside_child).unwrap();

        // This outside handle models a full-path open resolved through an
        // intermediate junction after the expected parent was retained.
        let error =
            retain_windows_root_component(&mut retained, escaped, &expected_child).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(retained.len(), 1);
    }

    #[test]
    fn final_handle_path_must_be_a_direct_child_of_the_pinned_directory() {
        let pinned = Path::new(r"\\?\C:\target\database");

        assert!(windows_child_is_contained(
            pinned,
            Path::new(r"\\?\C:\target\database\chunk.bin")
        ));
        assert!(!windows_child_is_contained(
            pinned,
            Path::new(r"\\?\C:\outside\chunk.bin")
        ));
        assert!(!windows_child_is_contained(
            pinned,
            Path::new(r"\\?\C:\target\database\nested\chunk.bin")
        ));
    }
}
