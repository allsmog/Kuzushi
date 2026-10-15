use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub(crate) const BINARY_SNIFF_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundedText {
    pub(crate) text: String,
    pub(crate) truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DigestedPrefix {
    pub(crate) bytes: Vec<u8>,
    pub(crate) truncated: bool,
    pub(crate) sha256: String,
}

/// Read at most `max_bytes` of a source-like file without following symlinks.
/// Binary-looking files return `Ok(None)`; text is decoded lossily to preserve
/// the existing inventory behavior for imperfect source encodings.
pub(crate) fn read_source_text_prefix(path: &Path, max_bytes: usize) -> io::Result<Option<String>> {
    read_source_text_prefix_from_reader(open_regular_file(path)?, max_bytes)
}

pub(crate) fn read_source_text_prefix_from_reader(
    reader: impl Read,
    max_bytes: usize,
) -> io::Result<Option<String>> {
    let prefix = read_open_file_prefix(reader, max_bytes.max(BINARY_SNIFF_BYTES))?;
    if prefix
        .bytes
        .iter()
        .take(BINARY_SNIFF_BYTES)
        .any(|byte| *byte == 0)
    {
        return Ok(None);
    }
    let end = prefix.bytes.len().min(max_bytes);
    Ok(Some(
        String::from_utf8_lossy(&prefix.bytes[..end]).into_owned(),
    ))
}

/// Read a bounded UTF-8 text prefix and report whether the file had more data.
pub(crate) fn read_utf8_text_prefix(path: &Path, max_bytes: usize) -> io::Result<BoundedText> {
    let prefix = read_file_prefix(path, max_bytes)?;
    let text = decode_utf8_prefix(prefix.bytes)?;
    Ok(BoundedText {
        text,
        truncated: prefix.truncated,
    })
}

/// Read an entire UTF-8 text file only when it fits within `max_bytes`.
///
/// Parsers that require a complete document must not parse a truncated prefix:
/// doing so can turn an oversized, attacker-controlled manifest into a valid but
/// incomplete input. This helper returns an explicit error instead.
pub(crate) fn read_utf8_text(path: &Path, max_bytes: usize) -> io::Result<String> {
    decode_utf8_prefix(read_regular_bytes(path, max_bytes)?)
}

/// Read an entire binary file only when it fits within `max_bytes`.
pub(crate) fn read_regular_bytes(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    read_open_regular_bytes(path, open_regular_file(path)?, max_bytes)
}

pub(crate) fn read_open_regular_bytes(
    path: &Path,
    file: fs::File,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    reject_truncated(path, max_bytes, file.metadata()?.len() > max_bytes as u64)?;
    let prefix = read_open_file_prefix(file, max_bytes)?;
    reject_truncated(path, max_bytes, prefix.truncated)?;
    Ok(prefix.bytes)
}

/// Open `path` beneath `root` without following symlinked path components, then
/// perform an exact bounded read.
pub(crate) fn read_utf8_text_within(
    root: &Path,
    path: &Path,
    max_bytes: usize,
) -> io::Result<String> {
    decode_utf8_prefix(read_regular_bytes_within(root, path, max_bytes)?)
}

/// Open `path` beneath `root` without following symlinked path components,
/// then read a bounded UTF-8 prefix from the same authorized file descriptor.
pub(crate) fn read_utf8_text_prefix_within(
    root: &Path,
    path: &Path,
    max_bytes: usize,
) -> io::Result<BoundedText> {
    let prefix = read_open_file_prefix(open_regular_file_within(root, path)?, max_bytes)?;
    let text = decode_utf8_prefix(prefix.bytes)?;
    Ok(BoundedText {
        text,
        truncated: prefix.truncated,
    })
}

pub(crate) fn read_source_text_prefix_within(
    root: &Path,
    path: &Path,
    max_bytes: usize,
) -> io::Result<Option<String>> {
    read_source_text_prefix_from_reader(open_regular_file_within(root, path)?, max_bytes)
}

pub(crate) fn read_regular_bytes_within(
    root: &Path,
    path: &Path,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    read_open_regular_bytes(path, open_regular_file_within(root, path)?, max_bytes)
}

pub(crate) fn digest_regular_file_prefix_within(
    root: &Path,
    path: &Path,
    max_bytes: usize,
) -> io::Result<DigestedPrefix> {
    digest_open_file_prefix(open_regular_file_within(root, path)?, max_bytes)
}

pub(crate) fn read_dir_within(root: &Path, path: &Path) -> io::Result<fs::ReadDir> {
    let canonical = canonical_path_within(root, path)?;
    if !fs::symlink_metadata(&canonical)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a directory", path.display()),
        ));
    }
    fs::read_dir(canonical)
}

struct FilePrefix {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_file_prefix(path: &Path, max_bytes: usize) -> io::Result<FilePrefix> {
    read_open_file_prefix(open_regular_file(path)?, max_bytes)
}

fn read_open_file_prefix(reader: impl Read, max_bytes: usize) -> io::Result<FilePrefix> {
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "read limit is too large"))?;
    let mut bytes = Vec::with_capacity(read_limit.min(64 * 1024));
    reader.take(read_limit as u64).read_to_end(&mut bytes)?;
    let truncated = bytes.len() > max_bytes;
    bytes.truncate(max_bytes);
    Ok(FilePrefix { bytes, truncated })
}

fn digest_open_file_prefix(mut file: fs::File, max_bytes: usize) -> io::Result<DigestedPrefix> {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    let mut prefix = Vec::with_capacity(max_bytes.min(64 * 1024));
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_usize;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        if prefix.len() < max_bytes {
            let keep = read.min(max_bytes - prefix.len());
            prefix.extend_from_slice(&buffer[..keep]);
        }
        total = total.saturating_add(read);
    }
    let sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(DigestedPrefix {
        bytes: prefix,
        truncated: total > max_bytes,
        sha256: format!("sha256:{sha256}"),
    })
}

fn reject_truncated(path: &Path, max_bytes: usize, truncated: bool) -> io::Result<()> {
    if truncated {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} exceeds the maximum supported size of {max_bytes} bytes",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn canonical_path_within(root: &Path, path: &Path) -> io::Result<PathBuf> {
    let canonical_root = fs::canonicalize(root)?;
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        canonical_root.join(path)
    };
    reject_symlink(&candidate)?;
    let canonical = fs::canonicalize(&candidate)?;
    if !canonical.starts_with(&canonical_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} escapes workspace {}", path.display(), root.display()),
        ));
    }
    Ok(canonical)
}

#[cfg(unix)]
pub(crate) fn open_regular_file_within(root: &Path, path: &Path) -> io::Result<fs::File> {
    let canonical_root = fs::canonicalize(root)?;
    let relative = relative_path_within(root, &canonical_root, path)?;
    let mut components = relative.components().filter_map(normal_component);
    let leaf = components
        .next_back()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file path is empty"))?;
    let mut directory = open_absolute_directory_no_follow(&canonical_root)?;
    for component in components {
        directory = open_directory_at(&directory, component)?;
    }
    open_regular_at(&directory, leaf)
}

#[cfg(windows)]
pub(crate) fn open_regular_file_within(root: &Path, path: &Path) -> io::Result<fs::File> {
    let canonical_root = fs::canonicalize(root)?;
    let relative = relative_path_within(root, &canonical_root, path)?;
    let (root_handle, _ancestors, candidate) =
        open_windows_ancestor_chain(&canonical_root, &relative)?;
    let file = open_regular_file(&candidate)?;
    verify_windows_handle_containment(&root_handle, &file, &canonical_root, path)?;
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn open_regular_file_within(root: &Path, path: &Path) -> io::Result<fs::File> {
    open_regular_file(&canonical_path_within(root, path)?)
}

#[cfg(any(unix, windows))]
pub(crate) fn relative_path_within(
    root: &Path,
    canonical_root: &Path,
    path: &Path,
) -> io::Result<PathBuf> {
    let relative = if path.is_absolute() {
        path.strip_prefix(root)
            .or_else(|_| path.strip_prefix(canonical_root))
            .map_err(|_| workspace_escape_error(root, path))?
    } else {
        path
    };
    validate_relative_path(root, path, relative)?;
    Ok(relative.to_path_buf())
}

#[cfg(any(unix, windows))]
fn validate_relative_path(root: &Path, path: &Path, relative: &Path) -> io::Result<()> {
    let valid = relative.components().all(|component| {
        matches!(
            component,
            std::path::Component::Normal(_) | std::path::Component::CurDir
        )
    });
    if valid {
        return Ok(());
    }
    Err(workspace_escape_error(root, path))
}

#[cfg(any(unix, windows))]
fn normal_component(component: std::path::Component<'_>) -> Option<&std::ffi::OsStr> {
    match component {
        std::path::Component::Normal(value) => Some(value),
        std::path::Component::CurDir => None,
        _ => None,
    }
}

#[cfg(any(unix, windows))]
fn workspace_escape_error(root: &Path, path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("{} escapes workspace {}", path.display(), root.display()),
    )
}

#[cfg(unix)]
fn open_directory_no_follow(path: &Path) -> io::Result<fs::File> {
    let directory = open_no_follow(path)?;
    if directory.metadata()?.is_dir() {
        return Ok(directory);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{} is not a directory", path.display()),
    ))
}

#[cfg(unix)]
pub(crate) fn open_absolute_directory_no_follow(path: &Path) -> io::Result<fs::File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not an absolute directory", path.display()),
        ));
    }
    let mut directory = open_directory_no_follow(Path::new("/"))?;
    for component in path.components().filter_map(normal_component) {
        directory = open_directory_at(&directory, component)?;
    }
    Ok(directory)
}

#[cfg(unix)]
pub(crate) fn open_directory_at(
    directory: &fs::File,
    name: &std::ffi::OsStr,
) -> io::Result<fs::File> {
    open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
    )
}

#[cfg(unix)]
pub(crate) fn open_regular_at(
    directory: &fs::File,
    name: &std::ffi::OsStr,
) -> io::Result<fs::File> {
    let file = open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )?;
    if file.metadata()?.is_file() {
        return Ok(file);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "workspace path is not a regular file",
    ))
}

/// Open a regular file for read/append/create while retaining trusted handles
/// to every ancestor until the leaf handle is established.
#[cfg(unix)]
pub(crate) fn open_append_regular_file_within(root: &Path, path: &Path) -> io::Result<fs::File> {
    let canonical_root = fs::canonicalize(root)?;
    let relative = relative_path_within(root, &canonical_root, path)?;
    let mut components = relative.components().filter_map(normal_component);
    let leaf = components
        .next_back()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file path is empty"))?;
    let mut directory = open_absolute_directory_no_follow(&canonical_root)?;
    for component in components {
        directory = open_directory_at(&directory, component)?;
    }
    open_append_regular_at(&directory, leaf)
}

#[cfg(unix)]
fn open_append_regular_at(directory: &fs::File, name: &std::ffi::OsStr) -> io::Result<fs::File> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let name = std::ffi::CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    let flags = libc::O_RDWR | libc::O_APPEND | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if descriptor < 0 {
        return Err(map_no_follow_error(io::Error::last_os_error()));
    }
    let file = unsafe { fs::File::from_raw_fd(descriptor) };
    reject_non_regular_open_file(file)
}

#[cfg(unix)]
fn open_at(directory: &fs::File, name: &std::ffi::OsStr, flags: i32) -> io::Result<fs::File> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

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
            "refusing to follow a symlinked workspace path component",
        );
    }
    error
}

pub(crate) fn open_regular_file(path: &Path) -> io::Result<fs::File> {
    reject_symlink(path)?;
    let file = open_no_follow(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(file)
}

fn reject_symlink(path: &Path) -> io::Result<()> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to follow symlink {}", path.display()),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn open_no_follow(path: &Path) -> io::Result<fs::File> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    use windows_sys::Win32::Foundation::GENERIC_READ;
    let file = open_windows_handle(
        path,
        GENERIC_READ,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    reject_windows_reparse_attributes(path, file.metadata()?.file_attributes())?;
    Ok(file)
}

#[cfg(windows)]
fn open_windows_directory_no_follow(path: &Path) -> io::Result<fs::File> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let file = open_windows_handle(
        path,
        0,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    reject_windows_reparse_attributes(path, file.metadata()?.file_attributes())?;
    if file.metadata()?.is_dir() {
        return Ok(file);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{} is not a directory", path.display()),
    ))
}

#[cfg(windows)]
fn open_windows_ancestor_chain(
    canonical_root: &Path,
    relative: &Path,
) -> io::Result<(fs::File, Vec<fs::File>, PathBuf)> {
    let root = open_windows_absolute_directory_no_follow(canonical_root)?;
    let mut ancestors = Vec::new();
    let mut candidate = canonical_root.to_path_buf();
    let mut components = relative
        .components()
        .filter_map(normal_component)
        .peekable();
    while let Some(component) = components.next() {
        candidate.push(component);
        if components.peek().is_some() {
            ancestors.push(open_windows_directory_no_follow(&candidate)?);
        }
    }
    Ok((root, ancestors, candidate))
}

#[cfg(windows)]
fn open_windows_absolute_directory_no_follow(path: &Path) -> io::Result<fs::File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not an absolute directory", path.display()),
        ));
    }
    let mut current = PathBuf::new();
    let mut retained = Vec::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match component {
            std::path::Component::RootDir | std::path::Component::Normal(_) => {
                retained.push(open_windows_directory_no_follow(&current)?);
            }
            std::path::Component::Prefix(_) | std::path::Component::CurDir => {}
            std::path::Component::ParentDir => return Err(workspace_escape_error(path, path)),
        }
    }
    retained.pop().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no directory components", path.display()),
        )
    })
}

#[cfg(windows)]
pub(crate) fn open_append_regular_file_within(root: &Path, path: &Path) -> io::Result<fs::File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    let canonical_root = fs::canonicalize(root)?;
    let relative = relative_path_within(root, &canonical_root, path)?;
    let (root_handle, _ancestors, candidate) =
        open_windows_ancestor_chain(&canonical_root, &relative)?;
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&candidate)?;
    reject_windows_reparse_attributes(&candidate, file.metadata()?.file_attributes())?;
    let file = reject_non_regular_open_file(file)?;
    verify_windows_handle_containment(&root_handle, &file, &canonical_root, path)?;
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn open_append_regular_file_within(root: &Path, path: &Path) -> io::Result<fs::File> {
    let file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(canonical_path_within(root, path)?)?;
    reject_non_regular_open_file(file)
}

fn reject_non_regular_open_file(file: fs::File) -> io::Result<fs::File> {
    if file.metadata()?.is_file() {
        return Ok(file);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "workspace path is not a regular file",
    ))
}

#[cfg(windows)]
fn open_windows_handle(path: &Path, desired_access: u32, flags: u32) -> io::Result<fs::File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide_path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // Excluding FILE_SHARE_DELETE pins each ancestor against replacement while
    // its child handle is opened.
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            desired_access,
            share,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { fs::File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn verify_windows_handle_containment(
    root: &fs::File,
    file: &fs::File,
    expected_root: &Path,
    requested: &Path,
) -> io::Result<()> {
    let root_path = crate::file_lock::windows_final_path(root)?;
    let file_path = crate::file_lock::windows_final_path(file)?;
    if windows_paths_equal(&root_path, expected_root) && file_path.starts_with(&root_path) {
        return Ok(());
    }
    Err(workspace_escape_error(&root_path, requested))
}

#[cfg(windows)]
fn windows_paths_equal(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(windows)]
fn reject_windows_reparse_attributes(path: &Path, attributes: u32) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to follow reparse point {}", path.display()),
        ));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn open_no_follow(path: &Path) -> io::Result<fs::File> {
    fs::File::open(path)
}

fn decode_utf8_prefix(mut bytes: Vec<u8>) -> io::Result<String> {
    loop {
        match String::from_utf8(bytes) {
            Ok(text) => return Ok(text),
            Err(error) if error.utf8_error().error_len().is_none() => {
                let valid = error.utf8_error().valid_up_to();
                bytes = error.into_bytes();
                bytes.truncate(valid);
            }
            Err(error) => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, error));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_prefix_never_allocates_the_whole_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("large.rs");
        fs::write(&path, vec![b'a'; 8 * 1024]).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(128 * 1024 * 1024)
            .unwrap();

        let text = read_source_text_prefix(&path, 1024).unwrap().unwrap();

        assert_eq!(text.len(), 1024);
    }

    #[test]
    fn utf8_prefix_handles_a_split_multibyte_character() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("utf8.txt");
        fs::write(&path, "abcé-tail").unwrap();

        let prefix = read_utf8_text_prefix(&path, 4).unwrap();

        assert_eq!(prefix.text, "abc");
        assert!(prefix.truncated);
    }

    #[test]
    fn binary_source_prefix_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("binary.rs");
        fs::write(&path, b"fn main() {}\0hidden").unwrap();

        assert_eq!(read_source_text_prefix(&path, 1024).unwrap(), None);
    }

    #[test]
    fn exact_text_read_rejects_oversized_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("manifest.json");
        fs::write(&path, "123456789").unwrap();

        let error = read_utf8_text(&path, 8).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("8 bytes"));
    }

    #[test]
    fn exact_binary_read_rejects_oversized_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("lock.bin");
        fs::write(&path, [0_u8; 9]).unwrap();

        assert!(read_regular_bytes(&path, 8).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn workspace_read_rejects_symlink_to_outside() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let outside = temp.path().join("outside.txt");
        fs::create_dir_all(&workspace).unwrap();
        fs::write(&outside, "outside secret").unwrap();
        symlink(&outside, workspace.join("prompt.md")).unwrap();

        let error = read_utf8_text_within(&workspace, Path::new("prompt.md"), 1024).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!error.to_string().contains("outside secret"));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_read_rejects_parent_symlink_escape() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("prompt.md"), "outside secret").unwrap();
        symlink(&outside, workspace.join("prompts")).unwrap();

        let error =
            read_utf8_text_within(&workspace, Path::new("prompts/prompt.md"), 1024).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!error.to_string().contains("outside secret"));
    }

    #[cfg(unix)]
    #[test]
    fn directory_handle_read_survives_parent_replacement_without_escape() {
        use std::ffi::OsStr;
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let nested = workspace.join("nested");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&nested).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(nested.join("prompt.md"), "approved bytes").unwrap();
        fs::write(outside.join("prompt.md"), "outside secret").unwrap();
        let root_handle = open_directory_no_follow(&workspace).unwrap();
        let nested_handle = open_directory_at(&root_handle, OsStr::new("nested")).unwrap();
        fs::rename(&nested, workspace.join("original-nested")).unwrap();
        symlink(&outside, &nested).unwrap();

        let file = open_regular_at(&nested_handle, OsStr::new("prompt.md")).unwrap();
        let bytes = read_open_regular_bytes(Path::new("prompt.md"), file, 1024).unwrap();

        assert_eq!(bytes, b"approved bytes");
        assert!(read_utf8_text_within(&workspace, Path::new("nested/prompt.md"), 1024).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn absolute_root_walk_rejects_an_ancestor_replaced_after_resolution() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("selected-parent");
        let workspace = parent.join("workspace");
        let outside_parent = temp.path().join("outside-parent");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(outside_parent.join("workspace")).unwrap();
        let resolved_workspace = fs::canonicalize(&workspace).unwrap();
        fs::rename(&parent, temp.path().join("original-parent")).unwrap();
        symlink(&outside_parent, &parent).unwrap();

        let error = open_absolute_directory_no_follow(&resolved_workspace).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn workspace_source_prefix_rejects_outside_symlink() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("workspace");
        let outside = temp.path().join("outside.rs");
        fs::create_dir_all(&workspace).unwrap();
        fs::write(&outside, "OUTSIDE_PREFIX_TOKEN").unwrap();
        symlink(&outside, workspace.join("lib.rs")).unwrap();

        let error =
            read_source_text_prefix_within(&workspace, Path::new("lib.rs"), 1024).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!error.to_string().contains("OUTSIDE_PREFIX_TOKEN"));
    }

    #[cfg(unix)]
    #[test]
    fn source_prefix_does_not_follow_symlinks() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        let link = temp.path().join("link.rs");
        fs::write(&outside, "secret").unwrap();
        symlink(&outside, &link).unwrap();

        assert!(read_source_text_prefix(&link, 1024).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn exact_read_does_not_follow_windows_file_symlinks() {
        use std::os::windows::fs::symlink_file;
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside.txt");
        let link = temp.path().join("link.txt");
        fs::write(&outside, "secret").unwrap();
        if let Err(error) = symlink_file(&outside, &link) {
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            return;
        }

        let error = read_regular_bytes(&link, 1024).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!error.to_string().contains("secret"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_attribute_is_rejected_deterministically() {
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        let error = reject_windows_reparse_attributes(
            Path::new("process-identity.json"),
            FILE_ATTRIBUTE_REPARSE_POINT,
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(reject_windows_reparse_attributes(Path::new("regular.json"), 0).is_ok());
    }
}
