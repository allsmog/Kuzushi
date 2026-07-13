use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const BINARY_SNIFF_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BoundedText {
    pub(crate) text: String,
    pub(crate) truncated: bool,
}

/// Read at most `max_bytes` of a source-like file without following symlinks.
/// Binary-looking files return `Ok(None)`; text is decoded lossily to preserve
/// the existing inventory behavior for imperfect source encodings.
pub(crate) fn read_source_text_prefix(path: &Path, max_bytes: usize) -> io::Result<Option<String>> {
    let sniff_limit = max_bytes.max(BINARY_SNIFF_BYTES);
    let prefix = read_file_prefix(path, sniff_limit)?;
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
    let file = open_regular_file(path)?;
    reject_truncated(path, max_bytes, file.metadata()?.len() > max_bytes as u64)?;
    let prefix = read_open_file_prefix(file, max_bytes)?;
    reject_truncated(path, max_bytes, prefix.truncated)?;
    Ok(prefix.bytes)
}

/// Resolve `path` inside `root`, reject a symlink at the requested leaf, and
/// then perform an exact bounded read. Canonical containment closes parent
/// directory symlink escapes; `O_NOFOLLOW` on the canonical leaf closes a
/// replacement race at open time.
pub(crate) fn read_utf8_text_within(
    root: &Path,
    path: &Path,
    max_bytes: usize,
) -> io::Result<String> {
    let canonical = canonical_path_within(root, path)?;
    read_utf8_text(&canonical, max_bytes)
}

pub(crate) fn read_source_text_prefix_within(
    root: &Path,
    path: &Path,
    max_bytes: usize,
) -> io::Result<Option<String>> {
    let canonical = canonical_path_within(root, path)?;
    read_source_text_prefix(&canonical, max_bytes)
}

pub(crate) fn read_regular_bytes_within(
    root: &Path,
    path: &Path,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    let canonical = canonical_path_within(root, path)?;
    read_regular_bytes(&canonical, max_bytes)
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

fn read_open_file_prefix(file: fs::File, max_bytes: usize) -> io::Result<FilePrefix> {
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "read limit is too large"))?;
    let mut bytes = Vec::with_capacity(read_limit.min(64 * 1024));
    file.take(read_limit as u64).read_to_end(&mut bytes)?;
    let truncated = bytes.len() > max_bytes;
    bytes.truncate(max_bytes);
    Ok(FilePrefix { bytes, truncated })
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
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide_path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ,
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
    let file = unsafe { fs::File::from_raw_handle(handle) };
    reject_windows_reparse_attributes(path, file.metadata()?.file_attributes())?;
    Ok(file)
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
