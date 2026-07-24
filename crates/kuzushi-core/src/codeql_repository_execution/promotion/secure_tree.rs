use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

#[cfg(not(any(unix, windows)))]
mod fallback;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(not(any(unix, windows)))]
use fallback as platform;
#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

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
        platform::open_root_directory(path)
    }

    pub(super) fn entry_names(&self, limit: usize) -> io::Result<Vec<OsString>> {
        let mut names = platform::directory_entry_names(self, limit)?;
        names.sort();
        Ok(names)
    }

    pub(super) fn open_entry(&self, name: &OsStr) -> io::Result<SecureEntry> {
        validate_entry_name(name)?;
        platform::open_child_entry(self, name)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_name_must_be_one_normal_component() {
        assert!(validate_entry_name(OsStr::new("chunk.bin")).is_ok());
        assert!(validate_entry_name(OsStr::new("nested/chunk.bin")).is_err());
        assert!(validate_entry_name(OsStr::new("..")).is_err());
    }

    #[test]
    fn entry_names_are_sorted_and_bounded() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("z"), "z").unwrap();
        fs::write(temp.path().join("a"), "a").unwrap();
        let directory = SecureDirectory::open(temp.path()).unwrap();

        assert_eq!(
            directory.entry_names(2).unwrap(),
            [OsString::from("a"), OsString::from("z")]
        );
        let directory = SecureDirectory::open(temp.path()).unwrap();
        assert_eq!(
            directory.entry_names(1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
