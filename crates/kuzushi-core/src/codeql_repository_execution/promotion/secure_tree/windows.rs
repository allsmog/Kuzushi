use super::{
    absolute_path, collect_entry_names, invalid_root, non_regular_entry, symlink_entry,
    SecureDirectory, SecureEntry,
};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

pub(super) fn open_root_directory(path: &Path) -> io::Result<SecureDirectory> {
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

pub(super) fn directory_entry_names(
    directory: &SecureDirectory,
    limit: usize,
) -> io::Result<Vec<OsString>> {
    verify_visible_windows_directory(directory)?;
    let names = collect_entry_names(fs::read_dir(&directory.path)?, limit)?;
    verify_visible_windows_directory(directory)?;
    Ok(names)
}

pub(super) fn open_child_entry(
    directory: &SecureDirectory,
    name: &OsStr,
) -> io::Result<SecureEntry> {
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

fn ensure_windows_child_contained(
    directory: &SecureDirectory,
    child_final_path: &Path,
) -> io::Result<()> {
    if windows_child_is_contained(&directory.final_path, child_final_path) {
        return Ok(());
    }
    Err(windows_path_changed(&directory.path))
}

fn windows_child_is_contained(directory: &Path, child: &Path) -> bool {
    child.parent() == Some(directory)
}

fn windows_path_changed(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "database path changed during secure traversal: {}",
            path.display()
        ),
    )
}

fn retain_windows_root_component(
    retained: &mut Vec<fs::File>,
    directory: fs::File,
    requested: &Path,
) -> io::Result<()> {
    let Some(parent) = retained.last() else {
        retained.push(directory);
        return Ok(());
    };
    ensure_windows_direct_child(parent, &directory, requested)?;
    retained.push(directory);
    Ok(())
}

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

fn open_windows_entry(path: &Path) -> io::Result<fs::File> {
    use windows_sys::Win32::Foundation::GENERIC_READ;
    open_windows_handle(path, GENERIC_READ)
}

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

#[cfg(test)]
mod tests {
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
