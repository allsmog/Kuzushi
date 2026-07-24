use super::{
    absolute_path, collect_entry_names, invalid_root, non_regular_entry, symlink_entry,
    SecureDirectory, SecureEntry,
};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::Path;

pub(super) fn open_root_directory(path: &Path) -> io::Result<SecureDirectory> {
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

pub(super) fn directory_entry_names(
    directory: &SecureDirectory,
    limit: usize,
) -> io::Result<Vec<OsString>> {
    collect_entry_names(fs::read_dir(&directory.path)?, limit)
}

pub(super) fn open_child_entry(
    directory: &SecureDirectory,
    name: &OsStr,
) -> io::Result<SecureEntry> {
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
