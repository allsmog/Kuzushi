mod metadata;
mod schema;

#[cfg(test)]
pub(super) use metadata::external_mkdir_test_hook_path;
pub(in crate::run_artifacts::run_history_index) use metadata::DirectoryStamp;
pub(super) use metadata::{directory_stamp, stable_directory_snapshot, IndexMetadata};

use super::super::super::checked_run_history_index_path;
use anyhow::{Context, Result};
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags};
use std::fs;
use std::path::Path;
use std::time::Duration;

const SQLITE_CACHE_KIB: i64 = 2 * 1024;
const MAX_INDEX_BYTES: u64 = 512 * 1024 * 1024;

pub(super) fn open_index(target: &Path, writable: bool) -> Result<Connection> {
    let path = checked_run_history_index_path(target)?;
    reject_index_symlink(&path)?;
    open_path(&path, writable)
        .with_context(|| format!("Could not open run-history index {}", path.display()))
}

pub(super) fn open_path(path: &Path, writable: bool) -> Result<Connection> {
    reject_oversized_index(path)?;
    let access = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let flags = access | OpenFlags::SQLITE_OPEN_NOFOLLOW | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(path, flags)?;
    connection.busy_timeout(Duration::from_secs(2))?;
    validate_page_budget(&connection, writable)?;
    configure_connection(&connection, writable)?;
    Ok(connection)
}

fn validate_page_budget(connection: &Connection, writable: bool) -> Result<()> {
    let page_size: i64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let page_count: i64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
    let page_size = u64::try_from(page_size).context("run-history page size is invalid")?;
    let page_count = u64::try_from(page_count).context("run-history page count is invalid")?;
    let bytes = page_size
        .checked_mul(page_count)
        .context("run-history index page count overflowed")?;
    anyhow::ensure!(bytes <= MAX_INDEX_BYTES, "run-history index is too large");
    if writable {
        let max_pages = i64::try_from((MAX_INDEX_BYTES / page_size.max(1)).max(1))
            .context("run-history page limit does not fit SQLite")?;
        connection.pragma_update(None, "max_page_count", max_pages)?;
    }
    Ok(())
}

fn configure_connection(connection: &Connection, writable: bool) -> Result<()> {
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, false)?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, false)?;
    connection.pragma_update(None, "cache_size", -SQLITE_CACHE_KIB)?;
    connection.pragma_update(None, "mmap_size", 0)?;
    connection.pragma_update(None, "temp_store", "MEMORY")?;
    if writable {
        connection.pragma_update(None, "journal_mode", "MEMORY")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
    } else {
        connection.pragma_update(None, "query_only", true)?;
    }
    Ok(())
}

pub(super) fn initialize_schema(connection: &Connection) -> Result<()> {
    schema::initialize_schema(connection)
}

pub(super) fn validate_schema(connection: &Connection) -> Result<()> {
    schema::validate_schema(connection)
}

pub(super) fn reject_index_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "run-history index must not be a symlink: {}",
                path.display()
            )
        }
        Ok(metadata) if !metadata.is_file() => {
            anyhow::bail!("run-history index is not a file: {}", path.display())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

fn reject_oversized_index(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.len() <= MAX_INDEX_BYTES,
                "run-history index is too large"
            );
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

#[cfg(not(windows))]
pub(super) fn publish_replacement(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
pub(super) fn publish_replacement(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };
    let source = wide_path(source);
    let destination = wide_path(destination);
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    if unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), flags) } == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub(super) fn sync_index_file(target: &Path) -> Result<()> {
    let path = checked_run_history_index_path(target)?;
    fs::File::open(&path)?.sync_all()?;
    Ok(crate::fs_atomic::sync_parent_dir(&path)?)
}
