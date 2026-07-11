use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use std::time::Duration;

const SQLITE_BUSY_TIMEOUT_MS: u64 = 5_000;

pub(crate) fn open_file(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        ensure_safe_database_directory(parent)?;
    }
    validate_database_leaf(path)?;
    validate_sqlite_sidecars(path)?;
    let open_path = canonical_database_path(path)?;
    let flags = OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let conn = Connection::open_with_flags(&open_path, flags)
        .with_context(|| format!("Could not open {}", path.display()))?;
    validate_database_leaf(&open_path)?;
    validate_sqlite_sidecars(&open_path)?;
    configure_file_connection(&conn)?;
    Ok(conn)
}

fn canonical_database_path(path: &Path) -> Result<std::path::PathBuf> {
    let parent = path
        .parent()
        .with_context(|| format!("SQLite database path has no parent: {}", path.display()))?;
    let leaf = path
        .file_name()
        .with_context(|| format!("SQLite database path has no file name: {}", path.display()))?;
    let parent = parent
        .canonicalize()
        .with_context(|| format!("Could not resolve SQLite directory {}", parent.display()))?;
    Ok(parent.join(leaf))
}

fn ensure_safe_database_directory(path: &Path) -> Result<()> {
    if let Some(state_root) = path
        .ancestors()
        .find(|ancestor| ancestor.file_name().is_some_and(|name| name == ".kuzushi"))
    {
        return ensure_workspace_database_directory(path, state_root);
    }
    ensure_external_database_directory(path)
}

fn ensure_workspace_database_directory(path: &Path, state_root: &Path) -> Result<()> {
    let workspace_root = state_root.parent().with_context(|| {
        format!(
            "SQLite state directory {} has no workspace parent",
            path.display()
        )
    })?;
    let relative = path.strip_prefix(workspace_root).with_context(|| {
        format!(
            "SQLite directory {} is outside workspace {}",
            path.display(),
            workspace_root.display()
        )
    })?;
    crate::workspace::ensure_workspace_descendant_dir(workspace_root, relative)?;
    Ok(())
}

fn ensure_external_database_directory(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("SQLite directory must not be a symlink: {}", path.display())
        }
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => anyhow::bail!("SQLite parent is not a directory: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_database_directory(path)
        }
        Err(error) => Err(error)
            .with_context(|| format!("Could not inspect SQLite directory {}", path.display())),
    }
}

fn create_database_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent().filter(|parent| *parent != path) {
        ensure_safe_database_directory(parent)?;
    }
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure_safe_database_directory(path)
        }
        Err(error) => Err(error)
            .with_context(|| format!("Could not create SQLite directory {}", path.display())),
    }
}

fn validate_database_leaf(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("SQLite database must not be a symlink: {}", path.display())
        }
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => anyhow::bail!("SQLite database is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("Could not inspect SQLite database {}", path.display())),
    }
}

fn validate_sqlite_sidecars(path: &Path) -> Result<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        validate_optional_regular_file(Path::new(&sidecar))?;
    }
    Ok(())
}

fn validate_optional_regular_file(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("SQLite sidecar must not be a symlink: {}", path.display())
        }
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => anyhow::bail!("SQLite sidecar is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("Could not inspect SQLite sidecar {}", path.display())),
    }
}

pub(crate) fn configure_file_connection(conn: &Connection) -> Result<()> {
    let _journal_mode: String = conn
        .query_row("pragma journal_mode = wal", [], |row| row.get(0))
        .context("Could not enable sqlite WAL mode")?;
    conn.busy_timeout(Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))
        .context("Could not configure sqlite busy timeout")?;
    conn.execute_batch("pragma foreign_keys = on;")
        .context("Could not enable sqlite foreign keys")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn database_and_sidecar_symlinks_are_rejected_before_sqlite_opens() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside.sqlite3");
        Connection::open(&outside)
            .unwrap()
            .execute_batch("create table outside_sentinel(value text);")
            .unwrap();
        let linked = temp.path().join("linked.sqlite3");
        symlink(&outside, &linked).unwrap();
        assert!(open_file(&linked).is_err());

        let database = temp.path().join("safe.sqlite3");
        let outside_sidecar = temp.path().join("outside-sidecar");
        std::fs::write(&outside_sidecar, "sentinel").unwrap();
        symlink(&outside_sidecar, temp.path().join("safe.sqlite3-wal")).unwrap();
        assert!(open_file(&database).is_err());
        assert_eq!(
            std::fs::read_to_string(outside_sidecar).unwrap(),
            "sentinel"
        );

        let outside_conn = Connection::open(outside).unwrap();
        let count: i64 = outside_conn
            .query_row(
                "select count(*) from sqlite_master where type='table'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[cfg(unix)]
    #[test]
    fn workspace_database_parent_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), workspace.path().join(".kuzushi")).unwrap();
        let database = workspace.path().join(".kuzushi/v3/index.sqlite3");

        assert!(open_file(&database).is_err());
        assert!(!outside.path().join("v3/index.sqlite3").exists());
    }

    #[cfg(unix)]
    #[test]
    fn database_under_platform_symlinked_ancestor_opens_safely() {
        let temp = tempfile::tempdir().unwrap();
        let database = temp.path().join("index.sqlite3");

        let conn = open_file(&database).unwrap();

        conn.execute_batch("create table proof(value text);")
            .unwrap();
        assert!(database.is_file());
    }
}
