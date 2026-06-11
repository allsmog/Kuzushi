//! Crash-safe writes for `.kuzushi` state files.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Write `contents` to `path` atomically: write a same-directory temp file,
/// then rename it over the target. A crash mid-write can no longer leave a
/// truncated or corrupt state file — the previous content survives instead.
/// Rename is atomic because the temp sibling lives on the same filesystem.
pub(crate) fn write_atomic(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    let temp = temp_sibling(path);
    fs::write(&temp, contents).with_context(|| format!("Could not write {}", temp.display()))?;
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error)
            .with_context(|| format!("Could not move {} into place", path.display()));
    }
    Ok(())
}

fn temp_sibling(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state".to_string());
    path.with_file_name(format!(".{file_name}.tmp-{}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_new_file_and_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_atomic(&path, "{\"v\":1}").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"v\":1}");
        write_atomic(&path, "{\"v\":2}").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"v\":2}");
    }

    #[test]
    fn creates_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/deeper/state.json");
        write_atomic(&path, "ok").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "ok");
    }

    #[test]
    fn leaves_no_temp_sibling_behind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        write_atomic(&path, "ok").unwrap();
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }
}
