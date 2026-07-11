use anyhow::{Context, Result};
use std::path::Path;
use std::time::SystemTime;

/// Generic on-disk artifact existence + validity check shared across
/// the planning picker (TUI) and the MCP attachment probe (kuzushi-core).
///
/// `Cached` means the artifact is present and parses (for JSON files);
/// `Invalid` means it exists but is malformed; `Missing` means the file
/// or directory is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactState {
    Cached,
    Invalid,
    Missing,
}

impl ArtifactState {
    pub fn label(self) -> &'static str {
        match self {
            ArtifactState::Cached => "cached",
            ArtifactState::Invalid => "invalid",
            ArtifactState::Missing => "missing",
        }
    }

    pub fn is_cached(self) -> bool {
        matches!(self, ArtifactState::Cached)
    }

    /// Probe `path` and report what state it is in. Symlinks are invalid:
    /// workspace artifacts must be owned files or directories.
    pub fn for_path(path: &Path) -> Self {
        artifact_state(path)
    }
}

pub fn artifact_state(path: &Path) -> ArtifactState {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => ArtifactState::Invalid,
        Ok(metadata) if metadata.file_type().is_dir() => directory_artifact_state(path),
        Ok(metadata) if metadata.file_type().is_file() => file_artifact_state(path),
        Ok(_) => ArtifactState::Invalid,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ArtifactState::Missing,
        Err(_) => ArtifactState::Invalid,
    }
}

pub fn artifact_state_within(root: &Path, path: &Path) -> ArtifactState {
    let relative = match path.strip_prefix(root) {
        Ok(relative) => relative,
        Err(_) => return ArtifactState::Invalid,
    };
    match crate::workspace::validated_workspace_descendant(root, relative) {
        Ok(safe_path) => artifact_state(&safe_path),
        Err(_) => ArtifactState::Invalid,
    }
}

pub fn artifact_modified_within(root: &Path, path: &Path) -> Result<Option<SystemTime>> {
    let relative = path.strip_prefix(root).with_context(|| {
        format!(
            "Artifact {} is outside workspace {}",
            path.display(),
            root.display()
        )
    })?;
    let safe_path = crate::workspace::validated_workspace_descendant(root, relative)?;
    match std::fs::symlink_metadata(&safe_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("Artifact is a symlink: {}", safe_path.display())
        }
        Ok(metadata) if metadata.is_file() || metadata.is_dir() => metadata
            .modified()
            .map(Some)
            .with_context(|| format!("Could not read mtime for {}", safe_path.display())),
        Ok(_) => anyhow::bail!(
            "Artifact is not a file or directory: {}",
            safe_path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("Could not inspect {}", safe_path.display()))
        }
    }
}

fn directory_artifact_state(path: &Path) -> ArtifactState {
    match std::fs::read_dir(path) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                ArtifactState::Cached
            } else {
                ArtifactState::Missing
            }
        }
        Err(_) => ArtifactState::Invalid,
    }
}

fn file_artifact_state(path: &Path) -> ArtifactState {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return ArtifactState::Invalid;
    };
    if metadata.len() == 0 {
        return ArtifactState::Invalid;
    }
    if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
        return ArtifactState::Cached;
    }
    let Ok(bytes) = crate::bounded_file::read_regular_bytes(path, 16 * 1024 * 1024) else {
        return ArtifactState::Invalid;
    };
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(_) => ArtifactState::Cached,
        Err(_) => ArtifactState::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn missing_path_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(
            artifact_state(&tmp.path().join("nope.json")),
            ArtifactState::Missing
        );
    }

    #[test]
    fn empty_directory_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("empty");
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(artifact_state(&dir), ArtifactState::Missing);
    }

    #[test]
    fn populated_directory_is_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("populated");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("inside.txt"), "x").unwrap();
        assert_eq!(artifact_state(&dir), ArtifactState::Cached);
    }

    #[test]
    fn valid_json_file_is_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ok.json");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(b"{}").unwrap();
        assert_eq!(artifact_state(&path), ArtifactState::Cached);
    }

    #[test]
    fn malformed_json_is_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bad.json");
        std::fs::write(&path, "{not-json").unwrap();
        assert_eq!(artifact_state(&path), ArtifactState::Invalid);
    }

    #[test]
    fn empty_file_is_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("empty.json");
        std::fs::write(&path, "").unwrap();
        assert_eq!(artifact_state(&path), ArtifactState::Invalid);
    }

    #[test]
    fn non_json_file_is_cached_when_non_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("x-ray.md");
        std::fs::write(&path, "# x-ray").unwrap();
        assert_eq!(artifact_state(&path), ArtifactState::Cached);
    }

    #[test]
    fn binary_cpg_is_cached_when_non_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cpg.bin");
        std::fs::write(&path, [0xff, 0x00, 0x7f, 0x80]).unwrap();

        assert_eq!(artifact_state(&path), ArtifactState::Cached);
    }

    #[test]
    fn symlink_to_file_is_invalid() {
        #[cfg(unix)]
        {
            let tmp = tempfile::tempdir().unwrap();
            let real = tmp.path().join("real.json");
            std::fs::write(&real, "{}").unwrap();
            let link = tmp.path().join("link.json");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert_eq!(artifact_state(&link), ArtifactState::Invalid);
        }
    }

    #[test]
    fn oversized_artifact_is_invalid_without_full_read() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("oversized.json");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(17 * 1024 * 1024)
            .unwrap();

        assert_eq!(artifact_state(&path), ArtifactState::Invalid);
    }

    #[cfg(unix)]
    #[test]
    fn artifact_modified_within_rejects_parent_symlink() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("report.json"), "{}").unwrap();
        std::os::unix::fs::symlink(outside.path(), workspace.path().join("linked")).unwrap();

        assert!(artifact_modified_within(
            workspace.path(),
            &workspace.path().join("linked/report.json")
        )
        .is_err());
    }
}
