use std::path::Path;

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

    /// Probe `path` and report what state it is in.
    /// Symlinks are followed (we care about the artifact, not the link).
    pub fn for_path(path: &Path) -> Self {
        artifact_state(path)
    }
}

pub fn artifact_state(path: &Path) -> ArtifactState {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => directory_artifact_state(path),
        Ok(metadata) if metadata.is_file() => file_artifact_state(path),
        Ok(_) => ArtifactState::Invalid,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ArtifactState::Missing,
        Err(_) => ArtifactState::Invalid,
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
    let Ok(body) = std::fs::read_to_string(path) else {
        return ArtifactState::Invalid;
    };
    if body.trim().is_empty() {
        return ArtifactState::Invalid;
    }
    if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
        if serde_json::from_str::<serde_json::Value>(&body).is_ok() {
            ArtifactState::Cached
        } else {
            ArtifactState::Invalid
        }
    } else {
        ArtifactState::Cached
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
    fn symlink_to_file_follows_target() {
        #[cfg(unix)]
        {
            let tmp = tempfile::tempdir().unwrap();
            let real = tmp.path().join("real.json");
            std::fs::write(&real, "{}").unwrap();
            let link = tmp.path().join("link.json");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert_eq!(artifact_state(&link), ArtifactState::Cached);
        }
    }
}
