use std::path::{Path, PathBuf};

/// A checked artifact path was absent, rather than unsafe, unreadable or malformed.
#[derive(Debug)]
pub struct RunArtifactMissing {
    label: String,
    path: PathBuf,
}

impl RunArtifactMissing {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn new(label: &str, path: PathBuf) -> Self {
        Self {
            label: label.to_string(),
            path,
        }
    }
}

impl std::fmt::Display for RunArtifactMissing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} is missing: {}",
            self.label,
            super::escaped_path(&self.path)
        )
    }
}

impl std::error::Error for RunArtifactMissing {}
