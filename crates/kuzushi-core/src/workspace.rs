use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceTarget {
    root: PathBuf,
}

impl WorkspaceTarget {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let root = if path.exists() {
            fs::canonicalize(path)
                .with_context(|| format!("Could not resolve {}", path.display()))?
        } else {
            anyhow::bail!("Target path does not exist: {}", path.display());
        };

        if !root.is_dir() {
            anyhow::bail!("Target must be a directory: {}", root.display());
        }

        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn state_dir(&self) -> PathBuf {
        self.root.join(".kuzushi").join("v2")
    }

    pub fn findings_db_path(&self) -> PathBuf {
        self.state_dir().join("findings.sqlite3")
    }

    pub fn ensure_state_dir(&self) -> Result<PathBuf> {
        let state_dir = self.state_dir();
        fs::create_dir_all(&state_dir)
            .with_context(|| format!("Could not create {}", state_dir.display()))?;
        Ok(state_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_v2_state_paths_under_project() {
        let tmp = tempfile::tempdir().unwrap();
        let target = WorkspaceTarget::new(tmp.path()).unwrap();

        assert_eq!(target.state_dir(), target.root().join(".kuzushi/v2"));
        assert_eq!(
            target.findings_db_path(),
            target.root().join(".kuzushi/v2/findings.sqlite3")
        );
    }
}
