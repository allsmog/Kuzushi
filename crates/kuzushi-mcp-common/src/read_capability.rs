use anyhow::{Context, Result};
use std::fs::File;
use std::path::{Path, PathBuf};

mod directory;
mod directory_entries;
mod directory_revisions;
mod file;
mod open;

pub use directory::{
    AuthorizedChild, AuthorizedDirectory, AuthorizedDirectoryEntry, AuthorizedFile,
};
pub use directory_revisions::AuthorizedDirectoryRevisions;
use file::bounded_regular_file;
pub use file::{BoundedReadFile, ReadFileIdentity};

use open::{identity_for, open_file_beneath, ReadRoot};

pub const MCP_READ_ROOTS_ENV: &str = "KUZUSHI_MCP_READ_ROOTS";

#[derive(Debug, Clone)]
pub struct ReadRootCapability {
    roots: Vec<ReadRoot>,
}

impl ReadRootCapability {
    pub fn from_environment() -> Result<Self> {
        let raw = std::env::var(MCP_READ_ROOTS_ENV).with_context(|| {
            format!("MCP read capability missing: {MCP_READ_ROOTS_ENV} was not provided")
        })?;
        let roots: Vec<PathBuf> = serde_json::from_str(&raw)
            .with_context(|| format!("{MCP_READ_ROOTS_ENV} must be a JSON array of paths"))?;
        Self::new(roots)
    }

    pub fn new(roots: impl IntoIterator<Item = PathBuf>) -> Result<Self> {
        let roots = roots
            .into_iter()
            .map(|root| ReadRoot::new(&root))
            .collect::<Result<Vec<_>>>()?;
        anyhow::ensure!(!roots.is_empty(), "MCP read capability has no roots");
        Ok(Self { roots })
    }

    pub fn resolve(&self, requested: &Path) -> Result<PathBuf> {
        if requested.is_absolute() {
            return self.authorize_existing_path(requested);
        }
        self.roots
            .iter()
            .filter_map(|root| std::fs::canonicalize(root.path.join(requested)).ok())
            .find(|candidate| self.contains(candidate))
            .with_context(|| {
                format!(
                    "path is outside the MCP read roots: {}",
                    requested.display()
                )
            })
    }

    /// Authorize and open a regular file for an exact, bounded read.
    pub fn open(&self, requested: &Path, max_bytes: usize) -> Result<BoundedReadFile> {
        let path = self.resolve(requested)?;
        let root = self.root_for(&path).with_context(|| {
            format!(
                "path is outside the MCP read roots: {}",
                requested.display()
            )
        })?;
        let file = open_file_beneath(root, &path)?;
        bounded_regular_file(path, file, max_bytes)
    }

    /// Authorize a file without following any path component beneath a root.
    pub fn open_strict(&self, requested: &Path, max_bytes: usize) -> Result<BoundedReadFile> {
        let (_root, _relative, path, file) = self.open_strict_path(requested)?;
        bounded_regular_file(path, file, max_bytes)
    }

    /// Retain an existing directory for later no-follow child access.
    pub fn authorize_directory(&self, requested: &Path) -> Result<AuthorizedDirectory> {
        let (root, relative, path, file) = self.open_strict_path(requested)?;
        let metadata = file
            .metadata()
            .with_context(|| format!("could not inspect {}", path.display()))?;
        anyhow::ensure!(
            metadata.is_dir(),
            "MCP path is not a directory: {}",
            path.display()
        );
        Ok(AuthorizedDirectory {
            path,
            relative,
            root: root.clone(),
            identity: identity_for(&file, &metadata)?,
            file,
        })
    }

    pub fn read_bytes(&self, requested: &Path, max_bytes: usize) -> Result<Vec<u8>> {
        self.open(requested, max_bytes)?.read_bytes()
    }

    pub fn read_utf8(&self, requested: &Path, max_bytes: usize) -> Result<String> {
        self.open(requested, max_bytes)?.read_utf8()
    }

    fn authorize_existing_path(&self, requested: &Path) -> Result<PathBuf> {
        let canonical = std::fs::canonicalize(requested).with_context(|| {
            format!("could not resolve requested path: {}", requested.display())
        })?;
        anyhow::ensure!(
            self.contains(&canonical),
            "path is outside the MCP read roots: {}",
            requested.display()
        );
        Ok(canonical)
    }

    fn contains(&self, candidate: &Path) -> bool {
        self.root_for(candidate).is_some()
    }

    fn root_for(&self, candidate: &Path) -> Option<&ReadRoot> {
        self.roots
            .iter()
            .filter(|root| candidate.starts_with(&root.path))
            .max_by_key(|root| root.path.components().count())
    }

    fn open_strict_path(&self, requested: &Path) -> Result<StrictOpenedPath<'_>> {
        let mut candidates = self.strict_candidates(requested)?;
        candidates.sort_by_key(|(root, _)| std::cmp::Reverse(root.path.components().count()));
        let mut last_error = None;
        for (root, relative) in candidates {
            let path = root.path.join(&relative);
            match open_file_beneath(root, &path) {
                Ok(file) => return Ok((root, relative, path, file)),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!(
                "path is outside the MCP read roots: {}",
                requested.display()
            )
        }))
    }

    fn strict_candidates(&self, requested: &Path) -> Result<Vec<(&ReadRoot, PathBuf)>> {
        let candidates = self
            .roots
            .iter()
            .filter_map(|root| relative_for_root(root, requested).map(|relative| (root, relative)))
            .collect::<Vec<_>>();
        anyhow::ensure!(
            !candidates.is_empty(),
            "path is outside the MCP read roots: {}",
            requested.display()
        );
        for (_, relative) in &candidates {
            validate_relative_path(relative)?;
        }
        Ok(candidates)
    }
}

type StrictOpenedPath<'a> = (&'a ReadRoot, PathBuf, PathBuf, File);

fn relative_for_root(root: &ReadRoot, requested: &Path) -> Option<PathBuf> {
    if !requested.is_absolute() {
        return Some(requested.to_path_buf());
    }
    requested
        .strip_prefix(&root.path)
        .or_else(|_| requested.strip_prefix(&root.requested_path))
        .ok()
        .map(Path::to_path_buf)
}

fn validate_relative_child(path: &Path) -> Result<()> {
    anyhow::ensure!(!path.as_os_str().is_empty(), "MCP child path is empty");
    validate_relative_path(path)
}

fn validate_relative_path(path: &Path) -> Result<()> {
    anyhow::ensure!(
        !path.is_absolute(),
        "absolute MCP child paths are not allowed"
    );
    anyhow::ensure!(
        path.components()
            .all(|component| matches!(component, std::path::Component::Normal(_))),
        "MCP child path contains '.' or '..': {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests;
