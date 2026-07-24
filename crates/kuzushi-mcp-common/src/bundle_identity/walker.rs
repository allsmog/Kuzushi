use super::budget::{entry_limit, BundleBudget};
use super::copy::{self, CopyTarget};
use super::revision::{encoded_name, DirectoryRevision};
use super::BundleIdentityConfig;
use crate::{
    AuthorizedChild, AuthorizedDirectory, AuthorizedDirectoryEntry, AuthorizedDirectoryRevisions,
    AuthorizedFile, ReadRootCapability,
};
use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

pub(super) fn walk_bundle(
    root: &Path,
    destination: Option<CopyTarget<'_>>,
    config: BundleIdentityConfig,
) -> Result<String> {
    let root = fs::canonicalize(root)
        .with_context(|| format!("could not resolve {} {}", config.label, root.display()))?;
    let capability = ReadRootCapability::new([root.clone()])?;
    let directory = capability.authorize_directory(&root)?;
    BundleWalker::new(&directory, destination, config)?.walk(&directory)
}

pub(super) struct BundleWalker<'a> {
    destination: Option<CopyTarget<'a>>,
    config: BundleIdentityConfig,
    budget: BundleBudget,
    revisions: AuthorizedDirectoryRevisions,
    hasher: blake3::Hasher,
}

impl<'a> BundleWalker<'a> {
    pub(super) fn new(
        root: &AuthorizedDirectory,
        destination: Option<CopyTarget<'a>>,
        config: BundleIdentityConfig,
    ) -> Result<Self> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(config.domain);
        Ok(Self {
            destination,
            config,
            budget: BundleBudget::default(),
            revisions: AuthorizedDirectoryRevisions::new(root, entry_limit(config)?)?,
            hasher,
        })
    }

    fn walk(mut self, directory: &AuthorizedDirectory) -> Result<String> {
        self.hash_directory(directory, Path::new(""), 0)?;
        self.finish()
    }

    fn finish(self) -> Result<String> {
        self.revisions.verify_all_unchanged()?;
        Ok(self.hasher.finalize().to_hex().to_string())
    }

    pub(super) fn hash_directory(
        &mut self,
        directory: &AuthorizedDirectory,
        relative: &Path,
        depth: usize,
    ) -> Result<()> {
        ensure_depth(depth, self.config)?;
        let entries = self.bounded_entries(directory)?;
        self.revisions.retain(directory, &entries)?;
        let before = DirectoryRevision::read(directory.path(), self.config.label)?;
        self.hasher.update(b"d");
        for entry in entries {
            self.hash_entry(directory, relative, &entry, depth)?;
        }
        self.hasher.update(b"e");
        verify_directory_stable(directory, &before, self.config.label)
    }

    fn hash_entry(
        &mut self,
        directory: &AuthorizedDirectory,
        parent: &Path,
        entry: &AuthorizedDirectoryEntry,
        depth: usize,
    ) -> Result<()> {
        self.budget.reserve_entry(self.config)?;
        let relative = parent.join(entry.name());
        match directory.open_child(entry)? {
            AuthorizedChild::Directory(child) => {
                frame_entry(&mut self.hasher, b'd', entry.name());
                copy::create_directory(self.destination, &relative)?;
                self.hash_directory(&child, &relative, depth + 1)
            }
            AuthorizedChild::File(file) => self.hash_file(file, &relative, entry.name()),
        }
    }

    fn hash_file(&mut self, file: AuthorizedFile, relative: &Path, name: &OsStr) -> Result<()> {
        let max_bytes = self.budget.remaining_byte_capacity(self.config)?;
        let permissions = file.permissions();
        let file = file.into_bounded(max_bytes)?;
        let bytes = file.identity().len;
        self.budget.reserve_bytes(bytes, self.config)?;
        let digest = copy::digest_file(file, self.destination, relative, permissions)?;
        frame_entry(&mut self.hasher, b'f', name);
        self.hasher.update(&bytes.to_le_bytes());
        self.hasher.update(&(digest.len() as u64).to_le_bytes());
        self.hasher.update(digest.as_bytes());
        Ok(())
    }

    fn bounded_entries(
        &self,
        directory: &AuthorizedDirectory,
    ) -> Result<Vec<AuthorizedDirectoryEntry>> {
        let remaining = self.budget.remaining_entry_capacity(self.config)?;
        directory.entries(remaining).with_context(|| {
            format!(
                "{} exceeds the {}-entry limit or could not be enumerated",
                self.config.label, self.config.max_entries
            )
        })
    }

    #[cfg(test)]
    pub(super) fn verify_revisions_unchanged(&self) -> Result<()> {
        self.revisions.verify_all_unchanged()
    }
}

fn ensure_depth(depth: usize, config: BundleIdentityConfig) -> Result<()> {
    anyhow::ensure!(
        depth <= config.max_depth,
        "{} nesting exceeds the {}-level limit",
        config.label,
        config.max_depth
    );
    Ok(())
}

fn frame_entry(hasher: &mut blake3::Hasher, kind: u8, name: &OsStr) {
    let name = encoded_name(name);
    hasher.update(&[kind]);
    hasher.update(&(name.len() as u64).to_le_bytes());
    hasher.update(&name);
}

fn verify_directory_stable(
    directory: &AuthorizedDirectory,
    before: &DirectoryRevision,
    label: &str,
) -> Result<()> {
    let after = DirectoryRevision::read(directory.path(), label)?;
    anyhow::ensure!(
        after == *before,
        "{label} changed while its identity was computed: {}",
        directory.path().display()
    );
    directory.verify_revision_unchanged()
}

#[cfg(test)]
pub(super) fn hash_test_entry(
    directory: &AuthorizedDirectory,
    entry: &AuthorizedDirectoryEntry,
    config: BundleIdentityConfig,
) -> Result<String> {
    let mut walker = BundleWalker::new(directory, None, config)?;
    walker.hash_entry(directory, Path::new(""), entry, 0)?;
    walker.finish()
}
