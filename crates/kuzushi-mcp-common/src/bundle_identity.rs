use crate::{AuthorizedDirectory, ReadRootCapability};
use anyhow::{Context, Result};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;

mod revision;

use revision::{encoded_name, DirectoryRevision};

#[derive(Clone, Copy)]
pub struct BundleIdentityConfig {
    domain: &'static [u8],
    label: &'static str,
    max_entries: u64,
    max_bytes: u64,
    max_depth: usize,
}

impl BundleIdentityConfig {
    pub const fn new(
        domain: &'static [u8],
        label: &'static str,
        max_entries: u64,
        max_bytes: u64,
        max_depth: usize,
    ) -> Self {
        Self {
            domain,
            label,
            max_entries,
            max_bytes,
            max_depth,
        }
    }
}

pub fn bounded_bundle_identity(root: &Path, config: BundleIdentityConfig) -> Result<String> {
    walk_bundle(root, None, config)
}

pub fn copy_bounded_bundle(
    root: &Path,
    destination: &Path,
    config: BundleIdentityConfig,
) -> Result<String> {
    prepare_empty_destination(root, destination, config.label)?;
    walk_bundle(root, Some(destination), config)
}

fn prepare_empty_destination(root: &Path, destination: &Path, label: &str) -> Result<()> {
    let destination_metadata = fs::symlink_metadata(destination)?;
    anyhow::ensure!(
        destination_metadata.is_dir() && !destination_metadata.file_type().is_symlink(),
        "{label} copy destination is not a regular directory"
    );
    anyhow::ensure!(
        fs::read_dir(destination)?.next().is_none(),
        "{label} copy destination is not empty"
    );
    let source = fs::canonicalize(root)?;
    let destination = fs::canonicalize(destination)?;
    anyhow::ensure!(
        !source.starts_with(&destination) && !destination.starts_with(&source),
        "{label} copy destination overlaps its source"
    );
    Ok(())
}

fn walk_bundle(
    root: &Path,
    destination: Option<&Path>,
    config: BundleIdentityConfig,
) -> Result<String> {
    let root = fs::canonicalize(root)
        .with_context(|| format!("could not resolve {} {}", config.label, root.display()))?;
    let capability = ReadRootCapability::new([root.clone()])?;
    let directory = capability.authorize_directory(&root)?;
    let mut budget = BundleBudget::default();
    let mut hasher = blake3::Hasher::new();
    hasher.update(config.domain);
    hash_directory(
        &capability,
        &directory,
        Path::new(""),
        destination,
        0,
        &mut budget,
        &mut hasher,
        config,
    )?;
    directory.verify_unchanged()?;
    Ok(hasher.finalize().to_hex().to_string())
}

#[derive(Default)]
struct BundleBudget {
    entries: u64,
    bytes: u64,
}

#[allow(clippy::too_many_arguments)]
fn hash_directory(
    capability: &ReadRootCapability,
    root: &AuthorizedDirectory,
    relative: &Path,
    destination: Option<&Path>,
    depth: usize,
    budget: &mut BundleBudget,
    hasher: &mut blake3::Hasher,
    config: BundleIdentityConfig,
) -> Result<()> {
    ensure_depth(depth, config)?;
    let directory = capability.authorize_directory(&root.path().join(relative))?;
    let before = DirectoryRevision::read(directory.path(), config.label)?;
    hasher.update(b"d");
    for name in bounded_entry_names(directory.path(), budget, config)? {
        hash_entry(
            capability,
            root,
            relative,
            &name,
            destination,
            depth,
            budget,
            hasher,
            config,
        )?;
    }
    hasher.update(b"e");
    verify_directory_stable(&directory, &before, config.label)
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

#[allow(clippy::too_many_arguments)]
fn hash_entry(
    capability: &ReadRootCapability,
    root: &AuthorizedDirectory,
    parent: &Path,
    name: &OsStr,
    destination: Option<&Path>,
    depth: usize,
    budget: &mut BundleBudget,
    hasher: &mut blake3::Hasher,
    config: BundleIdentityConfig,
) -> Result<()> {
    budget.reserve_entry(config)?;
    let relative = parent.join(name);
    let path = root.path().join(&relative);
    let metadata = checked_entry_metadata(&path, config.label)?;
    if metadata.is_dir() {
        frame_entry(hasher, b'd', name);
        prepare_output_directory(destination, &relative)?;
        return hash_directory(
            capability,
            root,
            &relative,
            destination,
            depth + 1,
            budget,
            hasher,
            config,
        );
    }
    hash_file(
        root,
        &relative,
        name,
        &metadata,
        destination,
        budget,
        hasher,
        config,
    )
}

fn checked_entry_metadata(path: &Path, label: &str) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "{label} contains a symbolic link: {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.is_dir() || metadata.is_file(),
        "{label} contains a non-regular entry: {}",
        path.display()
    );
    Ok(metadata)
}

fn prepare_output_directory(destination: Option<&Path>, relative: &Path) -> Result<()> {
    let Some(destination) = destination else {
        return Ok(());
    };
    fs::create_dir(destination.join(relative))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn hash_file(
    root: &AuthorizedDirectory,
    relative: &Path,
    name: &OsStr,
    metadata: &fs::Metadata,
    destination: Option<&Path>,
    budget: &mut BundleBudget,
    hasher: &mut blake3::Hasher,
    config: BundleIdentityConfig,
) -> Result<()> {
    let remaining = config.max_bytes.saturating_sub(budget.bytes);
    let max_bytes = usize::try_from(remaining).context("bundle limit exceeds this platform")?;
    let file = root.open_file(relative, max_bytes)?;
    let bytes = file.identity().len;
    budget.reserve_bytes(bytes, config)?;
    let digest = copy_or_discard(file, destination, relative, metadata)?;
    frame_entry(hasher, b'f', name);
    hasher.update(&bytes.to_le_bytes());
    hasher.update(&(digest.len() as u64).to_le_bytes());
    hasher.update(digest.as_bytes());
    Ok(())
}

fn copy_or_discard(
    source: crate::BoundedReadFile,
    destination: Option<&Path>,
    relative: &Path,
    metadata: &fs::Metadata,
) -> Result<String> {
    let Some(destination) = destination else {
        return source.copy_to_with_sha256_hex(&mut std::io::sink());
    };
    let path = destination.join(relative);
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    let digest = source.copy_to_with_sha256_hex(&mut output)?;
    output.sync_all()?;
    drop(output);
    fs::set_permissions(path, metadata.permissions())?;
    Ok(digest)
}

fn bounded_entry_names(
    path: &Path,
    budget: &BundleBudget,
    config: BundleIdentityConfig,
) -> Result<Vec<OsString>> {
    let remaining = config.max_entries.saturating_sub(budget.entries) as usize;
    let mut names = fs::read_dir(path)?
        .take(remaining.saturating_add(1))
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    anyhow::ensure!(
        names.len() <= remaining,
        "{} exceeds the {}-entry limit",
        config.label,
        config.max_entries
    );
    names.sort();
    Ok(names)
}

fn frame_entry(hasher: &mut blake3::Hasher, kind: u8, name: &OsStr) {
    let name = encoded_name(name);
    hasher.update(&[kind]);
    hasher.update(&(name.len() as u64).to_le_bytes());
    hasher.update(&name);
}

impl BundleBudget {
    fn reserve_entry(&mut self, config: BundleIdentityConfig) -> Result<()> {
        self.entries = self
            .entries
            .checked_add(1)
            .context("bundle entry overflow")?;
        anyhow::ensure!(
            self.entries <= config.max_entries,
            "{} exceeds the {}-entry limit",
            config.label,
            config.max_entries
        );
        Ok(())
    }

    fn reserve_bytes(&mut self, bytes: u64, config: BundleIdentityConfig) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .context("bundle byte overflow")?;
        anyhow::ensure!(
            self.bytes <= config.max_bytes,
            "{} exceeds the {}-byte limit",
            config.label,
            config.max_bytes
        );
        Ok(())
    }
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
    directory.verify_unchanged()
}
