use crate::{
    AuthorizedChild, AuthorizedDirectory, AuthorizedDirectoryEntry, AuthorizedDirectoryRevisions,
    AuthorizedFile, ReadRootCapability,
};
use anyhow::{Context, Result};
use std::ffi::OsStr;
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
    copy_bounded_bundle_with_durability(root, destination, config, CopyDurability::Durable)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyDurability {
    /// Flush every copied file before returning. Use for durable artifacts.
    Durable,
    /// Rely on ordinary filesystem writeback. Use for disposable execution snapshots.
    Ephemeral,
}

pub fn copy_bounded_bundle_with_durability(
    root: &Path,
    destination: &Path,
    config: BundleIdentityConfig,
    durability: CopyDurability,
) -> Result<String> {
    prepare_empty_destination(root, destination, config.label)?;
    walk_bundle(root, Some((destination, durability)), config)
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
    destination: Option<(&Path, CopyDurability)>,
    config: BundleIdentityConfig,
) -> Result<String> {
    let root = fs::canonicalize(root)
        .with_context(|| format!("could not resolve {} {}", config.label, root.display()))?;
    let capability = ReadRootCapability::new([root.clone()])?;
    let directory = capability.authorize_directory(&root)?;
    let mut budget = BundleBudget::default();
    let mut revisions = AuthorizedDirectoryRevisions::new(&directory, entry_limit(config)?)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(config.domain);
    hash_directory(
        &directory,
        Path::new(""),
        destination,
        0,
        &mut budget,
        &mut revisions,
        &mut hasher,
        config,
    )?;
    revisions.verify_all_unchanged()?;
    Ok(hasher.finalize().to_hex().to_string())
}

#[derive(Default)]
struct BundleBudget {
    entries: u64,
    bytes: u64,
}

#[allow(clippy::too_many_arguments)]
fn hash_directory(
    directory: &AuthorizedDirectory,
    relative: &Path,
    destination: Option<(&Path, CopyDurability)>,
    depth: usize,
    budget: &mut BundleBudget,
    revisions: &mut AuthorizedDirectoryRevisions,
    hasher: &mut blake3::Hasher,
    config: BundleIdentityConfig,
) -> Result<()> {
    ensure_depth(depth, config)?;
    let entries = bounded_entries(directory, budget, config)?;
    revisions.retain(directory, &entries)?;
    let before = DirectoryRevision::read(directory.path(), config.label)?;
    hasher.update(b"d");
    for entry in entries {
        hash_entry(
            directory,
            relative,
            &entry,
            destination,
            depth,
            budget,
            revisions,
            hasher,
            config,
        )?;
    }
    hasher.update(b"e");
    verify_directory_stable(directory, &before, config.label)
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

fn entry_limit(config: BundleIdentityConfig) -> Result<usize> {
    usize::try_from(config.max_entries).context("bundle entry limit exceeds this platform")
}

#[allow(clippy::too_many_arguments)]
fn hash_entry(
    directory: &AuthorizedDirectory,
    parent: &Path,
    entry: &AuthorizedDirectoryEntry,
    destination: Option<(&Path, CopyDurability)>,
    depth: usize,
    budget: &mut BundleBudget,
    revisions: &mut AuthorizedDirectoryRevisions,
    hasher: &mut blake3::Hasher,
    config: BundleIdentityConfig,
) -> Result<()> {
    budget.reserve_entry(config)?;
    let relative = parent.join(entry.name());
    match directory.open_child(entry)? {
        AuthorizedChild::Directory(child) => {
            frame_entry(hasher, b'd', entry.name());
            prepare_output_directory(destination, &relative)?;
            hash_directory(
                &child,
                &relative,
                destination,
                depth + 1,
                budget,
                revisions,
                hasher,
                config,
            )
        }
        AuthorizedChild::File(file) => hash_file(
            file,
            &relative,
            entry.name(),
            destination,
            budget,
            hasher,
            config,
        ),
    }
}

fn prepare_output_directory(
    destination: Option<(&Path, CopyDurability)>,
    relative: &Path,
) -> Result<()> {
    let Some((destination, _)) = destination else {
        return Ok(());
    };
    fs::create_dir(destination.join(relative))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn hash_file(
    file: AuthorizedFile,
    relative: &Path,
    name: &OsStr,
    destination: Option<(&Path, CopyDurability)>,
    budget: &mut BundleBudget,
    hasher: &mut blake3::Hasher,
    config: BundleIdentityConfig,
) -> Result<()> {
    let remaining = config.max_bytes.saturating_sub(budget.bytes);
    let max_bytes = usize::try_from(remaining).context("bundle limit exceeds this platform")?;
    let permissions = file.permissions();
    let file = file.into_bounded(max_bytes)?;
    let bytes = file.identity().len;
    budget.reserve_bytes(bytes, config)?;
    let digest = copy_or_discard(file, destination, relative, permissions)?;
    frame_entry(hasher, b'f', name);
    hasher.update(&bytes.to_le_bytes());
    hasher.update(&(digest.len() as u64).to_le_bytes());
    hasher.update(digest.as_bytes());
    Ok(())
}

fn copy_or_discard(
    source: crate::BoundedReadFile,
    destination: Option<(&Path, CopyDurability)>,
    relative: &Path,
    permissions: fs::Permissions,
) -> Result<String> {
    let Some((destination, durability)) = destination else {
        return source.copy_to_with_sha256_hex(&mut std::io::sink());
    };
    let path = destination.join(relative);
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    let digest = source.copy_to_with_sha256_hex(&mut output)?;
    if durability == CopyDurability::Durable {
        output.sync_all()?;
    }
    drop(output);
    fs::set_permissions(path, permissions)?;
    Ok(digest)
}

fn bounded_entries(
    directory: &AuthorizedDirectory,
    budget: &BundleBudget,
    config: BundleIdentityConfig,
) -> Result<Vec<AuthorizedDirectoryEntry>> {
    let remaining = config.max_entries.saturating_sub(budget.entries);
    let remaining =
        usize::try_from(remaining).context("bundle entry limit exceeds this platform")?;
    directory.entries(remaining).with_context(|| {
        format!(
            "{} exceeds the {}-entry limit or could not be enumerated",
            config.label, config.max_entries
        )
    })
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
    directory.verify_revision_unchanged()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CONFIG: BundleIdentityConfig =
        BundleIdentityConfig::new(b"kuzushi-test-bundle-v1\0", "test bundle", 32, 1024, 8);

    #[test]
    fn copy_preserves_nested_tree_identity_and_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::create_dir(&destination).unwrap();
        fs::write(source.join("root.txt"), "root").unwrap();
        fs::write(source.join("nested/child.bin"), [0_u8, 1, 2]).unwrap();

        let expected = bounded_bundle_identity(&source, TEST_CONFIG).unwrap();
        let copied = copy_bounded_bundle(&source, &destination, TEST_CONFIG).unwrap();

        assert_eq!(copied, expected);
        assert_eq!(
            bounded_bundle_identity(&destination, TEST_CONFIG).unwrap(),
            expected
        );
        assert_eq!(fs::read(destination.join("root.txt")).unwrap(), b"root");
        assert_eq!(
            fs::read(destination.join("nested/child.bin")).unwrap(),
            [0_u8, 1, 2]
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn bundle_walker_never_accepts_a_swapped_nested_subset() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let child = source.join("child");
        let retained = temp.path().join("retained-child");
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("trusted-a"), "trusted-a").unwrap();
        fs::write(child.join("trusted-b"), "trusted-b").unwrap();
        let capability = ReadRootCapability::new([temp.path().to_path_buf()]).unwrap();
        let directory = capability.authorize_directory(&source).unwrap();
        let entry = bounded_entries(&directory, &BundleBudget::default(), TEST_CONFIG)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let expected = hash_test_entry(&directory, &entry).unwrap();

        fs::rename(&child, &retained).unwrap();
        fs::create_dir(&child).unwrap();
        fs::write(child.join("decoy"), "decoy").unwrap();
        let swapped = hash_test_entry(&directory, &entry);
        fs::remove_dir_all(&child).unwrap();
        fs::rename(&retained, &child).unwrap();

        match swapped {
            Ok(actual) => assert_eq!(actual, expected, "the retained child must be hashed"),
            Err(error) => {
                let message = format!("{error:#}");
                assert!(
                    message.contains("directory entry") || message.contains("directory revision"),
                    "unexpected error: {error:#}"
                );
            }
        }
        assert!(directory.verify_revision_unchanged().is_err());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn bundle_revision_receipts_reject_a_restored_same_directory_subset() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let child_path = source.join("child");
        let omitted = child_path.join("trusted-b");
        let retained = temp.path().join("retained-b");
        fs::create_dir_all(&child_path).unwrap();
        fs::write(child_path.join("trusted-a"), "trusted-a").unwrap();
        fs::write(&omitted, "trusted-b").unwrap();
        let capability = ReadRootCapability::new([temp.path().to_path_buf()]).unwrap();
        let root = capability.authorize_directory(&source).unwrap();
        let child_entry = root.entries(4).unwrap().into_iter().next().unwrap();

        fs::rename(&omitted, &retained).unwrap();
        let AuthorizedChild::Directory(child) = root.open_child(&child_entry).unwrap() else {
            panic!("child token did not open a directory");
        };
        let mut budget = BundleBudget::default();
        let mut revisions =
            AuthorizedDirectoryRevisions::new(&child, entry_limit(TEST_CONFIG).unwrap()).unwrap();
        let mut hasher = blake3::Hasher::new();
        hash_directory(
            &child,
            Path::new("child"),
            None,
            1,
            &mut budget,
            &mut revisions,
            &mut hasher,
            TEST_CONFIG,
        )
        .unwrap();
        fs::rename(&retained, &omitted).unwrap();

        let error = revisions.verify_all_unchanged().unwrap_err();
        assert!(
            format!("{error:#}").contains("directory revision"),
            "unexpected error: {error:#}"
        );
    }

    fn hash_test_entry(
        directory: &AuthorizedDirectory,
        entry: &AuthorizedDirectoryEntry,
    ) -> Result<String> {
        let mut budget = BundleBudget::default();
        let mut revisions =
            AuthorizedDirectoryRevisions::new(directory, entry_limit(TEST_CONFIG)?)?;
        let mut hasher = blake3::Hasher::new();
        hash_entry(
            directory,
            Path::new(""),
            entry,
            None,
            0,
            &mut budget,
            &mut revisions,
            &mut hasher,
            TEST_CONFIG,
        )?;
        revisions.verify_all_unchanged()?;
        Ok(hasher.finalize().to_hex().to_string())
    }
}
