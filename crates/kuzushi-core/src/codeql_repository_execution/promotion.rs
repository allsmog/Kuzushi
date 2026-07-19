use anyhow::{Context, Result};
use secure_tree::{SecureDirectory, SecureEntry};
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

mod secure_tree;

const MAX_DATABASE_ENTRIES: u64 = 500_000;
const MAX_DATABASE_BYTES: u64 = 64_u64 * 1024 * 1024 * 1024;
const MAX_DATABASE_DEPTH: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum DestinationState {
    Missing,
    ValidDatabase(DatabaseIdentity),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DatabaseIdentity(String);

impl DatabaseIdentity {
    pub(super) fn from_receipt(value: String) -> Self {
        Self(value)
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(super) fn inspect_destination(path: &Path) -> Result<DestinationState> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            anyhow::ensure!(
                codeql_database_is_valid(path),
                "refusing to replace non-CodeQL output at {}",
                path.display()
            );
            Ok(DestinationState::ValidDatabase(database_identity(path)?))
        }
        Ok(_) => anyhow::bail!(
            "refusing to replace unsafe CodeQL output at {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(DestinationState::Missing),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

pub(crate) fn codeql_database_is_valid(path: &Path) -> bool {
    codeql_database_has_shape(path)
        && super::provenance::read_codeql_database_provenance(path).is_ok()
}

pub(super) fn codeql_database_has_shape(path: &Path) -> bool {
    let root_is_directory = fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink());
    root_is_directory && codeql_marker_is_valid(path) && codeql_database_has_language_dir(path)
}

fn codeql_marker_is_valid(path: &Path) -> bool {
    fs::symlink_metadata(path.join("codeql-database.yml"))
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

fn codeql_database_has_language_dir(path: &Path) -> bool {
    fs::read_dir(path)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|entry| {
            entry.file_name().to_string_lossy().starts_with("db-")
                && entry
                    .file_type()
                    .is_ok_and(|kind| kind.is_dir() && !kind.is_symlink())
        })
}

pub(super) fn promote_database(
    workspace: &Path,
    isolated_db: &Path,
    destination: &Path,
    expected_state: DestinationState,
) -> Result<DatabaseIdentity> {
    validate_isolated_database(isolated_db)?;
    let staged = stage_database_copy(isolated_db, destination)?;
    anyhow::ensure!(
        inspect_destination(destination)? == expected_state,
        "CodeQL destination changed during isolated execution; retry"
    );
    install_staged_database(workspace, destination, staged.directory, &expected_state)?;
    Ok(staged.identity)
}

fn validate_isolated_database(isolated_db: &Path) -> Result<()> {
    anyhow::ensure!(
        codeql_database_is_valid(isolated_db),
        "CodeQL reported success without a complete database and trusted provenance in the isolated checkout"
    );
    Ok(())
}

struct StagedDatabase {
    directory: tempfile::TempDir,
    identity: DatabaseIdentity,
}

fn stage_database_copy(source: &Path, destination: &Path) -> Result<StagedDatabase> {
    let parent = destination
        .parent()
        .context("CodeQL output has no parent")?;
    let staged = tempfile::Builder::new()
        .prefix(".codeql-db-stage-")
        .tempdir_in(parent)
        .context("could not stage the trusted CodeQL database")?;
    copy_database_tree(source, staged.path())?;
    anyhow::ensure!(
        codeql_database_is_valid(staged.path()),
        "staged CodeQL database failed validation"
    );
    let identity = database_identity(staged.path())?;
    Ok(StagedDatabase {
        directory: staged,
        identity,
    })
}

#[derive(Default)]
struct CopyBudget {
    entries: u64,
    bytes: u64,
}

fn copy_database_tree(source: &Path, destination: &Path) -> Result<()> {
    let source = SecureDirectory::open(source)
        .with_context(|| format!("opening CodeQL database {}", source.display()))?;
    let mut budget = CopyBudget::default();
    copy_directory_contents(&source, destination, 0, &mut budget)
}

fn copy_directory_contents(
    source: &SecureDirectory,
    destination: &Path,
    depth: usize,
    budget: &mut CopyBudget,
) -> Result<()> {
    anyhow::ensure!(
        depth <= MAX_DATABASE_DEPTH,
        "CodeQL database nesting is too deep"
    );
    for name in source
        .entry_names(remaining_entry_capacity(budget))
        .with_context(|| format!("reading {}", source.path().display()))?
    {
        copy_database_entry(source, &name, destination, depth, budget)?;
    }
    Ok(())
}

fn copy_database_entry(
    source: &SecureDirectory,
    name: &OsStr,
    destination: &Path,
    depth: usize,
    budget: &mut CopyBudget,
) -> Result<()> {
    reserve_entry(budget)?;
    let source_path = source.path().join(name);
    let target = destination.join(name);
    match source.open_entry(name) {
        Ok(SecureEntry::Directory(directory)) => {
            fs::create_dir(&target)?;
            copy_directory_contents(&directory, &target, depth + 1, budget)
        }
        Ok(SecureEntry::File(file, metadata)) => {
            copy_regular_file(file, metadata, &source_path, &target, budget)
        }
        Err(error) => Err(error).with_context(|| format!("opening {}", source_path.display())),
    }
}

fn copy_regular_file(
    mut source: fs::File,
    metadata: fs::Metadata,
    source_path: &Path,
    target: &Path,
    budget: &mut CopyBudget,
) -> Result<()> {
    reserve_file_bytes(budget, metadata.len())?;
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    stream_exact_file(&mut source, metadata.len(), |bytes| output.write_all(bytes))
        .with_context(|| format!("copying {}", source_path.display()))?;
    verify_source_unchanged(&source, &metadata, source_path)?;
    drop(output);
    fs::set_permissions(target, metadata.permissions())?;
    Ok(())
}

fn stream_exact_file<F>(source: &mut fs::File, expected: u64, mut consume: F) -> Result<()>
where
    F: FnMut(&[u8]) -> std::io::Result<()>,
{
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let remaining = expected.saturating_sub(total);
        let limit = (remaining.saturating_add(1)).min(buffer.len() as u64) as usize;
        let count = source.read(&mut buffer[..limit])?;
        if count == 0 {
            break;
        }
        anyhow::ensure!(
            count as u64 <= remaining,
            "CodeQL database file grew while reading"
        );
        consume(&buffer[..count])?;
        total += count as u64;
    }
    anyhow::ensure!(
        total == expected,
        "CodeQL database file shrank while reading"
    );
    Ok(())
}

fn verify_source_unchanged(source: &fs::File, before: &fs::Metadata, path: &Path) -> Result<()> {
    let after = source.metadata()?;
    let same_modified = before.modified().ok() == after.modified().ok();
    anyhow::ensure!(
        before.len() == after.len() && same_modified,
        "CodeQL database file changed while copying: {}",
        path.display()
    );
    Ok(())
}

fn reserve_entry(budget: &mut CopyBudget) -> Result<()> {
    budget.entries = budget.entries.saturating_add(1);
    anyhow::ensure!(
        budget.entries <= MAX_DATABASE_ENTRIES,
        "CodeQL database exceeds the file-count limit"
    );
    Ok(())
}

fn remaining_entry_capacity(budget: &CopyBudget) -> usize {
    MAX_DATABASE_ENTRIES.saturating_sub(budget.entries) as usize
}

fn reserve_file_bytes(budget: &mut CopyBudget, bytes: u64) -> Result<()> {
    budget.bytes = budget
        .bytes
        .checked_add(bytes)
        .context("CodeQL database byte count overflowed")?;
    anyhow::ensure!(
        budget.bytes <= MAX_DATABASE_BYTES,
        "CodeQL database exceeds the promotion byte limit"
    );
    Ok(())
}

fn install_staged_database(
    workspace: &Path,
    destination: &Path,
    staged: tempfile::TempDir,
    state: &DestinationState,
) -> Result<()> {
    if *state == DestinationState::Missing {
        fs::rename(staged.path(), destination).context("publishing trusted CodeQL database")?;
        return sync_database_parent(destination);
    }
    replace_existing_database(workspace, destination, staged.path(), state)
}

fn replace_existing_database(
    workspace: &Path,
    destination: &Path,
    staged: &Path,
    expected: &DestinationState,
) -> Result<()> {
    let parent = destination
        .parent()
        .context("CodeQL output has no parent")?;
    let backup = parent.join(format!(".codeql-db-backup-{}", uuid::Uuid::new_v4()));
    validate_backup_path(workspace, &backup)?;
    fs::rename(destination, &backup).context("backing up the previous CodeQL database")?;
    let unchanged = inspect_destination(&backup)
        .map(|actual| &actual == expected)
        .unwrap_or(false);
    if !unchanged {
        return restore_changed_database(destination, &backup);
    }
    if let Err(error) = fs::rename(staged, destination) {
        return restore_previous_database(destination, &backup, error);
    }
    fs::remove_dir_all(&backup).context("removing the previous CodeQL database backup")?;
    sync_database_parent(destination)
}

fn restore_changed_database(destination: &Path, backup: &Path) -> Result<()> {
    fs::rename(backup, destination)
        .context("restoring CodeQL database changed during isolated execution")?;
    anyhow::bail!("CodeQL destination changed during isolated execution; retry")
}

pub(super) fn database_identity(path: &Path) -> Result<DatabaseIdentity> {
    let root = SecureDirectory::open(path)
        .with_context(|| format!("opening CodeQL database {}", path.display()))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kuzushi-codeql-database-content-v1\0");
    let mut budget = CopyBudget::default();
    hash_directory_contents(&root, 0, &mut budget, &mut hasher)?;
    Ok(DatabaseIdentity(hasher.finalize().to_hex().to_string()))
}

fn hash_directory_contents(
    directory: &SecureDirectory,
    depth: usize,
    budget: &mut CopyBudget,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    anyhow::ensure!(
        depth <= MAX_DATABASE_DEPTH,
        "CodeQL database nesting is too deep"
    );
    for name in directory.entry_names(remaining_entry_capacity(budget))? {
        hash_database_entry(directory, &name, depth, budget, hasher)?;
    }
    hasher.update(b"e");
    Ok(())
}

fn hash_database_entry(
    directory: &SecureDirectory,
    name: &OsStr,
    depth: usize,
    budget: &mut CopyBudget,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    reserve_entry(budget)?;
    let entry = directory.open_entry(name)?;
    match entry {
        SecureEntry::Directory(child) => {
            hash_entry_header(hasher, b'd', name, 0);
            hash_directory_contents(&child, depth + 1, budget, hasher)
        }
        SecureEntry::File(mut file, metadata) => {
            hash_regular_file(&mut file, &metadata, name, budget, hasher)
        }
    }
}

fn hash_regular_file(
    file: &mut fs::File,
    metadata: &fs::Metadata,
    name: &OsStr,
    budget: &mut CopyBudget,
    hasher: &mut blake3::Hasher,
) -> Result<()> {
    reserve_file_bytes(budget, metadata.len())?;
    hash_entry_header(hasher, b'f', name, metadata.len());
    stream_exact_file(file, metadata.len(), |bytes| {
        hasher.update(bytes);
        Ok(())
    })?;
    verify_source_unchanged(file, metadata, Path::new(name))
}

fn hash_entry_header(hasher: &mut blake3::Hasher, kind: u8, name: &OsStr, size: u64) {
    let name = encoded_name(name);
    hasher.update(&[kind]);
    hasher.update(&(name.len() as u64).to_le_bytes());
    hasher.update(&name);
    hasher.update(&size.to_le_bytes());
}

#[cfg(unix)]
fn encoded_name(name: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    name.as_bytes().to_vec()
}

#[cfg(windows)]
fn encoded_name(name: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    name.encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

#[cfg(not(any(unix, windows)))]
fn encoded_name(name: &OsStr) -> Vec<u8> {
    name.to_string_lossy().into_owned().into_bytes()
}

fn validate_backup_path(workspace: &Path, backup: &Path) -> Result<()> {
    let relative = backup
        .strip_prefix(workspace)
        .context("CodeQL backup escaped workspace")?;
    crate::workspace::prepare_workspace_output_path(workspace, relative)?;
    Ok(())
}

fn restore_previous_database(
    destination: &Path,
    backup: &Path,
    publish_error: std::io::Error,
) -> Result<()> {
    fs::rename(backup, destination).with_context(|| {
        format!("publishing the new CodeQL database failed ({publish_error}); restoring the previous database also failed")
    })?;
    Err(publish_error).context("publishing trusted CodeQL database")
}

fn sync_database_parent(destination: &Path) -> Result<()> {
    crate::fs_atomic::sync_parent_dir(destination)
        .with_context(|| format!("syncing parent of {}", destination.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promotion_rejects_symlinks_inside_a_reported_database() {
        let workspace = tempfile::tempdir().unwrap();
        let isolated = tempfile::tempdir().unwrap();
        let destination = workspace.path().join(".kuzushi/codeql-db");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        make_valid_database(isolated.path());
        #[cfg(unix)]
        std::os::unix::fs::symlink("codeql-database.yml", isolated.path().join("alias")).unwrap();

        #[cfg(unix)]
        assert!(promote_database(
            workspace.path(),
            isolated.path(),
            &destination,
            DestinationState::Missing,
        )
        .is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn failed_preflight_preserves_non_database_output() {
        let workspace = tempfile::tempdir().unwrap();
        let destination = workspace.path().join(".kuzushi/codeql-db");
        fs::create_dir_all(&destination).unwrap();
        fs::write(destination.join("important.txt"), "keep").unwrap();

        assert!(inspect_destination(&destination).is_err());
        assert_eq!(
            fs::read_to_string(destination.join("important.txt")).unwrap(),
            "keep"
        );
    }

    #[test]
    fn promotion_rejects_destination_changed_after_preflight() {
        let workspace = tempfile::tempdir().unwrap();
        let isolated = tempfile::tempdir().unwrap();
        let destination = workspace.path().join(".kuzushi/codeql-db");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::create_dir(&destination).unwrap();
        make_valid_database(&destination);
        make_valid_database(isolated.path());
        let expected = inspect_destination(&destination).unwrap();
        fs::write(
            destination.join("codeql-database.yml"),
            "primaryLanguage: javascript\n",
        )
        .unwrap();

        let error = promote_database(workspace.path(), isolated.path(), &destination, expected)
            .unwrap_err()
            .to_string();

        assert!(error.contains("destination changed"), "{error}");
        assert_eq!(
            fs::read_to_string(destination.join("codeql-database.yml")).unwrap(),
            "primaryLanguage: javascript\n"
        );
    }

    #[test]
    fn destination_identity_detects_nested_same_size_rewrite() {
        let workspace = tempfile::tempdir().unwrap();
        let isolated = tempfile::tempdir().unwrap();
        let destination = workspace.path().join(".kuzushi/codeql-db");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::create_dir(&destination).unwrap();
        make_valid_database(&destination);
        make_valid_database(isolated.path());
        let nested = destination.join("db-cpp/cache/chunk.bin");
        fs::create_dir_all(nested.parent().unwrap()).unwrap();
        fs::write(&nested, b"AAAA").unwrap();
        let expected = inspect_destination(&destination).unwrap();

        fs::write(&nested, b"BBBB").unwrap();
        let actual = inspect_destination(&destination).unwrap();

        assert_ne!(actual, expected);
        let error = promote_database(workspace.path(), isolated.path(), &destination, expected)
            .unwrap_err()
            .to_string();
        assert!(error.contains("destination changed"), "{error}");
        assert_eq!(fs::read(&nested).unwrap(), b"BBBB");
    }

    #[test]
    fn promotion_returns_the_identity_of_the_staged_tree() {
        let workspace = tempfile::tempdir().unwrap();
        let isolated = tempfile::tempdir().unwrap();
        let destination = workspace.path().join(".kuzushi/codeql-db");
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        make_valid_database(isolated.path());
        fs::write(isolated.path().join("db-cpp/chunk.bin"), b"AAAA").unwrap();

        let promoted = promote_database(
            workspace.path(),
            isolated.path(),
            &destination,
            DestinationState::Missing,
        )
        .unwrap();

        assert_eq!(promoted, database_identity(&destination).unwrap());
        fs::write(destination.join("db-cpp/chunk.bin"), b"BBBB").unwrap();
        assert_ne!(promoted, database_identity(&destination).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn copy_rejects_file_swapped_to_symlink_after_enumeration() {
        use std::os::unix::fs::symlink;

        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let victim = source.path().join("chunk.bin");
        fs::write(&victim, b"approved").unwrap();
        let opened = SecureDirectory::open(source.path()).unwrap();
        assert!(opened
            .entry_names(MAX_DATABASE_ENTRIES as usize)
            .unwrap()
            .iter()
            .any(|name| name == "chunk.bin"));
        fs::remove_file(&victim).unwrap();
        symlink(outside.path(), &victim).unwrap();

        let error = copy_database_entry(
            &opened,
            OsStr::new("chunk.bin"),
            destination.path(),
            0,
            &mut CopyBudget::default(),
        )
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("symlinked database"),
            "{error:#}"
        );
        assert!(!destination.path().join("chunk.bin").exists());
    }

    #[test]
    fn database_identity_includes_provenance_bytes() {
        let database = tempfile::tempdir().unwrap();
        make_valid_database(database.path());
        let before = database_identity(database.path()).unwrap();
        let provenance = database
            .path()
            .join(super::super::provenance::CODEQL_PROVENANCE_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&provenance).unwrap()).unwrap();
        value["generation"] = serde_json::Value::String(uuid::Uuid::new_v4().to_string());
        fs::write(&provenance, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

        let after = database_identity(database.path()).unwrap();

        assert_ne!(after, before);
    }

    #[test]
    fn database_identity_frames_directory_boundaries() {
        let nested = tempfile::tempdir().unwrap();
        fs::create_dir(nested.path().join("a")).unwrap();
        fs::write(nested.path().join("a/b"), b"b").unwrap();
        fs::write(nested.path().join("a/c"), b"c").unwrap();
        let flattened = tempfile::tempdir().unwrap();
        fs::create_dir(flattened.path().join("a")).unwrap();
        fs::write(flattened.path().join("a/b"), b"b").unwrap();
        fs::write(flattened.path().join("c"), b"c").unwrap();

        assert_ne!(
            database_identity(nested.path()).unwrap(),
            database_identity(flattened.path()).unwrap()
        );
    }

    fn make_valid_database(path: &Path) {
        fs::write(path.join("codeql-database.yml"), "primaryLanguage: cpp\n").unwrap();
        fs::create_dir(path.join("db-cpp")).unwrap();
        let binding = crate::remediation::patch::RepositorySourceBinding {
            commit: "0".repeat(40),
            target_scope: ".".to_string(),
        };
        super::super::provenance::write_codeql_database_provenance(path, &binding, "cpp").unwrap();
    }
}
