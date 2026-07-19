use super::promotion::{codeql_database_has_shape, DatabaseIdentity};
use crate::remediation::patch::RepositorySourceBinding;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(super) const CODEQL_PROVENANCE_FILE: &str = ".kuzushi-provenance.json";
const CODEQL_PROVENANCE_SCHEMA_VERSION: u32 = 1;
const MAX_CODEQL_PROVENANCE_BYTES: usize = 64 * 1024;
const CODEQL_RECEIPT_SCHEMA_VERSION: u32 = 1;
const CODEQL_RECEIPTS_DIR: &str = "codeql-receipts";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CodeqlDatabaseProvenance {
    schema_version: u32,
    pub(crate) source_commit: String,
    pub(crate) target_scope: String,
    pub(crate) language: String,
    pub(crate) generation: String,
}

pub(crate) struct ValidatedManagedCodeqlDatabase {
    path: PathBuf,
    pub(crate) provenance: CodeqlDatabaseProvenance,
    expected_identity: DatabaseIdentity,
    _destination_lock: crate::file_lock::ExclusiveFileLock,
}

impl std::fmt::Debug for ValidatedManagedCodeqlDatabase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedManagedCodeqlDatabase")
            .field("path", &self.path)
            .field("provenance", &self.provenance)
            .field("expected_identity", &self.expected_identity)
            .finish_non_exhaustive()
    }
}

impl ValidatedManagedCodeqlDatabase {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn database_identity(&self) -> &str {
        self.expected_identity.as_str()
    }

    pub(crate) fn run_verified<T>(&self, operation: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
        let result = operation(&self.path);
        self.verify_unchanged()?;
        result
    }

    fn verify_unchanged(&self) -> Result<()> {
        let actual = super::promotion::database_identity(&self.path)?;
        anyhow::ensure!(
            actual == self.expected_identity,
            "managed CodeQL database changed while in use; discard its output and run `codeql:create-db` again"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CodeqlPromotionReceipt {
    schema_version: u32,
    target_id: String,
    database_identity: String,
    provenance: CodeqlDatabaseProvenance,
}

pub(super) fn write_codeql_database_provenance(
    database: &Path,
    binding: &RepositorySourceBinding,
    language: &str,
) -> Result<CodeqlDatabaseProvenance> {
    let provenance = CodeqlDatabaseProvenance {
        schema_version: CODEQL_PROVENANCE_SCHEMA_VERSION,
        source_commit: binding.commit.clone(),
        target_scope: binding.target_scope.clone(),
        language: normalized_language(language)?,
        generation: uuid::Uuid::new_v4().to_string(),
    };
    validate_codeql_database_provenance(&provenance)?;
    let bytes = serde_json::to_vec_pretty(&provenance)?;
    crate::fs_atomic::write_atomic_bytes(&database.join(CODEQL_PROVENANCE_FILE), &bytes)
        .context("could not write CodeQL database provenance")?;
    Ok(provenance)
}

pub(super) fn read_codeql_database_provenance(database: &Path) -> Result<CodeqlDatabaseProvenance> {
    let path = database.join(CODEQL_PROVENANCE_FILE);
    let raw =
        crate::bounded_file::read_utf8_text_within(database, &path, MAX_CODEQL_PROVENANCE_BYTES)
            .with_context(|| format!("could not read CodeQL provenance {}", path.display()))?;
    let provenance: CodeqlDatabaseProvenance = serde_json::from_str(&raw)
        .with_context(|| format!("invalid CodeQL provenance {}", path.display()))?;
    validate_codeql_database_provenance(&provenance)?;
    Ok(provenance)
}

pub(crate) fn resolve_managed_codeql_database(
    target: &Path,
) -> Result<Option<ValidatedManagedCodeqlDatabase>> {
    let path = crate::workspace::workspace_codeql_db_path(target);
    if !path_exists_no_follow(&path)? {
        reject_legacy_database(target)?;
        return Ok(None);
    }
    let destination_lock = super::acquire_managed_database_lock(target, &path)?;
    anyhow::ensure!(
        codeql_database_has_shape(&path),
        "managed CodeQL database at {} is incomplete or unsafe; run `codeql:create-db` again",
        path.display()
    );
    let provenance = read_codeql_database_provenance(&path).with_context(|| {
        format!(
            "managed CodeQL database at {} has no trusted provenance; run `codeql:create-db` again",
            path.display()
        )
    })?;
    validate_current_source(target, &provenance)?;
    let expected_identity = verify_codeql_promotion_receipt(target, &path, &provenance)?;
    Ok(Some(ValidatedManagedCodeqlDatabase {
        path,
        provenance,
        expected_identity,
        _destination_lock: destination_lock,
    }))
}

pub(super) fn write_codeql_promotion_receipt(
    target: &Path,
    provenance: &CodeqlDatabaseProvenance,
    database_identity: &DatabaseIdentity,
) -> Result<()> {
    let operator_home = operator_home_for_target(target)?;
    write_codeql_promotion_receipt_at(&operator_home, target, provenance, database_identity)
}

fn write_codeql_promotion_receipt_at(
    operator_home: &Path,
    target: &Path,
    provenance: &CodeqlDatabaseProvenance,
    database_identity: &DatabaseIdentity,
) -> Result<()> {
    let target_id = target_id(target)?;
    let path = prepare_receipt_path(operator_home, target, &target_id)?;
    let receipt = CodeqlPromotionReceipt {
        schema_version: CODEQL_RECEIPT_SCHEMA_VERSION,
        target_id,
        database_identity: database_identity.as_str().to_string(),
        provenance: provenance.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&receipt)?;
    crate::fs_atomic::write_atomic_bytes(&path, &bytes)
        .context("could not write operator CodeQL promotion receipt")
}

fn verify_codeql_promotion_receipt(
    target: &Path,
    database: &Path,
    provenance: &CodeqlDatabaseProvenance,
) -> Result<DatabaseIdentity> {
    let operator_home = operator_home_for_target(target)?;
    let expected_target_id = target_id(target)?;
    let path = receipt_path(&operator_home, target, &expected_target_id)?;
    let raw = crate::bounded_file::read_utf8_text_within(
        &operator_home,
        &path,
        MAX_CODEQL_PROVENANCE_BYTES,
    )
    .with_context(|| {
        format!(
            "managed CodeQL database has no operator promotion receipt at {}; run `codeql:create-db` again",
            path.display()
        )
    })?;
    let receipt: CodeqlPromotionReceipt = serde_json::from_str(&raw)
        .context("operator CodeQL promotion receipt is malformed; run `codeql:create-db` again")?;
    validate_promotion_receipt(database, provenance, &expected_target_id, &receipt)?;
    Ok(DatabaseIdentity::from_receipt(receipt.database_identity))
}

fn validate_promotion_receipt(
    database: &Path,
    provenance: &CodeqlDatabaseProvenance,
    expected_target_id: &str,
    receipt: &CodeqlPromotionReceipt,
) -> Result<()> {
    let actual_identity = super::promotion::database_identity(database)?;
    anyhow::ensure!(
        receipt.schema_version == CODEQL_RECEIPT_SCHEMA_VERSION
            && receipt.target_id == expected_target_id
            && receipt.provenance == *provenance
            && receipt.database_identity == actual_identity.as_str(),
        "managed CodeQL database does not match its operator promotion receipt; run `codeql:create-db` again"
    );
    Ok(())
}

fn prepare_receipt_path(operator_home: &Path, target: &Path, target_id: &str) -> Result<PathBuf> {
    let path = receipt_path(operator_home, target, target_id)?;
    crate::workspace::initialize_workspace_state(operator_home)?;
    let directory = receipt_relative_dir();
    crate::workspace::ensure_workspace_descendant_dir(operator_home, &directory)?;
    Ok(path)
}

fn receipt_path(operator_home: &Path, target: &Path, target_id: &str) -> Result<PathBuf> {
    let operator_home = std::fs::canonicalize(operator_home)
        .context("could not resolve operator home for CodeQL receipt")?;
    let target = std::fs::canonicalize(target).context("could not resolve CodeQL target")?;
    let receipt_store = operator_home.join(receipt_relative_dir());
    anyhow::ensure!(
        !receipt_store.starts_with(&target) && !target.starts_with(&receipt_store),
        "CodeQL target overlaps the operator-owned receipt store"
    );
    crate::workspace::validated_workspace_descendant(
        &operator_home,
        receipt_relative_dir().join(format!("{target_id}.json")),
    )
}

fn receipt_relative_dir() -> PathBuf {
    PathBuf::from(crate::workspace::KUZUSHI_STATE_DIR)
        .join(crate::workspace::WORKSPACE_STATE_VERSION_DIR)
        .join(CODEQL_RECEIPTS_DIR)
}

fn target_id(target: &Path) -> Result<String> {
    let target = std::fs::canonicalize(target).context("could not resolve CodeQL target")?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"kuzushi-codeql-target-v1\0");
    hash_path(&mut hasher, &target);
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(unix)]
fn hash_path(hasher: &mut blake3::Hasher, path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    hasher.update(path.as_os_str().as_bytes());
}

#[cfg(windows)]
fn hash_path(hasher: &mut blake3::Hasher, path: &Path) {
    use std::os::windows::ffi::OsStrExt;
    for unit in path.as_os_str().encode_wide() {
        hasher.update(&unit.to_le_bytes());
    }
}

#[cfg(not(any(unix, windows)))]
fn hash_path(hasher: &mut blake3::Hasher, path: &Path) {
    hasher.update(path.to_string_lossy().as_bytes());
}

fn operator_home_for_target(_target: &Path) -> Result<PathBuf> {
    #[cfg(test)]
    {
        return Ok(
            test_operator_home(_target).unwrap_or_else(|| register_test_operator_home(_target))
        );
    }
    #[cfg(not(test))]
    dirs::home_dir().context("could not resolve operator home for CodeQL promotion receipt")
}

fn validate_current_source(target: &Path, provenance: &CodeqlDatabaseProvenance) -> Result<()> {
    let current = crate::remediation::patch::clean_repository_source_binding(
        target,
        crate::remediation::patch::unattended_patch_control(),
    )?;
    anyhow::ensure!(
        current.commit == provenance.source_commit && current.target_scope == provenance.target_scope,
        "managed CodeQL database was built for commit {} at scope {:?}, but the current clean source is commit {} at scope {:?}; run `codeql:create-db` again",
        provenance.source_commit,
        provenance.target_scope,
        current.commit,
        current.target_scope
    );
    Ok(())
}

fn validate_codeql_database_provenance(provenance: &CodeqlDatabaseProvenance) -> Result<()> {
    anyhow::ensure!(
        provenance.schema_version == CODEQL_PROVENANCE_SCHEMA_VERSION,
        "unsupported CodeQL provenance schema version {}",
        provenance.schema_version
    );
    anyhow::ensure!(
        matches!(provenance.source_commit.len(), 40 | 64)
            && provenance
                .source_commit
                .chars()
                .all(|ch| ch.is_ascii_hexdigit()),
        "CodeQL provenance source commit is not a full Git object ID"
    );
    crate::remediation::patch::validate_repository_target_scope(&provenance.target_scope)?;
    normalized_language(&provenance.language)?;
    uuid::Uuid::parse_str(&provenance.generation)
        .context("CodeQL provenance generation is not a UUID")?;
    Ok(())
}

fn normalized_language(language: &str) -> Result<String> {
    let language = language.trim().to_ascii_lowercase();
    anyhow::ensure!(
        !language.is_empty()
            && language
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')),
        "CodeQL provenance language is invalid"
    );
    Ok(language)
}

fn path_exists_no_follow(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "managed CodeQL database path is a symbolic link: {}",
                path.display()
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
}

fn reject_legacy_database(target: &Path) -> Result<()> {
    for legacy in [
        crate::workspace::legacy_workspace_codeql_db_path(target),
        crate::workspace::legacy_codeql_db_path(target),
    ] {
        if path_exists_no_follow(&legacy)? {
            anyhow::bail!(
                "legacy CodeQL database at {} has no source provenance; rebuild it with `codeql:create-db`",
                legacy.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn write_test_codeql_database_provenance(
    database: &Path,
    target: &Path,
    language: &str,
) {
    let operator_home = register_test_operator_home(target);
    crate::workspace::initialize_workspace_state(target).unwrap();
    let binding = crate::remediation::patch::clean_repository_source_binding(
        target,
        crate::remediation::patch::unattended_patch_control(),
    )
    .unwrap();
    let provenance = write_codeql_database_provenance(database, &binding, language).unwrap();
    let identity = super::promotion::database_identity(database).unwrap();
    write_codeql_promotion_receipt_at(&operator_home, target, &provenance, &identity).unwrap();
}

#[cfg(test)]
#[derive(Default)]
struct TestOperatorHomes {
    roots: Vec<tempfile::TempDir>,
    by_target: std::collections::HashMap<PathBuf, PathBuf>,
}

#[cfg(test)]
fn test_operator_homes() -> &'static std::sync::Mutex<TestOperatorHomes> {
    static HOMES: std::sync::OnceLock<std::sync::Mutex<TestOperatorHomes>> =
        std::sync::OnceLock::new();
    HOMES.get_or_init(Default::default)
}

#[cfg(test)]
fn register_test_operator_home(target: &Path) -> PathBuf {
    let target = std::fs::canonicalize(target).unwrap();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().to_path_buf();
    let mut homes = test_operator_homes().lock().unwrap();
    homes.by_target.insert(target, path.clone());
    homes.roots.push(root);
    path
}

#[cfg(test)]
fn test_operator_home(target: &Path) -> Option<PathBuf> {
    let target = std::fs::canonicalize(target).ok()?;
    test_operator_homes()
        .lock()
        .ok()?
        .by_target
        .get(&target)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_database_requires_current_commit_provenance() {
        let repository = initialized_repository();
        let database = make_database(repository.path(), "javascript");
        write_test_codeql_database_provenance(&database, repository.path(), "javascript");

        let current = resolve_managed_codeql_database(repository.path())
            .unwrap()
            .unwrap();
        assert_eq!(current.path(), database);
        assert_eq!(current.provenance.language, "javascript");
        drop(current);

        std::fs::write(repository.path().join("source.js"), "const value = 2;\n").unwrap();
        commit_all(repository.path(), "next");
        let error = resolve_managed_codeql_database(repository.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("built for commit"), "{error}");
        assert!(error.contains("codeql:create-db"), "{error}");
    }

    #[test]
    fn managed_database_rejects_missing_provenance() {
        let repository = initialized_repository();
        make_database(repository.path(), "cpp");

        let error = resolve_managed_codeql_database(repository.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("trusted provenance"), "{error}");
    }

    #[test]
    fn managed_database_rejects_self_asserted_target_provenance() {
        let repository = initialized_repository();
        let database = make_database(repository.path(), "javascript");
        let operator_home = register_test_operator_home(repository.path());
        let binding = crate::remediation::patch::clean_repository_source_binding(
            repository.path(),
            crate::remediation::patch::unattended_patch_control(),
        )
        .unwrap();
        write_codeql_database_provenance(&database, &binding, "javascript").unwrap();

        let error = resolve_managed_codeql_database(repository.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("operator promotion receipt"), "{error}");
        assert!(!operator_home.join(receipt_relative_dir()).exists());
    }

    #[test]
    fn managed_database_rejects_content_changed_after_operator_receipt() {
        let repository = initialized_repository();
        let database = make_database(repository.path(), "javascript");
        write_test_codeql_database_provenance(&database, repository.path(), "javascript");
        std::fs::write(database.join("db-javascript/forged.bin"), b"forged").unwrap();

        let error = resolve_managed_codeql_database(repository.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("does not match"), "{error}");
        assert!(error.contains("codeql:create-db"), "{error}");
    }

    #[test]
    fn receipt_writer_does_not_bless_a_live_database_mutation() {
        let repository = initialized_repository();
        let database = make_database(repository.path(), "javascript");
        let operator_home = register_test_operator_home(repository.path());
        let binding = crate::remediation::patch::clean_repository_source_binding(
            repository.path(),
            crate::remediation::patch::unattended_patch_control(),
        )
        .unwrap();
        let provenance =
            write_codeql_database_provenance(&database, &binding, "javascript").unwrap();
        let promoted_identity = super::super::promotion::database_identity(&database).unwrap();
        std::fs::write(database.join("db-javascript/forged.bin"), b"forged").unwrap();

        write_codeql_promotion_receipt_at(
            &operator_home,
            repository.path(),
            &provenance,
            &promoted_identity,
        )
        .unwrap();

        let error = resolve_managed_codeql_database(repository.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not match"), "{error}");
    }

    #[test]
    fn managed_database_lease_rejects_mutation_during_use() {
        let repository = initialized_repository();
        let database = make_database(repository.path(), "javascript");
        let chunk = database.join("db-javascript/chunk.bin");
        std::fs::write(&chunk, b"AAAA").unwrap();
        write_test_codeql_database_provenance(&database, repository.path(), "javascript");
        let managed = resolve_managed_codeql_database(repository.path())
            .unwrap()
            .unwrap();

        let error = managed
            .run_verified(|_| {
                std::fs::write(&chunk, b"BBBB")?;
                Ok(())
            })
            .unwrap_err()
            .to_string();

        assert!(error.contains("changed while in use"), "{error}");
    }

    #[test]
    fn managed_database_lease_holds_the_publication_lock() {
        let repository = initialized_repository();
        let database = make_database(repository.path(), "javascript");
        write_test_codeql_database_provenance(&database, repository.path(), "javascript");
        let managed = resolve_managed_codeql_database(repository.path())
            .unwrap()
            .unwrap();
        let relative = database.strip_prefix(repository.path()).unwrap();
        let lock_path = super::super::destination_lock_path(repository.path(), relative).unwrap();

        assert!(crate::file_lock::ExclusiveFileLock::try_acquire(&lock_path)
            .unwrap()
            .is_none());
        drop(managed);
        assert!(crate::file_lock::ExclusiveFileLock::try_acquire(&lock_path)
            .unwrap()
            .is_some());
    }

    #[test]
    fn receipt_store_must_not_be_inside_the_target() {
        let operator_home = tempfile::tempdir().unwrap();

        let error = receipt_path(operator_home.path(), operator_home.path(), "target")
            .unwrap_err()
            .to_string();

        assert!(error.contains("overlaps"), "{error}");
    }

    #[test]
    fn target_must_not_be_inside_the_receipt_store() {
        let operator_home = tempfile::tempdir().unwrap();
        let receipt_store = operator_home.path().join(receipt_relative_dir());
        let target = receipt_store.join("target");
        std::fs::create_dir_all(&target).unwrap();

        let error = receipt_path(operator_home.path(), &target, "target")
            .unwrap_err()
            .to_string();

        assert!(error.contains("overlaps"), "{error}");
    }

    #[test]
    fn legacy_database_is_never_accepted_without_provenance() {
        let repository = initialized_repository();
        std::fs::create_dir_all(crate::workspace::legacy_codeql_db_path(repository.path()))
            .unwrap();

        let error = resolve_managed_codeql_database(repository.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("legacy CodeQL database"), "{error}");
    }

    fn initialized_repository() -> tempfile::TempDir {
        let repository = tempfile::tempdir().unwrap();
        run_git(repository.path(), &["init", "-q"]);
        std::fs::write(repository.path().join("source.js"), "const value = 1;\n").unwrap();
        commit_all(repository.path(), "initial");
        repository
    }

    fn make_database(target: &Path, language: &str) -> PathBuf {
        crate::workspace::initialize_workspace_state(target).unwrap();
        let database = crate::workspace::workspace_codeql_db_path(target);
        std::fs::create_dir_all(database.join(format!("db-{language}"))).unwrap();
        std::fs::write(
            database.join("codeql-database.yml"),
            format!("primaryLanguage: {language}\n"),
        )
        .unwrap();
        database
    }

    fn commit_all(repository: &Path, message: &str) {
        run_git(repository, &["add", "source.js"]);
        run_git(repository, &["commit", "-qm", message]);
    }

    fn run_git(repository: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(["-c", "user.email=test@example.invalid"])
            .args(["-c", "user.name=Kuzushi Test"])
            .args(args)
            .current_dir(repository)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }
}
