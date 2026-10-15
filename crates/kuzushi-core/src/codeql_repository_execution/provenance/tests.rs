use super::receipts::{receipt_path, receipt_relative_dir, write_codeql_promotion_receipt_at};
use super::*;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Default)]
struct TestOperatorHomes {
    roots: Vec<tempfile::TempDir>,
    by_target: HashMap<PathBuf, PathBuf>,
}

fn test_operator_homes() -> &'static Mutex<TestOperatorHomes> {
    static HOMES: OnceLock<Mutex<TestOperatorHomes>> = OnceLock::new();
    HOMES.get_or_init(Default::default)
}

pub(super) fn register_test_operator_home(target: &Path) -> PathBuf {
    let target = std::fs::canonicalize(target).unwrap();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().to_path_buf();
    let mut homes = test_operator_homes().lock().unwrap();
    homes.by_target.insert(target, path.clone());
    homes.roots.push(root);
    path
}

pub(super) fn test_operator_home(target: &Path) -> Option<PathBuf> {
    let target = std::fs::canonicalize(target).ok()?;
    test_operator_homes()
        .lock()
        .ok()?
        .by_target
        .get(&target)
        .cloned()
}

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
    let identity = super::super::promotion::database_identity(database).unwrap();
    write_codeql_promotion_receipt_at(&operator_home, target, &provenance, &identity).unwrap();
}

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

    assert!(
        error.starts_with("CodeQL database has no trusted provenance"),
        "{error}"
    );
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
    let provenance = write_codeql_database_provenance(&database, &binding, "javascript").unwrap();
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
    std::fs::create_dir_all(crate::workspace::legacy_codeql_db_path(repository.path())).unwrap();

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
