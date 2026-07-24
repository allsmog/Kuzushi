use super::*;

#[test]
fn empty_target_returns_only_constants() {
    let tmp = tempfile::tempdir().unwrap();
    let plan = try_mcp_attachment_plan_for_target(tmp.path()).unwrap();
    assert_eq!(plan.len(), MCP_CONSTANT_NAMES.len());
    for name in MCP_CONSTANT_NAMES {
        assert!(plan_contains(&plan, name), "missing constant {name}");
    }
}

#[test]
fn context_artifact_attaches_context_server() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join(".kuzushi")).unwrap();
    std::fs::write(
        tmp.path().join(".kuzushi/context-snapshot.json"),
        "{\"target\":\"x\"}",
    )
    .unwrap();
    let plan = try_mcp_attachment_plan_for_target(tmp.path()).unwrap();
    assert!(plan_contains(&plan, "context"));
    assert!(!plan_contains(&plan, "joern"));
    assert!(!plan_contains(&plan, "codeql"));
}

#[test]
fn cpg_attaches_joern_only_when_binary_present() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join(".kuzushi")).unwrap();
    std::fs::write(tmp.path().join(".kuzushi/cpg.bin"), b"CPG\0bin").unwrap();
    let plan = try_mcp_attachment_plan_for_target(tmp.path()).unwrap();
    assert!(plan_contains(&plan, "joern"));
    assert!(!plan_contains(&plan, "codeql"));
}

#[test]
fn authenticated_codeql_database_attaches_at_managed_path() {
    let repository = initialized_repository();
    let database = make_database(repository.path(), "rust");
    crate::codeql_repository_execution::write_test_codeql_database_provenance(
        &database,
        repository.path(),
        "rust",
    );

    let plan = try_mcp_attachment_plan_for_target(repository.path()).unwrap();
    let attachment = plan
        .iter()
        .find(|attachment| attachment.name == "codeql")
        .unwrap();

    assert_eq!(attachment.artifact_path, database.display().to_string());
    assert!(attachment.artifact_identity.as_ref().is_some_and(|identity| identity.len() == 64));
    assert_eq!(database, crate::workspace::workspace_codeql_db_path(repository.path()));
}

#[test]
fn marker_only_database_is_rejected() {
    let repository = initialized_repository();
    make_database(repository.path(), "rust");

    let error = try_mcp_attachment_plan_for_target(repository.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("trusted provenance"), "{error}");
    assert!(error.contains("codeql:create-db"), "{error}");
}

#[test]
fn unversioned_managed_database_is_rejected_as_legacy() {
    let repository = initialized_repository();
    let database = crate::workspace::legacy_workspace_codeql_db_path(repository.path());
    std::fs::create_dir_all(database.join("db-rust")).unwrap();
    std::fs::write(
        database.join("codeql-database.yml"),
        "primaryLanguage: rust\n",
    )
    .unwrap();

    let error = try_mcp_attachment_plan_for_target(repository.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("legacy CodeQL database"), "{error}");
    assert!(error.contains("codeql:create-db"), "{error}");
}

#[test]
fn database_without_operator_receipt_is_rejected() {
    let repository = initialized_repository();
    let database = make_database(repository.path(), "rust");
    write_self_asserted_provenance(repository.path(), &database, "rust");

    let error = try_mcp_attachment_plan_for_target(repository.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("operator promotion receipt"), "{error}");
    assert!(error.contains("codeql:create-db"), "{error}");
}

#[test]
fn stale_managed_database_is_rejected() {
    let repository = initialized_repository();
    let database = make_database(repository.path(), "rust");
    crate::codeql_repository_execution::write_test_codeql_database_provenance(
        &database,
        repository.path(),
        "rust",
    );
    std::fs::write(repository.path().join("source.rs"), "fn main() { println!(\"next\"); }\n")
        .unwrap();
    commit_all(repository.path(), "next");

    let error = try_mcp_attachment_plan_for_target(repository.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("built for commit"), "{error}");
    assert!(error.contains("codeql:create-db"), "{error}");
}

#[test]
fn malformed_artifact_does_not_attach() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join(".kuzushi")).unwrap();
    std::fs::write(
        tmp.path().join(".kuzushi/context-snapshot.json"),
        "{not json",
    )
    .unwrap();
    let plan = try_mcp_attachment_plan_for_target(tmp.path()).unwrap();
    assert!(!plan_contains(&plan, "context"));
}

#[test]
fn plan_ordering_is_stable() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join(".kuzushi")).unwrap();
    std::fs::write(tmp.path().join(".kuzushi/context-snapshot.json"), "{}").unwrap();
    std::fs::write(tmp.path().join(".kuzushi/cpg.bin"), b"CPG").unwrap();
    let first = try_mcp_attachment_plan_for_target(tmp.path()).unwrap();
    let second = try_mcp_attachment_plan_for_target(tmp.path()).unwrap();
    assert_eq!(first, second);
    let names: Vec<_> = first.iter().map(|a| a.name.as_str()).collect();
    let treesitter = names.iter().position(|name| *name == "treesitter").unwrap();
    let context = names.iter().position(|name| *name == "context").unwrap();
    assert!(treesitter < context);
}

fn initialized_repository() -> tempfile::TempDir {
    let repository = tempfile::tempdir().unwrap();
    run_git(repository.path(), &["init", "-q"]);
    std::fs::write(repository.path().join("source.rs"), "fn main() {}\n").unwrap();
    commit_all(repository.path(), "initial");
    repository
}

fn make_database(target: &Path, language: &str) -> std::path::PathBuf {
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

fn write_self_asserted_provenance(target: &Path, database: &Path, language: &str) {
    let commit = git_output(target, &["rev-parse", "HEAD"]);
    let provenance = serde_json::json!({
        "schemaVersion": 1,
        "sourceCommit": commit,
        "targetScope": ".",
        "language": language,
        "generation": uuid::Uuid::new_v4().to_string(),
    });
    std::fs::write(
        database.join(".kuzushi-provenance.json"),
        serde_json::to_vec_pretty(&provenance).unwrap(),
    )
    .unwrap();
}

fn commit_all(repository: &Path, message: &str) {
    run_git(repository, &["add", "source.rs"]);
    run_git(repository, &["commit", "-qm", message]);
}

fn git_output(repository: &Path, args: &[&str]) -> String {
    let output = git_command(repository, args).output().unwrap();
    assert!(output.status.success(), "git {args:?} failed");
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn run_git(repository: &Path, args: &[&str]) {
    let status = git_command(repository, args).status().unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn git_command(repository: &Path, args: &[&str]) -> std::process::Command {
    let mut command = std::process::Command::new("git");
    command
        .args(["-c", "user.email=test@example.invalid"])
        .args(["-c", "user.name=Kuzushi Test"])
        .args(args)
        .current_dir(repository);
    command
}
