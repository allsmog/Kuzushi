use super::*;

#[test]
fn transient_policy_verification_is_retried_once() {
    let mut attempts = 0;
    let result = retry_policy_verification(|| {
        attempts += 1;
        if attempts == 1 {
            anyhow::bail!("inputs changed")
        }
        Ok("stable")
    })
    .unwrap();

    assert_eq!(result, "stable");
    assert_eq!(attempts, 2);
}

#[test]
fn repeated_policy_verification_failure_remains_an_error() {
    let mut attempts = 0;
    let error = retry_policy_verification::<()>(|| {
        attempts += 1;
        anyhow::bail!("still changing")
    })
    .unwrap_err()
    .to_string();

    assert_eq!(attempts, 2);
    assert!(error.contains("first attempt"), "{error}");
}
use std::process::{Command, Output};

#[test]
fn non_git_initialization_creates_valid_policy_before_v3() {
    let workspace = tempfile::tempdir().unwrap();

    let state_dir = initialize_workspace_state(workspace.path()).unwrap();

    assert_eq!(
        state_dir,
        fs::canonicalize(workspace.path())
            .unwrap()
            .join(".kuzushi/v3")
    );
    assert_eq!(
        fs::read(workspace.path().join(".kuzushi/.gitignore")).unwrap(),
        DEFAULT_IGNORE_POLICY
    );
}

#[test]
fn non_git_initialization_preserves_valid_custom_policy_bytes() {
    let workspace = tempfile::tempdir().unwrap();
    let state_root = workspace.path().join(".kuzushi");
    fs::create_dir(&state_root).unwrap();
    let custom =
        b"# operator policy\n*\n!scope.toml\n!prompts/\n!prompts/**\n!v3/\nv3/*\n!v3/config.toml\n";
    fs::write(state_root.join(".gitignore"), custom).unwrap();

    initialize_workspace_state(workspace.path()).unwrap();

    assert_eq!(fs::read(state_root.join(".gitignore")).unwrap(), custom);
}

#[test]
fn concurrent_first_use_only_publishes_a_complete_policy() {
    const WRITERS: usize = 32;
    let workspace = tempfile::tempdir().unwrap();
    let root = std::sync::Arc::new(workspace.path().to_path_buf());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
    let writers = (0..WRITERS)
        .map(|_| {
            let root = std::sync::Arc::clone(&root);
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                initialize_workspace_state(root.as_path())
            })
        })
        .collect::<Vec<_>>();

    for writer in writers {
        assert!(writer.join().unwrap().is_ok());
    }
    assert_eq!(
        fs::read(workspace.path().join(".kuzushi/.gitignore")).unwrap(),
        DEFAULT_IGNORE_POLICY
    );
}

#[test]
fn empty_or_insufficient_policy_fails_before_v3_creation() {
    for policy in [b"".as_slice(), b"v3/runs/\n".as_slice()] {
        let workspace = tempfile::tempdir().unwrap();
        let state_root = workspace.path().join(".kuzushi");
        fs::create_dir(&state_root).unwrap();
        fs::write(state_root.join(".gitignore"), policy).unwrap();

        let error = initialize_workspace_state(workspace.path())
            .unwrap_err()
            .to_string();

        assert!(error.contains("ignore policy"), "{error}");
        assert!(!state_root.join("v3").exists());
        assert_eq!(fs::read(state_root.join(".gitignore")).unwrap(), policy);
    }
}

#[test]
fn directory_ignore_node_fails_before_v3_creation() {
    let workspace = tempfile::tempdir().unwrap();
    let ignore_path = workspace.path().join(".kuzushi/.gitignore");
    fs::create_dir_all(&ignore_path).unwrap();

    let error = initialize_workspace_state(workspace.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("regular file"), "{error}");
    assert!(!workspace.path().join(".kuzushi/v3").exists());
}

#[cfg(unix)]
#[test]
fn symlinked_ignore_node_never_writes_outside_workspace() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    fs::write(outside.path(), "outside sentinel").unwrap();
    fs::create_dir(workspace.path().join(".kuzushi")).unwrap();
    symlink(outside.path(), workspace.path().join(".kuzushi/.gitignore")).unwrap();

    assert!(initialize_workspace_state(workspace.path()).is_err());
    assert_eq!(
        fs::read_to_string(outside.path()).unwrap(),
        "outside sentinel"
    );
    assert!(!workspace.path().join(".kuzushi/v3").exists());
}

#[cfg(unix)]
#[test]
fn symlinked_state_root_never_writes_outside_workspace() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), workspace.path().join(".kuzushi")).unwrap();

    assert!(initialize_workspace_state(workspace.path()).is_err());
    assert!(!outside.path().join(".gitignore").exists());
    assert!(!outside.path().join("v3").exists());
}

#[test]
fn expanded_generated_surface_cannot_be_left_trackable() {
    for (path, exceptions) in [
        (".gitignore", "!.gitignore\n"),
        ("v3/latest", "!v3/latest\n"),
        (
            "v3/run-history.index.sqlite3",
            "!v3/run-history.index.sqlite3\n",
        ),
        (
            "v3/run-history.index.dirty",
            "!v3/run-history.index.dirty\n",
        ),
        ("v3/log/**", "!v3/log/\n!v3/log/**\n"),
        ("v3/objects/**", "!v3/objects/\n!v3/objects/**\n"),
        ("v3/index.sqlite3", "!v3/index.sqlite3\n"),
        ("v3/runs/**", "!v3/runs/\n!v3/runs/**\n"),
        ("worktrees/**", "!worktrees/\n!worktrees/**\n"),
    ] {
        let workspace = tempfile::tempdir().unwrap();
        let state_root = workspace.path().join(".kuzushi");
        fs::create_dir(&state_root).unwrap();
        let mut policy = DEFAULT_IGNORE_POLICY.to_vec();
        policy.extend_from_slice(exceptions.as_bytes());
        fs::write(state_root.join(".gitignore"), &policy).unwrap();

        let error = initialize_workspace_state(workspace.path())
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("leave trackable")
                || error.contains("must ignore")
                || error.contains("may only"),
            "{path}: {error}"
        );
        assert!(!state_root.join("v3").exists());
    }
}

#[test]
fn exact_probe_allowlist_does_not_establish_generated_tree_ownership() {
    let workspace = tempfile::tempdir().unwrap();
    let state_root = workspace.path().join(".kuzushi");
    fs::create_dir(&state_root).unwrap();
    let policy = b".gitignore\nv3/latest\nv3/run-history.index.sqlite3\nv3/run-history.index.dirty\nv3/index.sqlite3\nv3/log/**\nv3/objects/**\nv3/runs/**\nworktrees/**\n!scope.toml\n!prompts/\n!prompts/**\n!v3/config.toml\n";
    fs::write(state_root.join(".gitignore"), policy).unwrap();

    let error = initialize_workspace_state(workspace.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("by construction"), "{error}");
    assert!(!state_root.join("v3").exists());
}

#[test]
fn directory_only_root_rule_does_not_establish_file_ownership() {
    let workspace = committed_repository();
    let policy =
        b".gitignore\n*/\n!scope.toml\n!prompts/\n!prompts/**\n!v3/\nv3/*\n!v3/config.toml\n";
    commit_workspace_policy(workspace.path(), policy);

    let error = initialize_workspace_state(workspace.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("`*`"), "{error}");
    assert!(!workspace.path().join(".kuzushi/v3").exists());
    assert_eq!(
        fs::read(workspace.path().join(".kuzushi/.gitignore")).unwrap(),
        policy
    );
    assert_git_clean(workspace.path());
}

#[test]
fn directory_only_v3_rule_does_not_establish_file_ownership() {
    let workspace = committed_repository();
    let policy = b".gitignore\n*\n!scope.toml\n!prompts/\n!prompts/**\n!v3/\nv3/latest\nv3/run-history.index.sqlite3\nv3/run-history.index.dirty\nv3/index.sqlite3\nv3/log/\nv3/objects/\nv3/runs/\nv3/*/\n!v3/config.toml\n";
    commit_workspace_policy(workspace.path(), policy);

    let error = initialize_workspace_state(workspace.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("`v3/*`"), "{error}");
    assert!(!workspace.path().join(".kuzushi/v3").exists());
    assert_eq!(
        fs::read(workspace.path().join(".kuzushi/.gitignore")).unwrap(),
        policy
    );
    assert_git_clean(workspace.path());
}

#[test]
fn generated_tree_rule_rejects_later_cross_tree_negation() {
    let workspace = tempfile::tempdir().unwrap();
    let state_root = workspace.path().join(".kuzushi");
    fs::create_dir(&state_root).unwrap();
    let policy = b"*\n!scope.toml\n!prompts/\n!prompts/**\n!v3/\nv3/*\n!v3/config.toml\n!*.json\n";
    fs::write(state_root.join(".gitignore"), policy).unwrap();

    let error = initialize_workspace_state(workspace.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("may only negate"), "{error}");
    assert!(!state_root.join("v3").exists());
}

#[test]
fn git_first_use_run_and_database_state_stay_clean() {
    let workspace = committed_repository();
    let summary = crate::run_artifacts::RunSummary::running(
        "first-run",
        "run",
        Some("catalog:tools".to_string()),
        workspace.path().display().to_string(),
    );

    crate::run_artifacts::write_run_summary(workspace.path(), &summary).unwrap();
    crate::findings::FindingStore::open(workspace.path().join(".kuzushi/v3/index.sqlite3"))
        .unwrap();

    assert!(git(workspace.path(), &["status", "--porcelain"])
        .stdout
        .is_empty());
    assert_probe(workspace.path(), ".kuzushi/v3/runs/probe", 0);
    assert_probe(workspace.path(), ".kuzushi/scope.toml", 1);
    assert_probe(workspace.path(), ".kuzushi/prompts/probe.md", 1);
    assert_probe(workspace.path(), ".kuzushi/v3/config.toml", 1);
}

#[test]
fn git_first_use_finding_store_initializes_policy_before_database_state() {
    let workspace = committed_repository();
    let database = workspace.path().join(".kuzushi/v3/index.sqlite3");

    crate::findings::FindingStore::open(&database).unwrap();

    assert!(workspace.path().join(".kuzushi/.gitignore").is_file());
    assert!(database.is_file());
    assert!(git(workspace.path(), &["status", "--porcelain"])
        .stdout
        .is_empty());
}

#[test]
fn cached_proof_revalidates_changed_parent_ignore_policy() {
    let workspace = committed_repository();
    initialize_workspace_state(workspace.path()).unwrap();
    fs::write(workspace.path().join(".gitignore"), ".kuzushi/\n").unwrap();

    let error = crate::workspace::write_workspace_state_file(
        workspace.path(),
        ".kuzushi/v3/options.json",
        b"{}",
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("hides trackable"), "{error}");
    assert!(!workspace.path().join(".kuzushi/v3/options.json").exists());
}

#[test]
fn cached_proof_revalidates_git_info_exclude() {
    let workspace = committed_repository();
    initialize_workspace_state(workspace.path()).unwrap();
    fs::write(workspace.path().join(".git/info/exclude"), ".kuzushi/\n").unwrap();

    let error = initialize_workspace_state(workspace.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("hides trackable"), "{error}");
}

#[test]
fn cached_proof_revalidates_included_git_config() {
    let workspace = committed_repository();
    let git_dir = workspace.path().join(".git");
    let include_path = git_dir.join("kuzushi-policy.inc");
    let exclude_path = git_dir.join("kuzushi-excludes");
    fs::write(&include_path, "[alias]\nfixture = status\n").unwrap();
    append_file(
        &git_dir.join("config"),
        "\n[include]\npath = kuzushi-policy.inc\n",
    );
    initialize_workspace_state(workspace.path()).unwrap();
    fs::write(&exclude_path, ".kuzushi/\n").unwrap();
    fs::write(
        &include_path,
        format!(
            "[core]\nexcludesFile = {}\n",
            exclude_path.to_string_lossy()
        ),
    )
    .unwrap();

    let error = initialize_workspace_state(workspace.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("hides trackable"), "{error}");
}

#[test]
fn cached_proof_revalidates_branch_conditional_git_config() {
    let workspace = committed_repository();
    let git_dir = workspace.path().join(".git");
    let include_path = git_dir.join("conditional-policy.inc");
    let exclude_path = git_dir.join("conditional-excludes");
    fs::write(&exclude_path, ".kuzushi/\n").unwrap();
    fs::write(
        &include_path,
        format!(
            "[core]\nexcludesFile = {}\n",
            exclude_path.to_string_lossy()
        ),
    )
    .unwrap();
    append_file(
        &git_dir.join("config"),
        "\n[includeIf \"onbranch:workspace-policy\"]\npath = conditional-policy.inc\n",
    );
    initialize_workspace_state(workspace.path()).unwrap();
    git_ok(
        workspace.path(),
        &["checkout", "-q", "-b", "workspace-policy"],
    );

    let error = initialize_workspace_state(workspace.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("hides trackable"), "{error}");
}

#[test]
fn cached_proof_revalidates_descendant_gitignore_policy() {
    let workspace = committed_repository();
    initialize_workspace_state(workspace.path()).unwrap();
    fs::write(
        workspace.path().join(".kuzushi/v3/.gitignore"),
        "config.toml\n",
    )
    .unwrap();

    let error = initialize_workspace_state(workspace.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("Generated state subtree"), "{error}");
}

#[test]
fn cached_proof_rejects_nested_prompt_gitignore_without_touching_prompts() {
    let workspace = committed_repository();
    initialize_workspace_state(workspace.path()).unwrap();
    let policy_path = workspace.path().join(".kuzushi/.gitignore");
    let policy = fs::read(&policy_path).unwrap();
    let prompt_dir = workspace.path().join(".kuzushi/prompts/team/nested");
    fs::create_dir_all(&prompt_dir).unwrap();
    fs::write(prompt_dir.join(".gitignore"), "custom.md\n").unwrap();
    git_ok(
        workspace.path(),
        &["add", ".kuzushi/prompts/team/nested/.gitignore"],
    );
    git_ok(
        workspace.path(),
        &["commit", "-q", "-m", "nested prompt policy"],
    );
    let prompt_path = prompt_dir.join("custom.md");
    let prompt = b"Preserve this operator prompt exactly.\n";
    fs::write(&prompt_path, prompt).unwrap();
    assert_git_clean(workspace.path());

    let error = initialize_workspace_state(workspace.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("Trackable prompt tree"), "{error}");
    assert_eq!(fs::read(&prompt_path).unwrap(), prompt);
    assert_eq!(fs::read(policy_path).unwrap(), policy);
    assert_git_clean(workspace.path());
}

#[cfg(unix)]
#[test]
fn prompt_policy_walk_does_not_follow_directory_symlinks() {
    use std::os::unix::fs::symlink;

    let workspace = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    initialize_workspace_state(workspace.path()).unwrap();
    fs::create_dir_all(workspace.path().join(".kuzushi/prompts")).unwrap();
    fs::write(outside.path().join(".gitignore"), "*.md\n").unwrap();
    symlink(
        outside.path(),
        workspace.path().join(".kuzushi/prompts/external"),
    )
    .unwrap();

    initialize_workspace_state(workspace.path()).unwrap();

    assert_eq!(
        fs::read(outside.path().join(".gitignore")).unwrap(),
        b"*.md\n"
    );
}

#[test]
fn storage_writer_rejects_policy_before_creating_its_lock() {
    let workspace = committed_repository();
    let policy = b"v3/runs/\n";
    commit_workspace_policy(workspace.path(), policy);
    let log_dir = workspace.path().join(".kuzushi/v3/log");
    let projection_path = workspace.path().join(".kuzushi/v3/index.sqlite3");

    let error = crate::storage_v3::writer_actor::StorageWriterActor::commit_blocking(
        &log_dir,
        &projection_path,
        crate::storage_v3::writer_actor::WriterCommand::Control(
            crate::storage_v3::writer_actor::ControlCommand::Barrier,
        ),
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("ignore policy"), "{error}");
    assert!(!log_dir.join(".storage-writer.lock").exists());
    assert!(!workspace.path().join(".kuzushi/v3").exists());
    assert_eq!(
        fs::read(workspace.path().join(".kuzushi/.gitignore")).unwrap(),
        policy
    );
    assert_git_clean(workspace.path());
}

#[test]
fn direct_storage_writer_first_use_keeps_git_clean() {
    let workspace = committed_repository();
    let log_dir = workspace.path().join(".kuzushi/v3/log");
    let projection_path = workspace.path().join(".kuzushi/v3/index.sqlite3");

    crate::storage_v3::writer_actor::StorageWriterActor::commit_blocking(
        &log_dir,
        &projection_path,
        crate::storage_v3::writer_actor::WriterCommand::Control(
            crate::storage_v3::writer_actor::ControlCommand::Barrier,
        ),
    )
    .unwrap();

    assert!(workspace.path().join(".kuzushi/.gitignore").is_file());
    assert!(log_dir.join(".storage-writer.lock").is_file());
    assert_git_clean(workspace.path());
}

#[test]
fn direct_storage_writer_accepts_relative_workspace_state_paths() {
    const CHILD_FLAG: &str = "KUZUSHI_RELATIVE_STORAGE_WRITER_CHILD";
    if std::env::var_os(CHILD_FLAG).is_some() {
        crate::storage_v3::writer_actor::StorageWriterActor::commit_blocking(
            ".kuzushi/v3/log",
            ".kuzushi/v3/index.sqlite3",
            crate::storage_v3::writer_actor::WriterCommand::Control(
                crate::storage_v3::writer_actor::ControlCommand::Barrier,
            ),
        )
        .unwrap();
        return;
    }
    let workspace = tempfile::tempdir().unwrap();
    let module = module_path!().trim_start_matches("kuzushi_core::");
    let test_name =
        format!("{module}::direct_storage_writer_accepts_relative_workspace_state_paths");
    let output = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .current_dir(workspace.path())
        .env(CHILD_FLAG, "1")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "relative writer child failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(workspace.path().join(".kuzushi/.gitignore").is_file());
    assert!(workspace
        .path()
        .join(".kuzushi/v3/log/.storage-writer.lock")
        .is_file());
    assert!(workspace.path().join(".kuzushi/v3/index.sqlite3").is_file());
}

#[test]
fn direct_storage_writer_preserves_custom_policy_and_prompt_bytes() {
    let workspace = committed_repository();
    let policy = b"# operator-owned policy\n*\n!scope.toml\n!prompts/\n!prompts/**\n!v3/\nv3/*\n!v3/config.toml\n";
    commit_workspace_policy(workspace.path(), policy);
    let prompt_path = workspace.path().join(".kuzushi/prompts/custom.md");
    let prompt = b"Operator-owned prompt bytes stay unchanged.\n";
    fs::create_dir_all(prompt_path.parent().unwrap()).unwrap();
    fs::write(&prompt_path, prompt).unwrap();
    git_ok(workspace.path(), &["add", ".kuzushi/prompts/custom.md"]);
    git_ok(workspace.path(), &["commit", "-q", "-m", "custom prompt"]);

    crate::storage_v3::writer_actor::StorageWriterActor::commit_blocking(
        workspace.path().join(".kuzushi/v3/log"),
        workspace.path().join(".kuzushi/v3/index.sqlite3"),
        crate::storage_v3::writer_actor::WriterCommand::Control(
            crate::storage_v3::writer_actor::ControlCommand::Barrier,
        ),
    )
    .unwrap();

    assert_eq!(
        fs::read(workspace.path().join(".kuzushi/.gitignore")).unwrap(),
        policy
    );
    assert_eq!(fs::read(prompt_path).unwrap(), prompt);
    assert_git_clean(workspace.path());
}

#[test]
fn explicit_parent_credentials_ignore_allows_child_policy_to_own_state() {
    let workspace = committed_repository();
    fs::write(
        workspace.path().join(".gitignore"),
        ".kuzushi/credentials.json\n",
    )
    .unwrap();
    git_ok(workspace.path(), &["add", ".gitignore"]);
    git_ok(workspace.path(), &["commit", "-m", "credentials ignore"]);

    initialize_workspace_state(workspace.path()).unwrap();

    assert_probe(workspace.path(), ".kuzushi/credentials.json", 0);
    assert_probe(workspace.path(), ".kuzushi/v3/index.sqlite3", 0);
    assert_probe(workspace.path(), ".kuzushi/v3/config.toml", 1);
}

#[test]
fn linked_git_worktree_initializes_and_stays_clean() {
    let repository = committed_repository();
    let worktree_parent = tempfile::tempdir().unwrap();
    let worktree = worktree_parent.path().join("linked");
    git_ok(
        repository.path(),
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "workspace-policy-test",
            worktree.to_str().unwrap(),
        ],
    );

    initialize_workspace_state(&worktree).unwrap();

    assert!(git(&worktree, &["status", "--porcelain"]).stdout.is_empty());
    assert_probe(&worktree, ".kuzushi/v3/runs/probe", 0);
    assert_probe(&worktree, ".kuzushi/v3/config.toml", 1);
}

#[test]
fn parent_git_rule_that_hides_trackable_state_is_rejected() {
    let workspace = committed_repository();
    fs::write(workspace.path().join(".gitignore"), ".kuzushi/\n").unwrap();
    git_ok(workspace.path(), &["add", ".gitignore"]);
    git_ok(workspace.path(), &["commit", "-m", "parent ignore"]);

    let error = initialize_workspace_state(workspace.path())
        .unwrap_err()
        .to_string();

    assert!(error.contains("hides trackable"), "{error}");
    assert!(!workspace.path().join(".kuzushi/v3").exists());
}

fn committed_repository() -> tempfile::TempDir {
    let workspace = tempfile::tempdir().unwrap();
    git_ok(workspace.path(), &["init", "-q"]);
    git_ok(
        workspace.path(),
        &["config", "user.email", "test@example.com"],
    );
    git_ok(workspace.path(), &["config", "user.name", "Kuzushi Test"]);
    fs::write(workspace.path().join("README.md"), "fixture\n").unwrap();
    git_ok(workspace.path(), &["add", "README.md"]);
    git_ok(workspace.path(), &["commit", "-q", "-m", "initial"]);
    workspace
}

fn commit_workspace_policy(root: &Path, policy: &[u8]) {
    fs::create_dir(root.join(".kuzushi")).unwrap();
    fs::write(root.join(".kuzushi/.gitignore"), policy).unwrap();
    git_ok(root, &["add", "-f", ".kuzushi/.gitignore"]);
    git_ok(root, &["commit", "-q", "-m", "workspace policy"]);
    assert_git_clean(root);
}

fn assert_git_clean(root: &Path) {
    let output = git(root, &["status", "--porcelain", "--untracked-files=all"]);
    assert!(
        output.stdout.is_empty(),
        "workspace is dirty:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

fn assert_probe(root: &Path, path: &str, expected_code: i32) {
    let output = git(root, &["check-ignore", "--no-index", "-q", "--", path]);
    assert_eq!(output.status.code(), Some(expected_code), "probe {path}");
}

fn git_ok(root: &Path, arguments: &[&str]) {
    let output = git(root, arguments);
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn append_file(path: &Path, contents: &str) {
    use std::io::Write;

    let mut file = fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(contents.as_bytes()).unwrap();
}

fn git(root: &Path, arguments: &[&str]) -> Output {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .unwrap()
}
