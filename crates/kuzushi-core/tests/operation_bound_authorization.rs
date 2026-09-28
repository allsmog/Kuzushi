use kuzushi_core::{
    ExecutionAuthorization, ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget,
};
use serde_json::json;
use std::path::Path;
use std::process::Command;

fn context<'a>(
    config: &'a V2Config,
    workspace: Option<&'a WorkspaceTarget>,
    authorization: ExecutionAuthorization,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization,
    }
}

/// A bare README repository has no detectable build, and `patch:finding`
/// binds a validation plan at preparation; the patch inputs below therefore
/// name `testCmd` explicitly so these tests exercise authorization only.
fn initialize_repo(repo: &Path) {
    run_git(repo, &["init"]);
    std::fs::write(repo.join("README.md"), "snapshot one\n").unwrap();
    run_git(repo, &["add", "README.md"]);
    run_git(repo, &["commit", "-m", "initial"]);
}

fn run_git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(["-c", "user.email=kuzushi@example.invalid"])
        .args(["-c", "user.name=Kuzushi Test"])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn prepared_input_cannot_cross_registry_instances() {
    let first = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let second = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let config = V2Config::default();
    let ctx = context(&config, None, ExecutionAuthorization::default());
    let prepared = first
        .prepare_dispatch_input("catalog:tools", json!({}), &ctx, None)
        .unwrap();

    let error = second
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap_err()
        .to_string();

    assert!(
        error.contains("does not belong to this registry"),
        "{error}"
    );
}

#[test]
fn interactive_request_is_not_an_authorization_grant() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let temp = tempfile::tempdir().unwrap();
    initialize_repo(temp.path());
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let config = V2Config::default();
    let request_ctx = context(
        &config,
        Some(&workspace),
        ExecutionAuthorization::interactive_request(),
    );

    let error = registry
        .execute_tool(
            "patch:finding",
            json!({"fingerprint": "finding-1", "testCmd": "true"}),
            &request_ctx,
        )
        .unwrap_err()
        .to_string();

    assert!(error.contains("explicit operator authorization"), "{error}");
}

#[test]
fn prepared_operation_can_consume_one_interactive_request() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let temp = tempfile::tempdir().unwrap();
    initialize_repo(temp.path());
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&config, Some(&workspace), ExecutionAuthorization::default());
    let prepared = registry
        .prepare_dispatch_input(
            "patch:finding",
            json!({"fingerprint": "finding-1", "testCmd": "true"}),
            &ctx,
            None,
        )
        .unwrap()
        .authorize_requested(ExecutionAuthorization::interactive_request())
        .unwrap();

    let error = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap_err()
        .to_string();

    assert!(!error.contains("operator authorization"), "{error}");
    assert!(error.contains("findings store"), "{error}");
}

#[test]
fn prepared_input_is_bound_to_workspace_identity() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let first_workspace = WorkspaceTarget::new(first.path()).unwrap();
    let second_workspace = WorkspaceTarget::new(second.path()).unwrap();
    let config = V2Config::default();
    let first_ctx = context(
        &config,
        Some(&first_workspace),
        ExecutionAuthorization::default(),
    );
    let second_ctx = context(
        &config,
        Some(&second_workspace),
        ExecutionAuthorization::default(),
    );
    let prepared = registry
        .prepare_dispatch_input("workspace:status", json!({}), &first_ctx, None)
        .unwrap();

    let error = registry
        .dispatch_prepared_input_with_runtime(prepared, &second_ctx, None)
        .unwrap_err()
        .to_string();

    assert!(error.contains("input, or workspace"), "{error}");
}

#[test]
fn operation_authorization_rejects_head_movement_after_prepare() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let temp = tempfile::tempdir().unwrap();
    initialize_repo(temp.path());
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&config, Some(&workspace), ExecutionAuthorization::default());
    let prepared = registry
        .prepare_dispatch_input(
            "patch:finding",
            json!({"fingerprint": "finding-1", "testCmd": "true"}),
            &ctx,
            None,
        )
        .unwrap()
        .authorize_explicit_headless();
    std::fs::write(temp.path().join("README.md"), "snapshot two\n").unwrap();
    run_git(temp.path(), &["add", "README.md"]);
    run_git(temp.path(), &["commit", "-m", "move head"]);

    let error = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap_err()
        .to_string();

    assert!(
        error.contains("source binding changed after preparation"),
        "{error}"
    );
}
