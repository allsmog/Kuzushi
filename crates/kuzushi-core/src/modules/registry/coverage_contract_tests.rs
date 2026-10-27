use crate::modules::{ModuleRegistry, RuntimeRequirement, ToolPhase, WorkflowPhase};
use crate::run_artifacts::RunTargetGitMetadata;
use crate::workspace::coverage_ledger::{BaselineRow, CoverageLedger};
use crate::{ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;
mod history_reads;
mod source_comparison;

fn context<'a>(config: &'a V2Config, workspace: &'a WorkspaceTarget) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

fn dispatch(workspace: &WorkspaceTarget, tool: &str, input: Value) -> anyhow::Result<Value> {
    let config = V2Config::default();
    let ctx = context(&config, workspace);
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input(tool, input, &ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

fn git(root: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn owned_repository() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join(".gitignore"),
        "# Workspace maintains local state ignore rules.\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("hello.txt"),
        "Owned inert metadata fixture.\n",
    )
    .unwrap();
    git(root.path(), &["init", "--initial-branch=main"]);
    git(root.path(), &["add", ".gitignore", "hello.txt"]);
    git(
        root.path(),
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            "Owned source fixture",
        ],
    );
    root
}

fn seed(workspace: &WorkspaceTarget) -> String {
    let sha = git(workspace.root(), &["rev-parse", "HEAD"]);
    CoverageLedger::open(workspace.root())
        .unwrap()
        .record_baseline(&BaselineRow {
            scope_id: "root".into(),
            phase: WorkflowPhase::Scan,
            mode: "owned-metadata".into(),
            run_id: "synthetic-history-not-a-scan".into(),
            revision: RunTargetGitMetadata {
                sha: sha.clone(),
                branch: Some("main".into()),
                dirty: false,
            },
            ts_unix: 1,
        })
        .unwrap();
    sha
}

#[test]
fn cancelled_sweep_cannot_advance_historical_baselines() {
    let root = owned_repository();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    seed(&workspace);
    git(
        root.path(),
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.test",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--allow-empty",
            "-m",
            "Owned metadata revision",
        ],
    );
    let config = V2Config::default();
    let cancellation = crate::ScanCancellation::default();
    let mut ctx = context(&config, &workspace);
    ctx.cancellation = Some(&cancellation);
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input("coverage:sweep", json!({"writeSkips":true}), &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    cancellation.cancel();
    let result = registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None);
    let rows = CoverageLedger::open_if_exists(root.path())
        .unwrap()
        .unwrap()
        .all_baselines()
        .unwrap();
    assert_eq!(rows.len(), 1, "Cancellation must preserve historical rows");
    assert!(format!("{:#}", result.unwrap_err()).contains("cancel"));
}

#[test]
fn coverage_descriptors_are_operational_and_cannot_complete_map() {
    let registry = ModuleRegistry::with_v2_builtins();
    for name in ["coverage:baselines", "coverage:sweep", "coverage:recommend"] {
        let descriptor = registry.resolve_tool(name).unwrap();
        assert_eq!(descriptor.phase, ToolPhase::Operate);
        assert!(!descriptor.phase_result);
        assert_eq!(descriptor.runtime_requirement, RuntimeRequirement::Never);
        assert!(descriptor.headless);
    }
}

#[test]
fn prepared_dispatch_keeps_full_sha_and_disclaims_coverage_and_fix_verdicts() {
    let root = owned_repository();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let sha = seed(&workspace);
    let baseline = dispatch(&workspace, "coverage:baselines", json!({})).unwrap();
    assert_eq!(baseline["data"]["baselines"][0]["revisionSha"], sha);
    assert_eq!(baseline["data"]["scopeCoverageVerified"], false);
    assert!(baseline["output"].as_str().unwrap().contains(&sha));
    let sweep = dispatch(&workspace, "coverage:sweep", json!({})).unwrap();
    assert_eq!(
        sweep["data"]["report"]["entries"][0]["verdict"]["kind"],
        "current"
    );
    assert_eq!(sweep["data"]["scopeCoverageVerified"], false);
    assert_eq!(sweep["data"]["findingFixVerified"], false);
    assert!(sweep["output"]
        .as_str()
        .unwrap()
        .contains("tracked source unchanged"));
    std::fs::write(root.path().join("hello.txt"), "Owned uncommitted edit.\n").unwrap();
    let dirty = dispatch(&workspace, "coverage:sweep", json!({})).unwrap();
    assert_eq!(dirty["data"]["report"]["head"]["sha"], sha);
    assert_eq!(
        dirty["data"]["report"]["entries"][0]["verdict"],
        json!({"kind":"source-unverified", "reason":"dirty-working-tree"})
    );
    assert!(dispatch(&workspace, "coverage:sweep", json!({"write-skips":true})).is_err());
    assert_eq!(
        CoverageLedger::open(root.path())
            .unwrap()
            .all_baselines()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn undeclared_inputs_fail_before_creating_a_coverage_database() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = context(&config, &workspace);
    let registry = ModuleRegistry::with_v2_builtins();
    for name in ["coverage:baselines", "coverage:sweep", "coverage:recommend"] {
        assert!(registry
            .prepare_dispatch_input(name, json!({"createJobs":true}), &ctx, None)
            .is_err());
    }
    assert!(!crate::workspace::coverage_ledger::workspace_coverage_db_path(root.path()).exists());
}

#[test]
fn unreadable_git_state_returns_an_error_without_a_clean_claim() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    assert!(dispatch(&workspace, "coverage:sweep", json!({})).is_err());
    let baselines = dispatch(&workspace, "coverage:baselines", json!({})).unwrap();
    assert_eq!(baselines["data"]["baselines"], json!([]));
    assert!(baselines["output"]
        .as_str()
        .unwrap()
        .contains("Historical Git baseline records: 0"));
}
