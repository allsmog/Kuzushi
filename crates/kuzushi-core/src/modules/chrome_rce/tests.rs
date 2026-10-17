use super::*;
use crate::findings::FindingStore;
use crate::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};

struct Fixture {
    _root: tempfile::TempDir,
    workspace: WorkspaceTarget,
    store: FindingStore,
    config: V2Config,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("broker");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(
            source.join("owned.cc"),
            "// Owned inert token: DuplicateHandle. Never executed.\n".repeat(3),
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        Self {
            _root: root,
            workspace,
            store,
            config: V2Config::default(),
        }
    }

    fn context(&self) -> ToolExecutionContext<'_> {
        ToolExecutionContext {
            config: &self.config,
            workspace: Some(&self.workspace),
            findings_store: Some(&self.store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        }
    }
}

#[test]
fn declared_finding_limit_bounds_raw_observations_and_discloses_partial_inspection() {
    for (maximum, expected, status) in [(1, 1, "partial"), (3, 3, "partial"), (4, 3, "completed")] {
        let fixture = Fixture::new();
        let output = ModuleRegistry::with_v2_builtins()
            .execute_tool(
                "chrome-rce:scan",
                json!({"maxFindings":maximum}),
                &fixture.context(),
            )
            .unwrap();
        assert_eq!(output["status"], status);
        assert_eq!(output["data"]["count"], expected);
        assert_eq!(
            output["data"]["inspection"]["findingLimitReached"],
            status == "partial"
        );
        let run = output["data"]["persisted"]["runId"].as_str().unwrap();
        assert_eq!(
            fixture.store.run_status(run).unwrap().as_deref(),
            Some(status)
        );
        assert_eq!(
            fixture
                .store
                .count_finding_observations_for_scan_ids(&[run])
                .unwrap(),
            expected
        );
        assert_eq!(
            output["warnings"].as_array().unwrap().is_empty(),
            status == "completed"
        );
    }
}

#[test]
fn invalid_limits_are_refused_before_writes_and_declared_alias_uses_the_same_limit() {
    let fixture = Fixture::new();
    let registry = ModuleRegistry::with_v2_builtins();
    for value in [json!(0), json!(-1), json!("invalid")] {
        assert!(registry
            .prepare_dispatch_input(
                "chrome-rce:scan",
                json!({"maxFindings":value}),
                &fixture.context(),
                None
            )
            .is_err());
    }
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
    let output = registry
        .execute_tool(
            "chrome-rce:scan",
            json!({"max_findings":"1"}),
            &fixture.context(),
        )
        .unwrap();
    assert_eq!(output["status"], "partial");
    assert_eq!(output["data"]["count"], 1);
}

#[test]
fn experimental_scan_is_not_recommended_as_a_core_capability() {
    let registry = ModuleRegistry::with_v2_builtins();
    let scan = registry.resolve_tool("chrome-rce:scan").unwrap();
    assert_eq!(
        scan.effective_maturity(ModuleMaturity::Core),
        ModuleMaturity::Labs
    );
    assert!(registry.resolve_tool("chrome-rce:review-trigger").is_some());
}

fn git(root: &std::path::Path, args: &[&str]) -> String {
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let output = std::process::Command::new("git")
        .args([
            "-c",
            "commit.gpgSign=false",
            "-c",
            &format!("core.hooksPath={null}"),
            "-c",
            "user.name=Owned fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", null)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn committed_path_fixture() -> (Fixture, String, String) {
    let fixture = Fixture::new();
    let root = fixture.workspace.root();
    git(root, &["init", "--quiet"]);
    git(root, &["add", "."]);
    git(root, &["commit", "--quiet", "-m", "Record owned baseline"]);
    let base = git(root, &["rev-parse", "HEAD"]);
    for name in [
        "v8/src/maglev/owned café.cc",
        "v8/src/compiler/typer.cc",
        "docs/line\nbreak.md",
    ] {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "// Owned inert path metadata. Never executed.\n").unwrap();
    }
    git(root, &["add", "."]);
    git(
        root,
        &["commit", "--quiet", "-m", "Record owned changed paths"],
    );
    let head = git(root, &["rev-parse", "HEAD"]);
    std::fs::write(
        root.join("broker/owned.cc"),
        "// Owned dirty text omitted by commit comparison.\n",
    )
    .unwrap();
    std::fs::write(root.join("untracked.md"), "Owned omitted untracked text").unwrap();
    (fixture, base, head)
}

fn compare(fixture: &Fixture, input: serde_json::Value) -> serde_json::Value {
    let registry = ModuleRegistry::with_v2_builtins();
    let mut ctx = fixture.context();
    ctx.findings_store = None;
    let prepared = registry
        .prepare_dispatch_input("chrome-rce:review-trigger", input, &ctx, None)
        .unwrap();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap()
}

#[test]
fn changed_paths_are_auxiliary_map_hints_without_findings_or_scan_completion() {
    let registry = ModuleRegistry::with_v2_builtins();
    let tool = registry.resolve_tool("chrome-rce:review-trigger").unwrap();
    assert_eq!(tool.phase, ToolPhase::Map);
    assert_eq!(tool.effect, ToolEffect::Read);
    assert_eq!(tool.runtime_requirement, RuntimeRequirement::Never);
    assert_eq!(
        tool.finding_store_requirement,
        FindingStoreRequirement::Optional
    );
    assert_eq!(tool.discovery_maturity, Some(ModuleMaturity::Labs));
    assert!(!tool.phase_result);
    let module = registry
        .all_modules()
        .find(|module| module.metadata().id == "chrome-rce")
        .unwrap();
    assert!(module
        .dag_nodes()
        .iter()
        .find(|node| node.id == tool.name)
        .unwrap()
        .depends_on
        .is_empty());
}

#[test]
fn actual_git_comparison_retains_exact_paths_and_commits_without_a_model_or_ledger() {
    let (fixture, base, head) = committed_path_fixture();
    let result = compare(&fixture, json!({"diffBase":base}));
    let data = &result["data"];
    assert_eq!(result["status"], "completed");
    assert_eq!(data["baseCommit"], base);
    assert_eq!(data["mergeBase"], base);
    assert_eq!(data["headCommit"], head);
    assert_eq!(
        data["changedFiles"],
        json!([
            "docs/line\nbreak.md",
            "v8/src/compiler/typer.cc",
            "v8/src/maglev/owned café.cc"
        ])
    );
    assert_eq!(data["reviewHints"].as_array().unwrap().len(), 2);
    assert_eq!(data["findings"], json!([]));
    assert!(data["persisted"].is_null());
    assert_eq!(data["workingTreeExcluded"], true);
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
    assert_eq!(fixture.store.latest_run_id().unwrap(), None);
}

#[test]
fn an_omitted_path_list_cannot_report_clean_or_complete_coverage() {
    let (fixture, base, _) = committed_path_fixture();
    let result = compare(&fixture, json!({"diff_base":base,"max_changed_files":"1"}));
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["count"], 0);
    assert_eq!(result["data"]["totalChangedFiles"], 3);
    assert_eq!(result["data"]["omittedChangedFiles"], 2);
    assert!(!result["warnings"].as_array().unwrap().is_empty());
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}

#[test]
fn a_nested_target_restricts_changed_paths_and_retains_repository_pattern_matching() {
    let (fixture, base, _) = committed_path_fixture();
    let result = compare(
        &fixture,
        json!({"target":fixture.workspace.root().join("v8"),"diffBase":base}),
    );
    assert_eq!(result["data"]["repositoryPrefix"], "v8/");
    assert_eq!(result["data"]["totalChangedFiles"], 2);
    assert_eq!(result["data"]["reviewHints"].as_array().unwrap().len(), 2);
    assert_eq!(
        result["data"]["changedFiles"],
        json!(["src/compiler/typer.cc", "src/maglev/owned café.cc"])
    );
}

#[test]
fn invalid_bounds_and_unsupported_scope_are_rejected_by_shared_preparation() {
    let fixture = Fixture::new();
    let registry = ModuleRegistry::with_v2_builtins();
    for input in [
        json!({"maxChangedFiles":0}),
        json!({"maxGitOutputBytes":8}),
        json!({"gitTimeoutMs":0}),
        json!({"gitTimeoutMs":120001}),
        json!({"scanScopeRef":{}}),
    ] {
        assert!(registry
            .prepare_dispatch_input("chrome-rce:review-trigger", input, &fixture.context(), None)
            .is_err());
    }
    assert!(fixture.store.list_all_findings().unwrap().is_empty());
}
