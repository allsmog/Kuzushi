use super::*;
use crate::run_artifacts::TraceHandle;
use crate::scan::ScanCancellation;
use crate::{FindingStore, V2Config, WorkspaceTarget};

struct OwnedAdapter {
    positive: bool,
    change_source: bool,
    fail: bool,
}
impl ScanEngine for OwnedAdapter {
    fn id(&self) -> &'static str {
        "govulncheck"
    }
    fn scan(&self, target: &Path, _: &ScanCancellation) -> Result<Vec<Finding>> {
        if self.change_source {
            std::fs::write(target.join("README.md"), "Planned inert operator edit.\n")?;
        }
        anyhow::ensure!(!self.fail, "Owned adapter failure");
        if !self.positive {
            return Ok(vec![]);
        }
        crate::scan::engines::govulncheck::parse_govulncheck_json(target,
            "{\"config\":{\"protocol_version\":\"v1.0.0\"}}\n{\"finding\":{\"osv\":\"GO-OWNED-1\"}}")
    }
}

fn fixture() -> (tempfile::TempDir, WorkspaceTarget, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("go.mod"), "module owned.invalid/inert\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    (root, workspace, store)
}

fn dispatch(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    run: &str,
    input: Value,
    adapter: OwnedAdapter,
) -> Value {
    let config = V2Config::default();
    let trace = TraceHandle::jsonl(workspace.root(), run);
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: Some(&trace),
        cancellation: None,
        authorization: Default::default(),
    };
    run_with_scanner(input, &ctx, &adapter).unwrap()
}

#[test]
fn source_changed_after_go_analysis_retains_partial_positive_and_empty_runs() {
    for positive in [false, true] {
        let (_root, workspace, store) = fixture();
        let output = dispatch(
            &workspace,
            &store,
            "go-drift",
            json!({}),
            OwnedAdapter {
                positive,
                change_source: true,
                fail: false,
            },
        );
        assert_eq!(output["status"], "partial");
        assert_eq!(output["data"]["sourceCheckCurrent"], false);
        assert_eq!(
            store.run_status("go-drift").unwrap().as_deref(),
            Some("partial")
        );
        assert_eq!(
            store.list_findings_for_scan_id("go-drift").unwrap().len(),
            usize::from(positive)
        );
        let (_, raw) = crate::run_artifacts::read_run_artifact_text(
            workspace.root(),
            "go-drift",
            "findings.json",
        )
        .require("observations")
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<Finding>>(&raw).unwrap().len(),
            usize::from(positive)
        );
    }
}

#[test]
fn go_adapter_failure_keeps_its_cause_and_has_no_observation_commit() {
    let (_root, workspace, store) = fixture();
    let output = dispatch(
        &workspace,
        &store,
        "go-failed",
        json!({}),
        OwnedAdapter {
            positive: true,
            change_source: true,
            fail: true,
        },
    );
    assert_eq!(output["status"], "failed");
    assert_eq!(output["data"]["sourceCheckCurrent"], false);
    assert!(output.to_string().contains("Owned adapter failure"));
    assert!(output["data"].get("persisted").is_none());
    assert!(store.list_all_findings().unwrap().is_empty());
}

#[test]
fn selected_go_modules_keep_separate_workspace_paths_and_identities() {
    let (root, workspace, store) = fixture();
    for name in ["a", "b"] {
        std::fs::create_dir(root.path().join(name)).unwrap();
        std::fs::write(
            root.path().join(name).join("go.mod"),
            "module owned.invalid/metadata\n",
        )
        .unwrap();
        let output = dispatch(
            &workspace,
            &store,
            name,
            json!({"target":name}),
            OwnedAdapter {
                positive: true,
                change_source: false,
                fail: false,
            },
        );
        assert_eq!(output["status"], "completed");
        assert_eq!(
            output["data"]["findings"][0]["file_path"],
            format!("{name}/go.mod")
        );
    }
    let findings = store.list_all_findings().unwrap();
    assert_eq!(findings.len(), 2);
    assert!(findings
        .iter()
        .all(|finding| finding.observation_gap.is_none()));
}

#[test]
fn untraced_go_call_publishes_the_same_committed_run_identity() {
    let (_root, workspace, store) = fixture();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let output = run_with_scanner(
        json!({}),
        &ctx,
        &OwnedAdapter {
            positive: true,
            change_source: false,
            fail: false,
        },
    )
    .unwrap();
    let run = output["data"]["persisted"]["runId"].as_str().unwrap();
    let (_, raw) =
        crate::run_artifacts::read_run_artifact_text(workspace.root(), run, "findings.json")
            .require("committed observations")
            .unwrap();
    let findings: Vec<Finding> = serde_json::from_str(&raw).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].scan_id.as_deref(), Some(run));
}
