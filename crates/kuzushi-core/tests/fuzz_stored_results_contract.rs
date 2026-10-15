//! Runtime-free stored-result readers, using owned inert metadata only.
use kuzushi_core::{
    FindingStore, ModuleRegistry, ScanCancellation, ToolExecutionContext, V2Config, WorkspaceTarget,
};
use serde_json::{json, Value};
use std::path::Path;

fn dispatch(
    root: &Path,
    tool: &str,
    input: Value,
    cancellation: Option<&ScanCancellation>,
) -> anyhow::Result<(FindingStore, Value)> {
    let workspace = WorkspaceTarget::new(root)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let config = V2Config::default();
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input(tool, input, &ctx, None)?
        .authorize_explicit_headless();
    let result = registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)?;
    Ok((store, result))
}

fn index(root: &Path, suffix: &str) {
    let body = json!({"event":"recorded","finding_id":"owned-inert-record","verified":true,
        "target":"owned-metadata","signature":"owned-synthetic-signature",
        "crash_excerpt":"Synthetic metadata fixture. No crash or source execution."});
    std::fs::write(
        root.join("findings-index.jsonl"),
        format!("{body}\n{suffix}"),
    )
    .unwrap();
}

#[test]
fn readers_remain_labs_and_cannot_complete_a_scan_phase() {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    for name in ["fuzz:status", "fuzz:import"] {
        let tool = registry.resolve_tool(name).unwrap();
        assert!(tool.headless);
        let (module, _) = registry
            .catalog_tools_with_modules()
            .find(|(_, descriptor)| descriptor.name == name)
            .unwrap();
        assert_eq!(
            tool.effective_maturity(module.maturity()),
            kuzushi_core::modules::ModuleMaturity::Labs
        );
        assert_eq!(
            tool.runtime_requirement,
            kuzushi_core::modules::RuntimeRequirement::Never
        );
        assert_eq!(kuzushi_core::modules::phase_result_phase(tool), None);
    }
}

#[test]
fn status_distinguishes_partial_external_claims_missing_and_invalid_indexes() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let input = json!({"workspace_root":data.path(), "data_root":data.path()});
    let (_, missing) = dispatch(root.path(), "fuzz:status", input.clone(), None).unwrap();
    assert_eq!(missing["status"], "completed");
    assert!(missing["data"]["findings"].is_null());
    index(data.path(), "invalid row");
    let (store, partial) = dispatch(root.path(), "fuzz:status", input.clone(), None).unwrap();
    assert_eq!(partial["status"], "partial");
    assert_eq!(
        partial["data"]["findings"],
        json!({"total":1,"verified":1,"malformedRows":1})
    );
    assert_eq!(partial["data"]["verificationAuthority"], "external-engine");
    assert_eq!(partial["data"]["localReproductionPerformed"], false);
    assert!(store.list_findings(10).unwrap().is_empty());
    std::fs::remove_file(data.path().join("findings-index.jsonl")).unwrap();
    std::fs::create_dir(data.path().join("findings-index.jsonl")).unwrap();
    assert!(dispatch(root.path(), "fuzz:status", input, None).is_err());
    let attempts = kuzushi_core::workflow_attempts::load_phase_attempt_ledger(root.path()).unwrap();
    assert_eq!(attempts.attempts().count(), 0);
}

#[test]
fn partial_import_keeps_human_decisions_without_creating_local_proof() {
    use kuzushi_core::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    index(data.path(), "invalid row");
    let input = json!({"dataRoot":data.path()});
    let (store, first) = dispatch(root.path(), "fuzz:import", input.clone(), None).unwrap();
    assert_eq!(first["status"], "partial");
    assert_eq!(first["data"]["summary"]["imported"], 1);
    assert_eq!(first["data"]["summary"]["skippedRows"], 1);
    assert_eq!(first["data"]["localReproductionPerformed"], false);
    let finding = store.list_findings(10).unwrap().remove(0);
    assert!(finding.verification.is_none());
    let id = finding.id.unwrap();
    store
        .append_user_review_decision(
            id,
            &ReviewDecision {
                verdict: ReviewDecisionVerdict::RejectedFalsePositive,
                author: TriageAuthor::Human,
                confidence: 1.0,
                rationale: "Owned synthetic record".into(),
                dismiss_reason: None,
                actor: None,
            },
        )
        .unwrap();
    let (store, second) = dispatch(root.path(), "fuzz:import", input, None).unwrap();
    assert_eq!(
        first["data"]["summary"]["runId"],
        second["data"]["summary"]["runId"]
    );
    assert_eq!(store.list_findings(10).unwrap().len(), 1);
    let decisions = store
        .list_review_decisions_for_finding_identity(id)
        .unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(
        decisions[0].decision.verdict,
        ReviewDecisionVerdict::RejectedFalsePositive
    );
    let attempts = kuzushi_core::workflow_attempts::load_phase_attempt_ledger(root.path()).unwrap();
    assert_eq!(attempts.attempts().count(), 0);
}

#[test]
fn malformed_only_import_is_partial_and_valid_empty_import_is_complete() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let path = data.path().join("findings-index.jsonl");
    let input = json!({"data_root":data.path()});
    std::fs::write(&path, "invalid").unwrap();
    let (store, result) = dispatch(root.path(), "fuzz:import", input.clone(), None).unwrap();
    assert_eq!(result["status"], "partial");
    assert!(store.list_findings(10).unwrap().is_empty());
    std::fs::write(path, "\n").unwrap();
    let (_, result) = dispatch(root.path(), "fuzz:import", input, None).unwrap();
    assert_eq!(result["status"], "completed");
}

#[test]
fn unknown_options_and_pre_cancellation_cannot_import_history() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    index(data.path(), "");
    let cancellation = ScanCancellation::default();
    cancellation.cancel();
    for tool in ["fuzz:status", "fuzz:import"] {
        assert!(dispatch(root.path(), tool, json!({"unexpected":true}), None).is_err());
        let error = dispatch(
            root.path(),
            tool,
            json!({"dataRoot":data.path()}),
            Some(&cancellation),
        )
        .err()
        .unwrap();
        assert!(format!("{error:#}").contains("cancel"));
    }
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    assert!(FindingStore::open(workspace.findings_db_path())
        .unwrap()
        .list_findings(10)
        .unwrap()
        .is_empty());
}
