use super::*;
use crate::{
    modules::{ModuleRegistry, ToolExecutionContext},
    V2Config, WorkspaceTarget,
};

fn fixture(rows: usize) -> (tempfile::TempDir, WorkspaceTarget, FindingStore) {
    let root = tempfile::tempdir().unwrap();
    let mut ledger = Vec::new();
    for index in 0..rows {
        let file = format!("citation-{index}.txt");
        std::fs::write(
            root.path().join(&file),
            format!("Owned inert citation {index}\n"),
        )
        .unwrap();
        ledger.push(
            json!({"file":file,"line":1,"title":format!("Owned citation {index}"),"severity":"P3"})
                .to_string(),
        );
    }
    let path = root.path().join("ledger.jsonl");
    std::fs::write(&path, ledger.join("\n")).unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    crate::findings::import::import_ledger_jsonl(&workspace, &path, "owned-citation-fixture")
        .unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    (root, workspace, store)
}

fn context<'a>(
    workspace: &'a WorkspaceTarget,
    store: &'a FindingStore,
    config: &'a V2Config,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

fn dispatch(workspace: &WorkspaceTarget, store: &FindingStore, input: Value) -> Result<Value> {
    let config = V2Config::default();
    let ctx = context(workspace, store, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input("findings:ground", input, &ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

#[test]
fn bounded_grounding_window_discloses_unchecked_candidates() {
    let (_root, workspace, store) = fixture(3);
    let result = dispatch(&workspace, &store, json!({"limit":1})).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["checked"], 1);
    assert_eq!(result["data"]["coverage"]["selected"], 1);
    assert_eq!(result["data"]["coverage"]["hasMoreCandidates"], true);
    assert_eq!(result["data"]["findingVerdictsChanged"], false);
    assert_eq!(store.list_all_findings().unwrap().len(), 3);
}

#[test]
fn unreadable_and_oversized_citations_are_unavailable_without_retiring_findings() {
    let (root, workspace, store) = fixture(2);
    std::fs::write(root.path().join("citation-0.txt"), [0xff, 0xfe]).unwrap();
    let before = store.list_all_findings().unwrap();
    let result = dispatch(
        &workspace,
        &store,
        json!({"maxBytesPerFile":4,"maxTotalBytes":8}),
    )
    .unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["counts"]["unavailable"], 2);
    assert!(result["data"]["counts"].get("file_missing").is_none());
    assert!(
        result["data"]["coverage"]["reservedReadBytes"]
            .as_u64()
            .unwrap()
            <= 8
    );
    let after = store.list_all_findings().unwrap();
    for (before, after) in before.iter().zip(&after) {
        assert_eq!(before.grounding, after.grounding);
        assert_eq!(before.triage, after.triage);
        assert_eq!(before.suppressed, after.suppressed);
    }
}

#[test]
fn citation_sources_are_captured_once_and_bind_real_content_sha256() {
    let (root, workspace, store) = fixture(1);
    let mut source = source::CitationSources::new(
        workspace.root(),
        limits::GroundingLimits {
            findings: 5,
            per_file: 1024,
            total_bytes: 1024,
        },
    );
    let finding = store.list_all_findings().unwrap().pop().unwrap();
    let first = source.inspect(&finding, Some("owned-revision"));
    let second = source.inspect(&finding, Some("owned-revision"));
    let bytes = std::fs::read(root.path().join("citation-0.txt")).unwrap();
    assert_eq!(first, second);
    assert_eq!(source.bytes, bytes.len());
    assert_eq!(source.reserved_bytes, bytes.len());
    assert_eq!(
        first.1["sha256"],
        crate::run_lifecycle::sha256_content_digest(&bytes)
    );
}

#[test]
fn citation_audits_are_idempotent_for_one_snapshot_and_distinct_across_revisions() {
    let (root, workspace, store) = fixture(1);
    let original = store.list_all_findings().unwrap().pop().unwrap();
    std::fs::remove_file(root.path().join("citation-0.txt")).unwrap();
    let config = V2Config::default();
    let ctx = context(&workspace, &store, &config);
    let limits = limits::GroundingLimits::from_input(&json!({})).unwrap();
    let a = json!({"sha":"a".repeat(40),"branch":"owned-fixture","dirty":false});
    let b = json!({"sha":"b".repeat(40),"branch":"owned-fixture","dirty":false});
    assert_eq!(
        pass::inspect_candidates(&ctx, &store, workspace.root(), limits, &a)
            .unwrap()
            .newly_drifted
            .len(),
        1
    );
    assert_eq!(
        pass::inspect_candidates(&ctx, &store, workspace.root(), limits, &a)
            .unwrap()
            .newly_drifted
            .len(),
        0
    );
    assert_eq!(
        pass::inspect_candidates(&ctx, &store, workspace.root(), limits, &b)
            .unwrap()
            .newly_drifted
            .len(),
        1
    );
    let history = store
        .list_finding_audit_events(original.id.unwrap(), "grounding")
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_ne!(
        history[0].details["inspectionKey"],
        history[1].details["inspectionKey"]
    );
    assert_eq!(
        store.list_all_findings().unwrap()[0].grounding,
        original.grounding
    );
}

#[test]
fn citation_audit_failure_is_partial_and_cannot_claim_a_successful_audit() {
    let (root, workspace, store) = fixture(1);
    std::fs::remove_file(root.path().join("citation-0.txt")).unwrap();
    store.conn.execute("drop table audit_events", []).unwrap();
    let result = dispatch(&workspace, &store, json!({})).unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["checked"], 1);
    assert_eq!(result["data"]["newlyDrifted"], json!([]));
    assert!(result["data"]["coverage"]["stopReason"]
        .as_str()
        .unwrap()
        .contains("audit"));
}

#[test]
fn shared_grounding_preparation_rejects_unknown_and_excessive_limits() {
    let (_root, workspace, store) = fixture(0);
    for input in [
        json!({"unexpected":true}),
        json!({"limit":-1}),
        json!({"limit":100001}),
        json!({"maxTotalBytes":0}),
        json!({"maxBytesPerFile":8388609}),
    ] {
        assert!(dispatch(&workspace, &store, input).is_err());
    }
    let zero = dispatch(&workspace, &store, json!({"limit":0})).unwrap();
    assert_eq!(zero["data"]["checked"], 0);
}

#[test]
fn canceled_citation_pass_does_not_query_the_candidate_ledger() {
    let (_root, workspace, store) = fixture(1);
    let config = V2Config::default();
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    let mut ctx = context(&workspace, &store, &config);
    ctx.cancellation = Some(&cancellation);
    store
        .conn
        .execute("drop table finding_observations", [])
        .unwrap();
    let limits = limits::GroundingLimits::from_input(&json!({})).unwrap();
    let pass =
        pass::inspect_candidates(&ctx, &store, workspace.root(), limits, &Value::Null).unwrap();
    assert!(pass.partial());
    assert_eq!(pass.selected, 0);
    assert_eq!(pass.checked, 0);
    assert_eq!(pass.bytes, 0);
}

#[test]
fn shared_import_replays_without_duplicate_observations() {
    let (_root, workspace, store) = fixture(2);
    let config = V2Config::default();
    let ctx = context(&workspace, &store, &config);
    let registry = ModuleRegistry::with_v2_builtins();
    let input =
        json!({"path":workspace.root().join("ledger.jsonl"),"tool":"owned-citation-fixture"});
    let prepared = registry
        .prepare_dispatch_input("workspace:import-findings", input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(result["data"]["imported"], 2);
    assert_eq!(store.list_all_findings().unwrap().len(), 2);
}

#[test]
fn completed_import_replay_after_source_drift_preserves_all_original_observations() {
    let (root, workspace, store) = fixture(2);
    let before: Vec<String> = store
        .conn
        .prepare("select finding_json from finding_observations order by created_seq")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    std::fs::write(
        root.path().join("citation-0.txt"),
        "Changed inert citation\n",
    )
    .unwrap();
    std::fs::remove_file(root.path().join("citation-1.txt")).unwrap();
    let result = crate::findings::import::import_ledger_jsonl(
        &workspace,
        &root.path().join("ledger.jsonl"),
        "owned-citation-fixture",
    )
    .unwrap();
    assert_eq!(result.imported, 2);
    let after: Vec<String> = store
        .conn
        .prepare("select finding_json from finding_observations order by created_seq")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(before, after);
}
