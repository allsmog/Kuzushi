use crate::findings::{TriageOutcome, TriageVerdict};
use crate::runtime::{AgentRuntime, TriageRequest};
use crate::{
    Finding, FindingStore, ModuleRegistry, Severity, ToolExecutionContext, V2Config,
    WorkspaceTarget,
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct SourceReviewRuntime(AtomicUsize);

impl AgentRuntime for SourceReviewRuntime {
    fn with_allowance_binding(
        &self,
        binding: crate::allowance::AllowanceBinding,
    ) -> anyhow::Result<Box<dyn AgentRuntime + '_>> {
        Ok(Box::new(AccountedSourceReview {
            inner: self,
            binding,
        }))
    }

    fn triage_semantic_cache_identity(
        &self,
        _: &TriageRequest,
    ) -> Option<crate::identity::Blake3Hash> {
        Some(crate::identity::hash_parts(
            "triage-runtime-test",
            &[b"owned-source-review-runtime-v1"],
        ))
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> anyhow::Result<TriageOutcome> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(TriageOutcome {
            verdict: TriageVerdict::NeedsReview,
            confidence: 0.5,
            rationale: std::fs::read_to_string(request.cwd.join("note.md"))?,
            cost_usd: 0.01,
            cost_usd_exact: true,
            ..Default::default()
        })
    }
}

struct AccountedSourceReview<'a> {
    inner: &'a SourceReviewRuntime,
    binding: crate::allowance::AllowanceBinding,
}

impl AgentRuntime for AccountedSourceReview<'_> {
    fn allowance_binding(&self) -> Option<&crate::allowance::AllowanceBinding> {
        Some(&self.binding)
    }

    fn triage_semantic_cache_identity(
        &self,
        request: &TriageRequest,
    ) -> Option<crate::identity::Blake3Hash> {
        self.inner.triage_semantic_cache_identity(request)
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> anyhow::Result<TriageOutcome> {
        let reservation = self.binding.reserve(&request.model)?;
        let outcome = self.inner.triage_finding_blocking(request)?;
        self.binding
            .settle(reservation, crate::runtime::triage_cost_report(&outcome)?)?;
        Ok(outcome)
    }
}

fn source_review_allowance(ctx: &ToolExecutionContext<'_>, scan: &str) -> Value {
    let ledger = crate::SpendLimiter::open(ctx.workspace.unwrap().findings_db_path()).unwrap();
    if ledger.allowance_snapshot("source-review").is_err() {
        let registry = ModuleRegistry::with_v2_builtins();
        let prepared = registry.prepare_dispatch_input("campaign:approve-allowance", json!({
            "investigationId":"source-review", "expectedRevision":0, "model":ctx.config.model,
            "maxProviderCalls":4, "protectedReviewCalls":2,
            "reason":"Explicit synthetic fixture allowance; no real provider request"
        }), ctx, None).unwrap().authorize_explicit_headless();
        registry
            .dispatch_prepared_input_with_runtime(prepared, ctx, None)
            .unwrap();
    }
    json!({"schemaVersion":1,"investigationId":"source-review","revision":1,"workId":format!("review-{scan}")})
}

fn prepared_source_review(
    registry: &ModuleRegistry,
    ctx: &ToolExecutionContext<'_>,
    scan: &str,
    retriage: bool,
) -> crate::modules::PreparedToolInput {
    let allowance_ref = source_review_allowance(ctx, scan);
    registry
        .prepare_dispatch_input(
            "triage:run",
            json!({
                "scanId":scan,"strategy":"standard","prefilterThreshold":0,
                "identityReconcile":"off","retriage":retriage,"allowanceRef":allowance_ref
            }),
            ctx,
            None,
        )
        .unwrap()
        .authorize_explicit_headless()
}

fn observe(store: &FindingStore, workspace: &WorkspaceTarget, scan: &str) {
    let snapshot = crate::incremental_index::register_workspace_tree_identity(workspace).unwrap();
    let record =
        crate::run_artifacts::ToolRunRecord::new(workspace.root(), scan, "scan", "fixture:observe");
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        &json!({"syntheticObservation":true}),
        None,
        None,
        Vec::new(),
    )
    .unwrap();
    store
        .record_run_started(scan, workspace.root(), "running")
        .unwrap();
    let finding = Finding::new_tool(
        "audit",
        "owned-note",
        "note.md",
        1,
        None,
        Severity::Low,
        "Labeled inert source observation",
    );
    store.insert_finding(scan, &finding).unwrap();
    store.record_run_finished(scan, "completed", 1).unwrap();
    crate::run_artifacts::try_record_tool_run_complete(record, &json!({"status":"completed",
        "data":{"syntheticObservation":true,"snapshotHash":snapshot.snapshot_hash,"treeHash":snapshot.tree_hash}})).unwrap();
}

fn review(
    workspace: &WorkspaceTarget,
    store: &FindingStore,
    runtime: &SourceReviewRuntime,
    scan: &str,
    retriage: bool,
) -> Value {
    let config = V2Config {
        model: Some("openai:gpt-5.5".into()),
        ..Default::default()
    };
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: Some(store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = prepared_source_review(&registry, &ctx, scan, retriage);
    let run_id = format!("triage-{scan}");
    let record =
        crate::run_artifacts::ToolRunRecord::new(workspace.root(), &run_id, "tool", "triage:run");
    crate::run_artifacts::try_record_tool_run_started_with_reproducibility(
        record,
        prepared.value(),
        config.model.clone(),
        None,
        Vec::new(),
    )
    .unwrap();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(runtime))
        .unwrap();
    crate::run_artifacts::try_record_tool_run_complete(record, &result).unwrap();
    result
}

#[test]
fn prepared_triage_reads_the_new_source_instead_of_reusing_an_earlier_snapshot() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("note.md"), "first source revision").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let runtime = SourceReviewRuntime::default();
    observe(&store, &workspace, "first");
    let first = review(&workspace, &store, &runtime, "first", false);
    assert_eq!(first["data"]["triaged"], 1);
    std::fs::write(root.path().join("note.md"), "second source revision").unwrap();
    observe(&store, &workspace, "second");
    let second = review(&workspace, &store, &runtime, "second", false);
    assert_eq!(second["data"]["triaged"], 1);
    assert_eq!(
        runtime.0.load(Ordering::SeqCst),
        2,
        "A new source must receive a fresh review"
    );
    assert_ne!(
        first["data"]["snapshotHash"],
        second["data"]["snapshotHash"]
    );
}

#[test]
fn prepared_review_retains_an_opinion_without_overwriting_human_authority() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("note.md"),
        "Owned public example; inert source.",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let runtime = SourceReviewRuntime::default();
    observe(&store, &workspace, "protected");
    let finding_id = protect_public_example(&store);
    let before = serde_json::to_value(store.list_review_decisions(finding_id).unwrap()).unwrap();
    let result = review(&workspace, &store, &runtime, "protected", true);
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["successful"], 1);
    assert_eq!(result["data"]["persistenceFailures"], 0);
    assert_eq!(result["data"]["unappliedOpinions"], 1);
    assert_eq!(result["data"]["findings"][0]["decisionApplied"], false);
    assert_eq!(result["data"]["findings"][0]["verdict"], "needs_review");
    assert_eq!(runtime.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        serde_json::to_value(store.list_review_decisions(finding_id).unwrap()).unwrap(),
        before
    );
    let receipt: Value = serde_json::from_slice(
        &std::fs::read(
            root.path()
                .join(".kuzushi/v3/runs/triage-protected/result.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        receipt["data"]["results"][0]["applicationStatus"],
        "not_applied"
    );
}

fn protect_public_example(store: &FindingStore) -> i64 {
    let finding = store
        .list_findings_for_scan_id("protected")
        .unwrap()
        .remove(0);
    store
        .record_triage_with_author(
            finding.id.unwrap(),
            &TriageOutcome {
                verdict: TriageVerdict::FalsePositive,
                confidence: 1.0,
                rationale: "Operator checked the public example".into(),
                ..Default::default()
            },
            crate::findings::TriageAuthor::Human,
        )
        .unwrap();
    finding.id.unwrap()
}

#[test]
fn prepare_native_triage_source_fixture() {
    let Some(root) = std::env::var_os("KUZUSHI_TRIAGE_FIXTURE_OUT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    assert!(root.is_absolute());
    assert!(!root.join(".kuzushi/triage-audit-fixture.json").exists());
    std::fs::create_dir_all(&root).unwrap();
    for name in ["app.py", "config.env"] {
        let _ = std::fs::remove_file(root.join(name));
    }
    let workspace = WorkspaceTarget::new(&root).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let runtime = SourceReviewRuntime::default();
    std::fs::write(
        root.join("note.md"),
        "First source revision. Labeled synthetic review; no vulnerability claim.\n",
    )
    .unwrap();
    observe(&store, &workspace, "first");
    let first = review(&workspace, &store, &runtime, "first", false);
    std::fs::write(
        root.join("note.md"),
        "Second source revision. Labeled synthetic review; no vulnerability claim.\n",
    )
    .unwrap();
    observe(&store, &workspace, "second");
    let second = review(&workspace, &store, &runtime, "second", false);
    assert_eq!(runtime.0.load(Ordering::SeqCst), 2);
    let receipt = json!({"syntheticOutcomes":true,"liveProviderRequests":0,"sourceExecuted":false,
        "runtimeInvocations":2,"first":first,"second":second});
    std::fs::write(
        root.join(".kuzushi/triage-audit-fixture.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
}
