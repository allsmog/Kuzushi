use super::*;
use kuzushi_core::allowance::{
    AllowanceApprovalV1, AllowanceCall, AllowanceLimits, InvestigationWork,
};
use kuzushi_core::capabilities::campaign::load_fixed_study_allowance as read_allowance;
use kuzushi_core::{ModuleRegistry, SpendLimiter, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::json;

fn fixture() -> (tempfile::TempDir, String) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("main.rs"),
        "// Owned source, never executed\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config {
        model: Some("openai-codex:gpt-5.5".into()),
        ..Default::default()
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let references: Vec<_> = ["Alpha", "Beta"]
        .iter()
        .map(|label| {
            let output = registry
                .execute_tool(
                    "threat-model:import",
                    json!({
            "activate":false,"label":label,"document":{"version":"1","methodology":"stride",
            "title":label,"systemContext":label,"dfd":{"nodes":[{"id":"app","name":label,
            "type":"process","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},
            "threats":[],"summary":{}}}),
                    &ctx,
                )
                .unwrap();
            output["data"]["modelRef"].clone()
        })
        .collect();
    let output = registry
        .execute_tool(
            "campaign:study",
            json!({
        "campaignId":"owned-matrix","investigationId":"owned-accounting","baselineCaseId":"alpha",
        "scanInput":{"taskMode":"manual","tasks":["secret-scan"]},"contextCases":[
            {"id":"alpha","label":"Baseline","threatModelRef":references[0]},
            {"id":"beta","label":"Candidate","threatModelRef":references[1]}]}),
            &ctx,
        )
        .unwrap();
    let digest = output["data"]["planSha256"].as_str().unwrap().into();
    (root, digest)
}

#[test]
fn matrix_allowance_reads_current_durable_consumption_without_reopening_the_plan() {
    let (root, digest) = fixture();
    assert!(read_allowance(root.path(), "owned-matrix", &digest)
        .unwrap()
        .is_none());
    let ledger = SpendLimiter::open(
        WorkspaceTarget::new(root.path())
            .unwrap()
            .findings_db_path(),
    )
    .unwrap();
    ledger
        .approve_allowance(&AllowanceApprovalV1 {
            schema_version: 1,
            investigation_id: "owned-accounting".into(),
            expected_revision: 0,
            model: "operator:model".into(),
            limits: AllowanceLimits {
                max_provider_calls: 3,
                protected_review_calls: 1,
            },
            reason: "Offline ledger read test; no provider request".into(),
            work_plan: None,
        })
        .unwrap();
    assert_eq!(
        read_allowance(root.path(), "owned-matrix", &digest)
            .unwrap()
            .unwrap()
            .committed_calls,
        0
    );
    drop(
        ledger
            .reserve_provider_call(&AllowanceCall {
                investigation_id: "owned-accounting".into(),
                expected_revision: 1,
                request_id: "interrupted".into(),
                run_id: "owned-run".into(),
                work_id: "owned-work".into(),
                model: "operator:model".into(),
                work: InvestigationWork::Discovery,
            })
            .unwrap(),
    );
    let snapshot = read_allowance(root.path(), "owned-matrix", &digest)
        .unwrap()
        .unwrap();
    assert_eq!(
        (snapshot.committed_calls, snapshot.unresolved_calls),
        (1, 1)
    );
    assert_eq!(snapshot.protected_review_remaining(), 1);
    assert!(snapshot.cost.is_unavailable());
}

#[test]
fn changed_matrix_and_wrong_target_are_errors_instead_of_another_investigation() {
    let (root, digest) = fixture();
    let error = read_allowance(root.path(), "owned-matrix", "different-plan").unwrap_err();
    assert!(error.to_string().contains("Study plan changed"));
    let other = tempfile::tempdir().unwrap();
    assert!(read_allowance(other.path(), "owned-matrix", &digest).is_err());
    assert!(!other.path().join(".kuzushi").exists());
    assert!(read_allowance(root.path(), "../outside", &digest).is_err());
    let key = ViewHydrationKey::StudyAllowance {
        campaign_id: "owned-matrix".into(),
        plan_sha256: digest,
    };
    let cancellation = ViewHydrationCancellation::default();
    cancellation.cancel();
    assert!(FsViewArtifactReader
        .read_cancellable(root.path(), &key, &cancellation)
        .is_none());
}
