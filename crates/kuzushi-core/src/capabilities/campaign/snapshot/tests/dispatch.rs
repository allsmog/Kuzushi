use super::*;
use crate::modules::{ModuleRegistry, ToolExecutionContext};

#[test]
fn prepared_native_study_and_status_share_pass_labels_without_changing_job_identity() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("owned.rs"), "// Owned inert source\n").unwrap();
    let workspace = crate::workspace::WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let findings = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&findings),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let draft = registry.prepare_dispatch_input("campaign:study", json!({"campaignId":"owned-human-labels", "scanInput":{"taskMode":"manual","tasks":["secret-scan"],"threatModelRef":null,"scanContextRef":null}}), &ctx, None).unwrap();
    registry
        .dispatch_prepared_input_with_runtime(draft, &ctx, None)
        .unwrap();
    let path = super::super::super::campaign_plan_path(root.path(), "owned-human-labels");
    let before = std::fs::read(&path).unwrap();
    let plan: Value = serde_json::from_slice(&before).unwrap();
    let request = registry
        .prepare_dispatch_input(
            "campaign:status",
            json!({"campaignId":"owned-human-labels"}),
            &ctx,
            None,
        )
        .unwrap();
    let status = registry
        .dispatch_prepared_input_with_runtime(request, &ctx, None)
        .unwrap();
    let jobs = status["data"]["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 3);
    for (index, job) in jobs.iter().enumerate() {
        assert_eq!(
            job["displayLabel"],
            format!("Discovery · pass {}/3", index + 1)
        );
        assert_eq!(job["jobId"], plan["jobs"][index]["jobId"]);
        assert_eq!(job["state"], "planned");
        assert_eq!(job["attempts"], 0);
    }
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert!(!super::super::super::campaign_queue_path(root.path(), "owned-human-labels").exists());
}
