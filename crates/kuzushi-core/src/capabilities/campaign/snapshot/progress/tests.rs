use super::*;
use crate::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::json;

const ID: &str = "owned-progress";

fn fixture(approve: bool) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("README.md"), "Owned progress fixture\n").unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let result = registry.execute_tool("campaign:study", json!({
        "campaignId": ID, "investigationId": ID,
        "scanInput": {"taskMode":"manual", "tasks":["license-scan"], "threatModelRef":null, "scanContextRef":null}
    }), &ctx).unwrap();
    if approve {
        let input = registry.prepare_dispatch_input("campaign:approve-allowance", json!({
            "campaignId":ID,"investigationId":ID,"expectedRevision":0,
            "campaignPlanSha256":result["data"]["planSha256"],"campaignJobs":3,"maxJobAttempts":1,
            "model":"openai-codex:gpt-5.5","maxProviderCalls":7,"protectedReviewCalls":2,
            "reason":"Owned offline progress reader; no jobs execute"
        }), &ctx, None).unwrap().authorize_explicit_headless();
        registry
            .dispatch_prepared_input_with_runtime(input, &ctx, None)
            .unwrap();
    }
    root
}

fn queue(root: &Path, states: &[&str]) -> Value {
    let plan = super::super::super::approved_work::read_bounded_plan(root, ID).unwrap();
    let jobs = plan["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .zip(states)
        .map(|(row, state)| {
            (
                row["jobId"].as_str().unwrap().into(),
                json!({"state":state,"attempts":0,"dispatches":0}),
            )
        })
        .collect::<Map<String, Value>>();
    json!({"campaignId":ID,"jobs":jobs})
}

fn write_queue(root: &Path, queue: &Value) {
    std::fs::write(
        campaign_queue_path(root, ID),
        serde_json::to_vec(queue).unwrap(),
    )
    .unwrap();
}

#[test]
fn approved_fixed_plan_reads_recorded_states_without_starting_or_spending() {
    let root = fixture(true);
    let before = crate::SpendLimiter::read_campaign_allowance_report(
        &WorkspaceTarget::new(root.path())
            .unwrap()
            .findings_db_path(),
        ID,
    )
    .unwrap();
    let empty = load_approved_scan_snapshot(root.path(), ID).unwrap();
    assert_eq!(empty.state_counts().get("planned"), Some(&3));
    let recorded = queue(root.path(), &["completed", "running", "planned"]);
    write_queue(root.path(), &recorded);
    let bytes = std::fs::read(campaign_queue_path(root.path(), ID)).unwrap();
    let snapshot = load_approved_scan_snapshot(root.path(), ID).unwrap();
    assert_eq!(snapshot.jobs.len(), 3);
    assert_eq!(
        snapshot.state_counts(),
        BTreeMap::from([
            ("completed".into(), 1),
            ("running".into(), 1),
            ("planned".into(), 1)
        ])
    );
    assert_eq!(
        std::fs::read(campaign_queue_path(root.path(), ID)).unwrap(),
        bytes
    );
    let after = crate::SpendLimiter::read_campaign_allowance_report(
        &WorkspaceTarget::new(root.path())
            .unwrap()
            .findings_db_path(),
        ID,
    )
    .unwrap();
    assert_eq!(before, after);
}

#[test]
fn unapproved_or_changed_plans_never_borrow_a_queue() {
    let root = fixture(false);
    write_queue(root.path(), &queue(root.path(), &["completed"; 3]));
    assert!(load_approved_scan_snapshot(root.path(), ID).is_err());
    let root = fixture(true);
    let mut plan = super::super::super::approved_work::read_bounded_plan(root.path(), ID).unwrap();
    plan["jobs"][0]["input"]["target"] = json!("outside");
    std::fs::write(
        campaign_plan_path(root.path(), ID),
        serde_json::to_vec(&plan).unwrap(),
    )
    .unwrap();
    assert!(load_approved_scan_snapshot(root.path(), ID).is_err());
}

#[test]
fn malformed_queue_documents_cannot_look_like_three_unstarted_jobs() {
    let root = fixture(true);
    for value in [
        Value::Null,
        json!({}),
        json!({"jobs":[]}),
        json!({"jobs":{},"campaignId":"other"}),
    ] {
        write_queue(root.path(), &value);
        assert!(
            load_approved_scan_snapshot(root.path(), ID).is_err(),
            "{value}"
        );
    }
}

#[test]
fn malformed_job_states_and_unsafe_run_refs_are_errors() {
    let root = fixture(true);
    for row in [
        Value::Null,
        json!({}),
        json!({"state":1}),
        json!({"state":" "}),
        json!({"state":"running","runId":"../outside"}),
        json!({"state":"running","runId":false}),
    ] {
        let mut value = queue(root.path(), &["planned"; 3]);
        let id = value["jobs"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        value["jobs"][id] = row;
        write_queue(root.path(), &value);
        assert!(
            load_approved_scan_snapshot(root.path(), ID).is_err(),
            "{value}"
        );
    }
}

#[test]
fn extra_jobs_are_rejected_and_unknown_states_remain_visible() {
    let root = fixture(true);
    let mut value = queue(root.path(), &["future-state", "failed", "parked"]);
    write_queue(root.path(), &value);
    assert_eq!(
        load_approved_scan_snapshot(root.path(), ID)
            .unwrap()
            .state_counts()
            .get("future-state"),
        Some(&1)
    );
    value["jobs"]["unapproved-job"] = json!({"state":"running"});
    write_queue(root.path(), &value);
    assert!(load_approved_scan_snapshot(root.path(), ID).is_err());
}

#[test]
fn queue_read_is_bounded_and_does_not_rewrite_oversized_input() {
    let root = fixture(true);
    let path = campaign_queue_path(root.path(), ID);
    let content = vec![b' '; 4 * 1024 * 1024 + 1];
    std::fs::write(&path, &content).unwrap();
    assert!(load_approved_scan_snapshot(root.path(), ID).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), content);
}

#[cfg(unix)]
#[test]
fn queue_symlink_cannot_escape_the_target() {
    let root = fixture(true);
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), "{\"jobs\":{}}").unwrap();
    std::os::unix::fs::symlink(outside.path(), campaign_queue_path(root.path(), ID)).unwrap();
    assert!(load_approved_scan_snapshot(root.path(), ID).is_err());
    assert_eq!(
        std::fs::read_to_string(outside.path()).unwrap(),
        "{\"jobs\":{}}"
    );
}
