use super::*;
use crate::findings::{DismissReason, Finding, Severity};

fn status(root: &Path, input: Value) -> Result<Value> {
    let workspace = crate::WorkspaceTarget::new(root)?;
    let config = crate::V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    execute_campaign_status(&input, &ctx)
}

#[test]
fn broken_history_preserves_readable_campaigns_and_discloses_unknown_spend() {
    let root = tempfile::tempdir().unwrap();
    for id in ["readable", "broken"] {
        let dir = super::super::campaign_dir(root.path(), id);
        std::fs::create_dir_all(&dir).unwrap();
        let body = if id == "broken" {
            "{"
        } else {
            r#"{"jobs":[]}"#
        };
        std::fs::write(dir.join("plan.json"), body).unwrap();
    }
    let result = status(root.path(), json!({})).unwrap();
    assert_eq!(result["data"]["campaigns"][0]["campaignId"], "readable");
    assert_eq!(result["data"]["historyCoverage"]["unreadableCampaigns"], 1);
    assert_eq!(result["data"]["historyCoverage"]["complete"], false);
    assert_eq!(result["data"]["trend"]["providerSpendUnresolved"], true);
}

#[test]
fn explicit_history_lookup_rejects_escaped_plan_paths() {
    let root = tempfile::tempdir().unwrap();
    let outside = crate::workspace::workspace_state_dir(root.path()).join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("plan.json"), r#"{"jobs":[]}"#).unwrap();
    let result = status(root.path(), json!({"campaignId":"../outside"}));
    assert!(result.is_err(), "{result:?}");
}

#[test]
fn status_uses_the_digest_from_its_snapshot_without_reading_the_plan_again() {
    let root = tempfile::tempdir().unwrap();
    let dir = super::super::campaign_dir(root.path(), "owned");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plan.json"), r#"{"jobs":[]}"#).unwrap();
    let history = load_campaign_history(root.path(), Some("owned"), &|| false)
        .unwrap()
        .unwrap();
    let expected = history.plan_digests["owned"].clone();
    std::fs::remove_file(dir.join("plan.json")).unwrap();
    let result =
        single_campaign_status(root.path(), "owned", &history, Value::Null, Value::Null).unwrap();
    assert_eq!(result["data"]["planSha256"], expected);
}

#[test]
fn workspace_trend_counts_repeated_identity_once_after_human_fp() {
    let root = tempfile::tempdir().unwrap();
    let store = FindingStore::open(root.path().join("ledger.sqlite3")).unwrap();
    let row = Finding::new_tool(
        "fixture",
        "owned.marker",
        "owned.rs",
        1,
        None,
        Severity::Low,
        "Owned counter fixture",
    );
    store
        .record_run_started("first", root.path(), "completed")
        .unwrap();
    store.insert_finding("first", &row).unwrap();
    store
        .record_run_started("second", root.path(), "completed")
        .unwrap();
    let later = store.insert_finding("second", &row).unwrap();
    store
        .append_dismissal(
            later,
            DismissReason::FalsePositive,
            "Owned fixture routing",
            "operator",
        )
        .unwrap();
    let metrics = workspace_review_metrics(Some(&store), Default::default());
    assert_eq!(
        (
            metrics.decided_findings,
            metrics.confirmed_findings,
            metrics.rejected_false_positives
        ),
        (1, 0, 1)
    );
    assert!(!metrics.decisions_unreadable);
}
