use super::*;
use serde_json::{json, Value};
use std::cell::Cell;
mod dispatch;

fn write_plan(root: &Path, id: &str, jobs: Value) -> std::path::PathBuf {
    let dir = super::super::campaign_dir(root, id);
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("plan.json"),
        json!({"campaignId":id,"jobs":jobs}).to_string(),
    )
    .unwrap();
    dir
}

fn read(root: &Path, preferred: Option<&str>) -> CampaignHistory {
    load_campaign_history(root, preferred, &|| false)
        .unwrap()
        .unwrap()
}

#[test]
fn absent_history_is_complete_and_does_not_create_artifacts() {
    let root = tempfile::tempdir().unwrap();
    let result = read(root.path(), None);
    assert!(result.campaigns.is_empty());
    assert!(result.coverage.complete());
    assert!(!super::super::campaigns_dir(root.path()).exists());
}

#[test]
fn pre_cancellation_does_not_open_an_invalid_history_directory() {
    let root = tempfile::tempdir().unwrap();
    let base = super::super::campaigns_dir(root.path());
    fs::create_dir_all(base.parent().unwrap()).unwrap();
    fs::write(base, "Owned file instead of a directory").unwrap();
    assert!(load_campaign_history(root.path(), Some("unread"), &|| true)
        .unwrap()
        .is_none());
}

#[test]
fn oversized_job_lists_are_refused_without_claiming_partial_job_counts() {
    let root = tempfile::tempdir().unwrap();
    write_plan(
        root.path(),
        "large",
        json!((0..=HISTORY_JOB_LIMIT)
            .map(|i| json!({"jobId":format!("job-{i}")}))
            .collect::<Vec<_>>()),
    );
    let result = read(root.path(), Some("large"));
    assert!(result.campaigns.is_empty());
    assert!(result.requested_error.unwrap().contains("1000 jobs"));
}

#[test]
fn damaged_plan_and_queue_preserve_other_history_and_unknown_total() {
    let root = tempfile::tempdir().unwrap();
    write_plan(root.path(), "valid", json!([]));
    let broken = write_plan(root.path(), "broken", json!([]));
    fs::write(broken.join("plan.json"), "{").unwrap();
    let queue = write_plan(root.path(), "queue", json!([]));
    fs::write(queue.join("queue.json"), "{").unwrap();
    let result = read(root.path(), None);
    assert_eq!(result.campaigns.len(), 1);
    assert_eq!(result.campaigns[0].campaign_id, "valid");
    assert_eq!(result.coverage.unreadable_campaigns, 2);
    assert!(!result.coverage.complete());
    assert!(result.spend().provider_spend_unresolved);
}

#[test]
fn exact_lookup_keeps_the_requested_study_beyond_the_browse_limit() {
    let root = tempfile::tempdir().unwrap();
    for i in 0..105 {
        write_plan(root.path(), &format!("history-{i:03}"), json!([]));
    }
    let first = read(root.path(), None);
    let outside = (0..105)
        .map(|i| format!("history-{i:03}"))
        .find(|id| !first.campaigns.iter().any(|row| &row.campaign_id == id))
        .unwrap();
    let result = read(root.path(), Some(&outside));
    assert_eq!(result.campaigns.len(), HISTORY_CAMPAIGN_LIMIT);
    assert!(result
        .campaigns
        .iter()
        .any(|row| row.campaign_id == outside));
    assert!(result.coverage.campaign_limit_reached);
    assert!(result
        .coverage
        .limitation_label()
        .unwrap()
        .contains("campaign <id>"));
}

#[test]
fn directory_visits_stop_even_when_no_plan_is_readable() {
    let root = tempfile::tempdir().unwrap();
    for i in 0..HISTORY_ENTRY_LIMIT + 2 {
        fs::create_dir_all(super::super::campaign_dir(
            root.path(),
            &format!("missing-{i:04}"),
        ))
        .unwrap();
    }
    let result = read(root.path(), None);
    assert_eq!(result.coverage.visited_entries, HISTORY_ENTRY_LIMIT + 1);
    assert_eq!(result.coverage.unreadable_campaigns, HISTORY_ENTRY_LIMIT);
    assert!(result.coverage.entry_limit_reached);
}

#[test]
fn oversized_plan_is_refused_without_parsing_a_prefix() {
    let root = tempfile::tempdir().unwrap();
    let dir = write_plan(root.path(), "oversized", json!([]));
    let file = fs::OpenOptions::new()
        .write(true)
        .open(dir.join("plan.json"))
        .unwrap();
    file.set_len(4 * 1024 * 1024 + 1).unwrap();
    let result = read(root.path(), Some("oversized"));
    assert!(result.campaigns.is_empty());
    assert_eq!(result.coverage.inspected_bytes, 0);
    assert!(result.requested_error.unwrap().contains("bytes per file"));
}

#[test]
fn malformed_documents_count_toward_the_shared_metadata_allowance() {
    let root = tempfile::tempdir().unwrap();
    let body = " ".repeat(3 * 1024 * 1024);
    for i in 0..12 {
        let dir = write_plan(root.path(), &format!("large-{i}"), json!([]));
        fs::write(dir.join("plan.json"), &body).unwrap();
    }
    let result = read(root.path(), None);
    assert!(result.coverage.byte_limit_reached);
    assert!(result.coverage.inspected_bytes <= 32 * 1024 * 1024);
    assert!(result.coverage.visited_entries < 12);
    assert!(result.spend().provider_spend_unresolved);
}

#[test]
fn only_explicit_detail_reads_optional_run_metadata() {
    let root = tempfile::tempdir().unwrap();
    let dir = write_plan(
        root.path(),
        "selected",
        json!([{"jobId":"one","tool":"threat-model:build"}]),
    );
    fs::write(
        dir.join("queue.json"),
        json!({"jobs":{"one":{"state":"completed","runId":"child"}}}).to_string(),
    )
    .unwrap();
    let runs = crate::workspace::workspace_state_dir(root.path()).join("runs/child");
    fs::create_dir_all(&runs).unwrap();
    fs::write(runs.join("run.json"), json!({"findings":42}).to_string()).unwrap();
    let list = read(root.path(), None);
    assert_eq!(list.campaigns[0].jobs[0].findings, None);
    let detail = read(root.path(), Some("selected"));
    assert_eq!(detail.campaigns[0].jobs[0].findings, Some(42));
    assert!(detail.coverage.inspected_bytes > list.coverage.inspected_bytes);
}

#[test]
fn oversized_run_metadata_is_unavailable_and_disclosed_without_forging_findings() {
    let root = tempfile::tempdir().unwrap();
    let dir = write_plan(root.path(), "selected", json!([{"jobId":"one"}]));
    fs::write(
        dir.join("queue.json"),
        json!({"jobs":{"one":{"state":"completed","runId":"child"}}}).to_string(),
    )
    .unwrap();
    let runs = crate::workspace::workspace_state_dir(root.path()).join("runs/child");
    fs::create_dir_all(&runs).unwrap();
    fs::write(runs.join("run.json"), vec![b' '; 256 * 1024 + 1]).unwrap();
    let result = read(root.path(), Some("selected"));
    assert_eq!(result.campaigns[0].jobs[0].findings, None);
    assert_eq!(result.coverage.unreadable_run_metadata, 1);
    assert!(!result.coverage.complete());
}

#[test]
fn cancellation_returns_no_snapshot_and_starts_no_work() {
    let root = tempfile::tempdir().unwrap();
    for i in 0..20 {
        write_plan(root.path(), &format!("study-{i}"), json!([{"jobId":"one"}]));
    }
    let calls = Cell::new(0);
    let result = load_campaign_history(root.path(), None, &|| {
        calls.set(calls.get() + 1);
        calls.get() > 12
    })
    .unwrap();
    assert!(result.is_none());
    assert!(calls.get() < 30);
    assert!(!crate::workspace::workspace_state_dir(root.path())
        .join("runs")
        .exists());
}

#[test]
fn requested_document_identity_and_queue_shape_are_checked() {
    let root = tempfile::tempdir().unwrap();
    let dir = write_plan(root.path(), "selected", json!([]));
    fs::write(
        dir.join("queue.json"),
        json!({"campaignId":"different","jobs":{}}).to_string(),
    )
    .unwrap();
    let result = read(root.path(), Some("selected"));
    assert!(result
        .requested_error
        .unwrap()
        .contains("another investigation"));
    fs::write(dir.join("queue.json"), json!({"jobs":[]}).to_string()).unwrap();
    assert!(read(root.path(), Some("selected"))
        .requested_error
        .unwrap()
        .contains("job map"));
}

#[cfg(unix)]
#[test]
fn symlinked_directories_and_metadata_are_not_followed() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("plan.json"), r#"{"jobs":[]}"#).unwrap();
    let base = super::super::campaigns_dir(root.path());
    fs::create_dir_all(&base).unwrap();
    std::os::unix::fs::symlink(outside.path(), base.join("linked")).unwrap();
    let dir = write_plan(root.path(), "file-link", json!([]));
    fs::remove_file(dir.join("plan.json")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("plan.json"), dir.join("plan.json")).unwrap();
    let result = read(root.path(), None);
    assert!(result.campaigns.is_empty());
    assert_eq!(result.coverage.skipped_symlinks, 1);
    assert_eq!(result.coverage.unreadable_campaigns, 1);
    assert_eq!(result.coverage.inspected_bytes, 0);
    assert!(read(root.path(), Some("linked")).requested_error.is_some());
}
