use super::*;
use std::cell::Cell;

fn study(root: &Path, id: &str, time: u64) {
    let directory = super::super::super::campaign_dir(root, id);
    fs::create_dir_all(&directory).unwrap();
    fs::write(directory.join("plan.json"),serde_json::to_vec(&json!({"schemaVersion":1,"kind":"scope-study","campaignId":id,"createdAtMs":time,"jobs":[{"jobId":"owned"}]})).unwrap()).unwrap();
}

#[test]
fn choices_are_sorted_capped_and_missing_queues_are_not_started() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..120 {
        study(root.path(), &format!("owned-{index:03}"), index)
    }
    let result = load_study_usage_catalogue(root.path(), &|| false)
        .unwrap()
        .unwrap();
    assert_eq!(result.choices.len(), 100);
    assert!(result.choice_limit_reached && !result.entry_limit_reached);
    assert_eq!(result.choices[0].campaign_id, "owned-119");
    assert_eq!(result.choices[0].completed_jobs, Some(0));
}

#[test]
fn cancellation_never_publishes_partial_choices() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..4 {
        study(root.path(), &format!("owned-{index}"), index)
    }
    assert!(load_study_usage_catalogue(root.path(), &|| true)
        .unwrap()
        .is_none());
    let calls = Cell::new(0);
    assert!(load_study_usage_catalogue(root.path(), &|| {
        calls.set(calls.get() + 1);
        calls.get() > 2
    })
    .unwrap()
    .is_none());
}

#[test]
fn cancellation_at_the_last_read_still_withholds_publication() {
    let root = tempfile::tempdir().unwrap();
    study(root.path(), "owned", 1);
    let calls = Cell::new(0);
    assert!(load_study_usage_catalogue(root.path(), &|| {
        calls.set(calls.get() + 1);
        calls.get() > 2
    })
    .unwrap()
    .is_none());
}

#[test]
fn wide_history_discloses_bounded_enumeration() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..1050 {
        study(root.path(), &format!("owned-{index:04}"), index)
    }
    let result = load_study_usage_catalogue(root.path(), &|| false)
        .unwrap()
        .unwrap();
    assert_eq!(result.visited_entries, 1001);
    assert!(result.entry_limit_reached && result.choice_limit_reached);
}

#[test]
fn malformed_and_oversized_metadata_stay_unavailable() {
    let root = tempfile::tempdir().unwrap();
    study(root.path(), "owned", 1);
    let directory = super::super::super::campaign_dir(root.path(), "owned");
    fs::write(directory.join("queue.json"), "not JSON").unwrap();
    let result = load_study_usage_catalogue(root.path(), &|| false)
        .unwrap()
        .unwrap();
    assert_eq!(result.choices[0].completed_jobs, None);
    assert_eq!(result.unreadable_entries, 1);
    fs::write(directory.join("plan.json"), vec![b' '; FILE_BYTES + 1]).unwrap();
    let result = load_study_usage_catalogue(root.path(), &|| false)
        .unwrap()
        .unwrap();
    assert!(result.choices.is_empty() && result.unreadable_entries == 1);
}

#[test]
fn total_metadata_limit_is_disclosed_without_exceeding_the_allowance() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..40 {
        let id = format!("owned-{index:03}");
        study(root.path(), &id, index);
        let path = super::super::super::campaign_dir(root.path(), &id).join("plan.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["padding"] = Value::String("x".repeat(900_000));
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }
    let result = load_study_usage_catalogue(root.path(), &|| false)
        .unwrap()
        .unwrap();
    assert!(result.byte_limit_reached);
    assert!(result.inspected_bytes <= HISTORY_BYTES);
    assert!(result.visited_entries < 40);
}

#[test]
#[cfg(unix)]
fn symlinked_studies_and_escaped_history_roots_are_not_followed() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    study(root.path(), "owned", 1);
    std::os::unix::fs::symlink(
        outside.path(),
        super::super::super::campaign_dir(root.path(), "linked"),
    )
    .unwrap();
    let result = load_study_usage_catalogue(root.path(), &|| false)
        .unwrap()
        .unwrap();
    assert_eq!(result.skipped_symlinks, 1);
    assert_eq!(result.choices.len(), 1);
    fs::remove_dir_all(root.path().join(".kuzushi/v3/campaigns")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join(".kuzushi/v3/campaigns")).unwrap();
    assert!(load_study_usage_catalogue(root.path(), &|| false).is_err());
}
