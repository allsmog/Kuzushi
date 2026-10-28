use super::*;
use serde_json::json;

fn snapshot(states: &[&str]) -> (tempfile::TempDir, CampaignSnapshot) {
    let root = tempfile::tempdir().unwrap();
    let directory = kuzushi_core::capabilities::campaign::campaign_dir(root.path(), "owned");
    std::fs::create_dir_all(&directory).unwrap();
    let jobs = states
        .iter()
        .enumerate()
        .map(|(i, _)| json!({"jobId":format!("job-{i}"), "tool":"sast:scan"}))
        .collect::<Vec<_>>();
    let queue = states
        .iter()
        .enumerate()
        .map(|(i, state)| (format!("job-{i}"), json!({"state":state})))
        .collect::<serde_json::Map<_, _>>();
    std::fs::write(
        directory.join("plan.json"),
        json!({"jobs":jobs}).to_string(),
    )
    .unwrap();
    std::fs::write(
        directory.join("queue.json"),
        json!({"jobs":queue}).to_string(),
    )
    .unwrap();
    let snapshot = kuzushi_core::capabilities::campaign::snapshot::load_campaign_snapshot(
        root.path(),
        "owned",
    )
    .unwrap();
    (root, snapshot)
}

#[test]
fn queue_categories_partition_fixed_jobs_without_inventing_success_for_unknown_states() {
    let (_root, snapshot) = snapshot(&[
        "completed",
        "running",
        "planned",
        "queued",
        "pending",
        "failed",
        "parked",
        "unrecognized",
    ]);
    let model = queue_model(&snapshot);
    assert_eq!(
        (
            model.completed,
            model.running,
            model.queued,
            model.failed,
            model.deferred,
            model.unknown
        ),
        (1, 1, 3, 1, 1, 1)
    );
    assert_eq!(model.jobs.len(), 8);
    assert_eq!(model.jobs[7].outcome, "unrecognized");
}

#[test]
fn persisted_labels_reasons_and_unknown_states_cannot_inject_terminal_controls() {
    let (_root, mut snapshot) = snapshot(&["\u{1b}[31munknown"]);
    snapshot.jobs[0].display_label = Some("case\u{1b}[2Jlabel".into());
    snapshot.jobs[0].reason = Some("reason\u{1b}]0;title\u{7}".into());
    snapshot.jobs[0].run_id = Some("run\u{1b}]0;title\u{7}".into());
    let model = queue_model(&snapshot);
    for value in [
        &model.jobs[0].engine,
        &model.jobs[0].outcome,
        model.jobs[0].detail.as_ref().unwrap(),
        model.jobs[0].run_ref.as_ref().unwrap(),
    ] {
        assert!(!value.contains('\u{1b}') && !value.contains('\u{7}'));
    }
    assert_eq!(model.unknown, 1);
}
