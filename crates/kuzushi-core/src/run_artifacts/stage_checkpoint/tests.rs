use super::*;
use std::fs;
use std::sync::Arc;

fn workspace() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join(".kuzushi")).unwrap();
    temp
}

fn open_handle(target: &Path, run_id: &str) -> StageCheckpointHandle {
    let store = StageCheckpointStore::discover(target, &[7u8; 32]).unwrap();
    StageCheckpointHandle::open(store, target, run_id, "demo:staged")
}

#[test]
fn checkpoints_require_an_existing_kuzushi_target() {
    let temp = tempfile::tempdir().unwrap();
    assert!(StageCheckpointStore::discover(temp.path(), &[1u8; 32]).is_none());
}

#[test]
fn completed_stages_survive_into_the_next_identical_run() {
    let temp = workspace();
    fs::write(temp.path().join("research.json"), "{}").unwrap();

    let first = open_handle(temp.path(), "run-1");
    assert!(first.resumed_from().is_none());
    first
        .stage("research")
        .complete(vec!["research.json".into()]);
    first.stage("coverage");
    drop(first);

    let second = open_handle(temp.path(), "run-2");
    assert_eq!(second.resumed_from().as_deref(), Some("run-1"));
    assert!(second.completed_stage("research").is_some());
    assert!(second.completed_stage("coverage").is_none());

    let coordinates = checkpoint_coordinates_for_run(temp.path(), "run-1").unwrap();
    assert_eq!(coordinates.resume_from.as_deref(), Some("coverage"));
    assert_eq!(coordinates.completed_stages, vec!["research".to_string()]);
    assert_eq!(
        coordinates.checkpoint_artifacts,
        vec!["research.json".to_string()]
    );
}

#[test]
fn missing_stage_artifact_forces_the_stage_to_rerun() {
    let temp = workspace();
    let handle = open_handle(temp.path(), "run-1");
    handle
        .stage("research")
        .complete(vec!["research.json".into()]);

    assert!(
        handle.completed_stage("research").is_none(),
        "declared artifact never existed, stage must not be trusted"
    );
}

#[test]
fn clear_on_completion_removes_the_pending_checkpoint() {
    let temp = workspace();
    let handle = open_handle(temp.path(), "run-1");
    handle.stage("research").complete(Vec::new());
    assert_eq!(pending_stage_checkpoints(temp.path()).len(), 1);

    handle.clear_checkpoint();
    assert!(pending_stage_checkpoints(temp.path()).is_empty());
}

#[test]
fn different_operation_fingerprints_do_not_share_checkpoints() {
    let temp = workspace();
    let first_store = StageCheckpointStore::discover(temp.path(), &[7u8; 32]).unwrap();
    StageCheckpointHandle::open(first_store, temp.path(), "run-1", "demo:staged")
        .stage("research")
        .complete(Vec::new());

    let other_store = StageCheckpointStore::discover(temp.path(), &[9u8; 32]).unwrap();
    let other = StageCheckpointHandle::open(other_store, temp.path(), "run-2", "demo:staged");
    assert!(other.resumed_from().is_none());
    assert!(other.completed_stage("research").is_none());
}

#[test]
fn scoped_install_isolates_nested_dispatch() {
    assert!(active_stage_checkpoints().is_none());
    let temp = workspace();
    let outer = Arc::new(open_handle(temp.path(), "run-outer"));

    let _outer_scope = StageCheckpointScope::install(Some(outer.clone()));
    assert!(active_stage_checkpoints().is_some());
    {
        let _inner_scope = StageCheckpointScope::install(None);
        assert!(
            active_stage_checkpoints().is_none(),
            "nested non-staged dispatch must not see the parent handle"
        );
    }
    assert!(active_stage_checkpoints().is_some());
}

#[test]
fn guard_dropped_without_complete_leaves_stage_incomplete() {
    let temp = workspace();
    {
        let handle = open_handle(temp.path(), "run-1");
        let guard = handle.stage("research");
        drop(guard);
    }
    let next = open_handle(temp.path(), "run-2");
    assert!(next.completed_stage("research").is_none());
}

#[test]
fn stage_payload_round_trips_across_runs() {
    let temp = workspace();
    let payload = serde_json::json!({"findings": [{"title": "t"}]});

    let first = open_handle(temp.path(), "run-1");
    let artifact = first
        .write_stage_payload("actor:fp-0", &payload)
        .expect("payload write");
    first.stage("actor:fp-0").complete(vec![artifact]);

    let second = open_handle(temp.path(), "run-2");
    let receipt = second.completed_stage("actor:fp-0").expect("receipt");
    assert_eq!(second.read_stage_payload(&receipt), Some(payload));
}
