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
    StageCheckpointHandle::open_with_source_identity(
        store,
        target,
        run_id,
        "demo:staged",
        Some("test-tree".to_string()),
    )
}

fn open_real_handle(target: &Path, run_id: &str) -> StageCheckpointHandle {
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
fn continuation_coordinates_require_the_failed_runs_matching_fingerprint() {
    let temp = workspace();
    let handle = open_handle(temp.path(), "run-1");
    handle.stage("research").complete(Vec::new());

    write_requested_operation(temp.path(), "run-1", [9u8; 32]);
    assert!(matching_checkpoint_coordinates_for_run(temp.path(), "run-1").is_none());

    let other = workspace();
    open_handle(other.path(), "run-1")
        .stage("research")
        .complete(Vec::new());
    write_requested_operation(other.path(), "run-1", [7u8; 32]);
    assert!(matching_checkpoint_coordinates_for_run(other.path(), "run-1").is_some());
}

fn write_requested_operation(target: &Path, run_id: &str, digest: [u8; 32]) {
    use crate::run_lifecycle::*;
    let writer = RunItemWriter::open(target, run_id, None).unwrap();
    let item = RunItemV1::ToolCallRequested {
        tool_name: SafeText::operator_visible("demo:staged"),
        operation_fingerprint: OperationFingerprint::from_digest(digest),
        safe_option_names: Vec::new(),
    };
    writer
        .emit_and_flush(
            RunItemRecord::new(RunItemId::new(), RunItemSource::Dispatch, item)
                .with_call(RunCallId::new()),
        )
        .unwrap();
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
fn changed_stage_artifact_content_forces_the_stage_to_rerun() {
    let temp = workspace();
    let artifact = temp.path().join("research.json");
    fs::write(&artifact, "{\"version\":1}").unwrap();

    let first = open_handle(temp.path(), "run-1");
    first
        .stage("research")
        .complete(vec!["research.json".into()]);
    assert!(first.completed_stage("research").is_some());
    drop(first);

    fs::write(&artifact, "{\"version\":2}").unwrap();
    let second = open_handle(temp.path(), "run-2");

    assert!(second.resumed_from().is_none());
    assert!(
        second.completed_stage("research").is_none(),
        "an existing artifact with different bytes must not satisfy resume"
    );
}

#[test]
fn changed_upstream_artifact_invalidates_later_stage_reuse() {
    let temp = workspace();
    let research = temp.path().join("research.json");
    let coverage = temp.path().join("coverage.json");
    fs::write(&research, "{\"version\":1}").unwrap();
    fs::write(&coverage, "{\"coverage\":1}").unwrap();

    let first = open_handle(temp.path(), "run-1");
    first
        .stage("research")
        .complete(vec!["research.json".into()]);
    first
        .stage("coverage")
        .complete(vec!["coverage.json".into()]);
    drop(first);

    fs::write(&research, "{\"version\":2}").unwrap();
    let second = open_handle(temp.path(), "run-2");

    assert!(second.completed_stage("research").is_none());
    assert!(
        second.completed_stage("coverage").is_none(),
        "a downstream stage must not survive an invalid upstream dependency"
    );
}

#[test]
fn rerunning_upstream_stage_discards_later_prior_receipts() {
    let temp = workspace();
    fs::write(temp.path().join("research.json"), "{}").unwrap();
    fs::write(temp.path().join("coverage.json"), "{}").unwrap();

    let first = open_handle(temp.path(), "run-1");
    first
        .stage("research")
        .complete(vec!["research.json".into()]);
    first
        .stage("coverage")
        .complete(vec!["coverage.json".into()]);
    drop(first);

    let second = open_handle(temp.path(), "run-2");
    assert!(second.completed_stage("research").is_some());
    second.record_reused_stage("research", "checked before rerun");
    assert!(second.completed_stage("coverage").is_some());
    second
        .stage("research")
        .complete(vec!["research.json".into()]);

    assert!(second.completed_stage("research").is_some());
    assert!(
        second.completed_stage("coverage").is_none(),
        "rerunning an upstream stage must invalidate its downstream suffix"
    );
}

#[test]
fn recording_reuse_preserves_the_remaining_ordered_suffix() {
    let temp = workspace();
    let first = open_handle(temp.path(), "run-1");
    first.stage("research").complete(Vec::new());
    first.stage("coverage").complete(Vec::new());
    drop(first);

    let second = open_handle(temp.path(), "run-2");
    assert!(second.completed_stage("research").is_some());
    second.record_reused_stage("research", "reused research");

    assert!(
        second.completed_stage("coverage").is_some(),
        "auditing reuse must not invalidate the next paid stage"
    );
}

#[test]
fn inserted_stage_discards_only_the_unconsumed_prior_suffix() {
    let temp = workspace();
    let first = open_handle(temp.path(), "run-1");
    first.stage("research").complete(Vec::new());
    first.stage("coverage").complete(Vec::new());
    drop(first);

    let second = open_handle(temp.path(), "run-2");
    assert!(second.completed_stage("research").is_some());
    second.record_reused_stage("research", "reused research");
    second.stage("new-validation").complete(Vec::new());
    drop(second);

    let third = open_handle(temp.path(), "run-3");
    assert!(third.completed_stage("research").is_some());
    third.record_reused_stage("research", "reused research");
    assert!(third.completed_stage("new-validation").is_some());
    third.record_reused_stage("new-validation", "reused validation");
    assert!(
        third.completed_stage("coverage").is_none(),
        "a stage inserted into the plan must invalidate the old downstream suffix"
    );
}

#[test]
fn out_of_order_lookup_cannot_reuse_a_downstream_stage() {
    let temp = workspace();
    let first = open_handle(temp.path(), "run-1");
    first.stage("research").complete(Vec::new());
    first.stage("coverage").complete(Vec::new());
    drop(first);

    let second = open_handle(temp.path(), "run-2");

    assert!(second.completed_stage("coverage").is_none());
    assert!(
        second.completed_stage("research").is_none(),
        "requesting a downstream stage first invalidates the stale plan"
    );
}

#[test]
fn pending_disclosure_rejects_modified_checkpoint_artifacts() {
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let temp = workspace();
    git(temp.path(), &["init"]);
    crate::workspace::initialize_workspace_state(temp.path()).unwrap();
    fs::write(temp.path().join("source.rs"), "fn stable() {}\n").unwrap();
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-m", "stable"]);

    let artifact = temp.path().join(".kuzushi/research.json");
    fs::write(&artifact, "{\"version\":1}").unwrap();
    open_real_handle(temp.path(), "run-1")
        .stage("research")
        .complete(vec![".kuzushi/research.json".into()]);
    write_requested_operation(temp.path(), "run-1", [7u8; 32]);

    let before = pending_stage_checkpoints(temp.path());
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].completed_stages, 1);
    assert!(before[0].reuse_eligible);

    fs::write(&artifact, "{\"version\":2}").unwrap();
    let after = pending_stage_checkpoints(temp.path());

    assert_eq!(after.len(), 1);
    assert_eq!(after[0].completed_stages, 0);
    assert!(!after[0].reuse_eligible);
    assert_eq!(after[0].current_stage.as_deref(), Some("research"));
    assert!(matching_checkpoint_coordinates_for_run(temp.path(), "run-1").is_none());
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
fn changed_clean_revision_does_not_reuse_a_stage_checkpoint() {
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let temp = workspace();
    git(temp.path(), &["init"]);
    fs::write(temp.path().join(".gitignore"), ".kuzushi/\n").unwrap();
    fs::write(temp.path().join("source.rs"), "fn first() {}\n").unwrap();
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-m", "first"]);
    open_real_handle(temp.path(), "run-1")
        .stage("research")
        .complete(Vec::new());

    fs::write(temp.path().join("source.rs"), "fn second() {}\n").unwrap();
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-m", "second"]);

    let next = open_real_handle(temp.path(), "run-2");
    assert!(next.resumed_from().is_none());
    assert!(next.completed_stage("research").is_none());
}

#[test]
fn non_git_target_reuses_a_checkpoint_when_content_is_unchanged() {
    let temp = workspace();
    open_real_handle(temp.path(), "run-1")
        .stage("research")
        .complete(Vec::new());

    let next = open_real_handle(temp.path(), "run-2");

    assert_eq!(next.resumed_from().as_deref(), Some("run-1"));
    assert!(next.completed_stage("research").is_some());
}

#[test]
fn changed_dirty_target_does_not_reuse_a_stage_checkpoint() {
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let temp = workspace();
    git(temp.path(), &["init"]);
    fs::write(temp.path().join(".gitignore"), ".kuzushi/\n").unwrap();
    fs::write(temp.path().join("source.rs"), "fn clean() {}\n").unwrap();
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-m", "clean"]);
    open_real_handle(temp.path(), "run-1")
        .stage("research")
        .complete(Vec::new());
    fs::write(temp.path().join("source.rs"), "fn dirty() {}\n").unwrap();

    let next = open_real_handle(temp.path(), "run-2");

    assert!(next.resumed_from().is_none());
    assert!(next.completed_stage("research").is_none());
}

#[test]
fn unchanged_dirty_target_reuses_a_content_bound_checkpoint() {
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let temp = workspace();
    git(temp.path(), &["init"]);
    fs::write(temp.path().join(".gitignore"), ".kuzushi/\n").unwrap();
    fs::write(temp.path().join("source.rs"), "fn clean() {}\n").unwrap();
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-m", "clean"]);
    fs::write(temp.path().join("source.rs"), "fn dirty() {}\n").unwrap();
    open_real_handle(temp.path(), "run-1")
        .stage("research")
        .complete(Vec::new());

    let next = open_real_handle(temp.path(), "run-2");

    assert_eq!(next.resumed_from().as_deref(), Some("run-1"));
    assert!(next.completed_stage("research").is_some());
}

#[test]
fn changed_git_ignored_source_does_not_reuse_a_stage_checkpoint() {
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let temp = workspace();
    git(temp.path(), &["init"]);
    fs::write(
        temp.path().join(".gitignore"),
        ".kuzushi/\nlocal-policy.toml\n",
    )
    .unwrap();
    fs::write(temp.path().join("source.rs"), "fn stable() {}\n").unwrap();
    fs::write(temp.path().join("local-policy.toml"), "mode = 'first'\n").unwrap();
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-m", "stable"]);
    open_real_handle(temp.path(), "run-1")
        .stage("research")
        .complete(Vec::new());

    fs::write(temp.path().join("local-policy.toml"), "mode = 'second'\n").unwrap();
    let next = open_real_handle(temp.path(), "run-2");

    assert!(next.resumed_from().is_none());
    assert!(next.completed_stage("research").is_none());
}

#[test]
fn different_kuzushi_build_identity_does_not_reuse_a_checkpoint() {
    let temp = workspace();
    let first = open_handle(temp.path(), "run-1");
    first.stage("research").complete(Vec::new());
    let path = first.store.path.clone();
    drop(first);
    let mut file: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    file["implementationIdentity"] = serde_json::json!("different-build");
    fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

    let next = open_handle(temp.path(), "run-2");

    assert!(next.resumed_from().is_none());
    assert!(next.completed_stage("research").is_none());
    assert!(pending_stage_checkpoints(temp.path()).is_empty());
}

#[test]
fn checkpoint_publish_does_not_reuse_a_fixed_temp_sibling() {
    let temp = workspace();
    let path = temp.path().join(".kuzushi/v3/checkpoints/stage-test.json");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let fixed = path.with_extension("json.tmp");
    fs::write(&fixed, "unrelated staging file").unwrap();

    write_checkpoint_atomically(&path, "{\"version\":1}").unwrap();

    assert_eq!(fs::read_to_string(fixed).unwrap(), "unrelated staging file");
    assert_eq!(fs::read_to_string(path).unwrap(), "{\"version\":1}");
}

fn git(target: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(["-c", "user.email=kuzushi@example.invalid"])
        .args(["-c", "user.name=Kuzushi Test"])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .current_dir(target)
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?} failed");
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
    assert!(temp.path().join(&artifact).exists(), "missing {artifact}");
    first.stage("actor:fp-0").complete(vec![artifact.clone()]);

    let second = open_handle(temp.path(), "run-2");
    let receipt = second
        .completed_stage("actor:fp-0")
        .unwrap_or_else(|| panic!("missing receipt for {artifact}"));
    assert_eq!(second.read_stage_payload(&receipt), Some(payload));
}
