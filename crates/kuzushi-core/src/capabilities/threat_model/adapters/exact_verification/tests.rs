use super::*;
use crate::modules::ModuleRegistry;

fn dispatch(root: &Path, tool: &str, input: Value) -> Result<Value> {
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
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry.prepare_dispatch_input(tool, input, &ctx, None)?;
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

fn import(root: &Path, label: &str, activate: bool) -> ThreatModelRef {
    let document = json!({"version":"1","methodology":"stride","systemContext":label,
        "dfd":{"nodes":[{"id":"reader","name":"Reader","type":"process","trustZone":"internal"}],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{}});
    let result = dispatch(
        root,
        "threat-model:import",
        json!({"document":document,"label":label,"activate":activate}),
    )
    .unwrap();
    serde_json::from_value(result["data"]["modelRef"].clone()).unwrap()
}

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("reader.txt"),
        "Benign source, never executed.\n",
    )
    .unwrap();
    root
}

#[test]
fn failed_exact_check_keeps_its_cause_and_an_unverified_source_marker() {
    let root = fixture();
    let selected = import(root.path(), "Owned context", false);
    let scope = checked_revision_request(root.path(), &selected, None)
        .unwrap()
        .scope;
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let snapshot = SourceSnapshot::capture(&ctx, "threat-model:verify", root.path()).unwrap();
    let output = json!({"ok":false,"status":"failed","summary":"Owned context check failed", "data":{"document":{}}});
    let result = finish_exact_check(snapshot, &ctx, root.path(), output, &scope);
    assert_eq!(result["status"], "failed");
    assert_eq!(result["summary"], "Owned context check failed");
    assert_eq!(result["data"]["sourceCheckCurrent"], false);
}

#[test]
fn exact_check_preserves_active_mirror_original_and_revision_scope() {
    let root = fixture();
    let selected = import(root.path(), "Selected context", false);
    let active = import(root.path(), "Other active context", true);
    let before = load_threat_model_manifest(root.path()).unwrap().unwrap();
    let original = load_exact_threat_model(root.path(), &selected).unwrap();
    let mirror = fs::read(persistent_threat_model_path(root.path())).unwrap();
    let result = dispatch(
        root.path(),
        "threat-model:verify",
        json!({"threatModelRef":selected}),
    )
    .unwrap();
    let checked: ThreatModelRef =
        serde_json::from_value(result["data"]["modelRef"].clone()).unwrap();
    assert_eq!(result["data"]["sourceModelRef"], json!(selected));
    assert_eq!(result["data"]["activated"], false);
    assert_eq!(checked.model_id, selected.model_id);
    assert_ne!(checked.revision_id, selected.revision_id);
    assert_eq!(
        load_exact_threat_model(root.path(), &selected).unwrap(),
        original
    );
    let after = load_threat_model_manifest(root.path()).unwrap().unwrap();
    assert_eq!(after.active, Some(active));
    assert_eq!(after.models[1], before.models[1]);
    let revision = after.models[0].revisions.last().unwrap();
    assert_eq!(revision.scope, before.models[0].revisions[0].scope);
    assert_eq!(revision.source_revision_id, Some(selected.revision_id));
    assert_eq!(revision.source, ThreatModelRevisionSource::Verify);
    assert_eq!(
        fs::read(persistent_threat_model_path(root.path())).unwrap(),
        mirror
    );
    let read = dispatch(
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":checked}),
    )
    .unwrap();
    assert_eq!(read["data"]["document"], result["data"]["document"]);
    assert_eq!(read["data"]["sourceState"]["status"], "matches");
}

#[test]
fn exact_check_never_activates_even_when_no_active_context_exists() {
    let root = fixture();
    let selected = import(root.path(), "Inactive", false);
    dispatch(
        root.path(),
        "threat-model:verify",
        json!({"threatModelRef":selected}),
    )
    .unwrap();
    assert!(load_threat_model_manifest(root.path())
        .unwrap()
        .unwrap()
        .active
        .is_none());
    assert!(!persistent_threat_model_path(root.path()).exists());
}

#[test]
fn inspection_only_returns_check_without_publishing_or_changing_selected_document() {
    let root = fixture();
    let selected = import(root.path(), "Selected", true);
    let before = fs::read(threat_model_manifest_path(root.path())).unwrap();
    let result = dispatch(
        root.path(),
        "threat-model:verify",
        json!({"threatModelRef":selected,"write":false}),
    )
    .unwrap();
    assert_eq!(result["data"]["written"], false);
    assert!(result["data"]["modelRef"].is_null());
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        before
    );
}

#[test]
fn prepared_reference_alias_checks_the_inactive_revision_without_fallback() {
    let root = fixture();
    let selected = import(root.path(), "Selected", false);
    let active = import(root.path(), "Other active", true);
    let result = dispatch(
        root.path(),
        "threat-model:verify",
        json!({"threat_model_ref":selected,"write":false}),
    )
    .unwrap();
    assert_eq!(result["data"]["sourceModelRef"], json!(selected));
    assert_eq!(result["data"]["document"]["systemContext"], "Selected");
    assert_eq!(
        load_threat_model_manifest(root.path())
            .unwrap()
            .unwrap()
            .active,
        Some(active)
    );
}

#[test]
fn exact_check_refuses_null_digest_scope_and_other_target_without_publication() {
    let root = fixture();
    let selected = import(root.path(), "Selected", false);
    let other = fixture();
    let mut wrong = selected.clone();
    wrong.sha256 = format!("sha256:{}", "0".repeat(64));
    let before = fs::read(threat_model_manifest_path(root.path())).unwrap();
    for input in [
        json!({"threatModelRef":null}),
        json!({"threatModelRef":wrong}),
        json!({"threatModelRef":selected,"scope":"path:."}),
        json!({"threatModelRef":selected,"target":other.path()}),
    ] {
        assert!(dispatch(root.path(), "threat-model:verify", input).is_err());
    }
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        before
    );
}

fn git(root: &Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_fixture() -> tempfile::TempDir {
    let root = fixture();
    git(root.path(), &["init", "--quiet"]);
    git(root.path(), &["config", "user.name", "Fixture"]);
    git(
        root.path(),
        &["config", "user.email", "fixture@example.invalid"],
    );
    git(root.path(), &["add", "reader.txt"]);
    git(root.path(), &["commit", "--quiet", "-m", "Fixture source"]);
    root
}

#[test]
fn same_sha_content_change_is_refused_and_original_remains_historical() {
    let root = git_fixture();
    let selected = import(root.path(), "Selected", false);
    let before = fs::read(threat_model_manifest_path(root.path())).unwrap();
    let sha = crate::workspace::target_git_metadata(root.path())
        .unwrap()
        .sha;
    fs::write(root.path().join("reader.txt"), "Different content\n").unwrap();
    assert_eq!(
        crate::workspace::target_git_metadata(root.path())
            .unwrap()
            .sha,
        sha
    );
    let error = dispatch(
        root.path(),
        "threat-model:verify",
        json!({"threatModelRef":selected}),
    )
    .unwrap_err();
    assert!(error.to_string().contains("source content changed"));
    let read = dispatch(
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":selected}),
    )
    .unwrap();
    assert_eq!(read["data"]["sourceState"]["status"], "drifted");
    assert!(read["data"]["sourceState"]["message"]
        .as_str()
        .unwrap()
        .contains("content changed"));
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        before
    );
}

#[test]
fn new_sha_with_identical_source_does_not_rebind_context() {
    let root = git_fixture();
    let selected = import(root.path(), "Selected", false);
    let before = fs::read(threat_model_manifest_path(root.path())).unwrap();
    git(
        root.path(),
        &[
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "Fixture revision",
        ],
    );
    let error = dispatch(
        root.path(),
        "threat-model:verify",
        json!({"threatModelRef":selected}),
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("source revision changed"),
        "{error}"
    );
    let read = dispatch(
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":selected}),
    )
    .unwrap();
    assert_eq!(read["data"]["sourceState"]["status"], "drifted");
    assert!(read["data"]["sourceState"]["message"]
        .as_str()
        .unwrap()
        .contains("SHA changed"));
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        before
    );
}

#[test]
fn missing_source_hash_cannot_be_presented_as_a_current_exact_check() {
    let root = fixture();
    let selected = commit_test_model(root.path(), "Historical");
    let before = fs::read(threat_model_manifest_path(root.path())).unwrap();
    let error = dispatch(
        root.path(),
        "threat-model:verify",
        json!({"threatModelRef":selected}),
    )
    .unwrap_err();
    assert!(error.to_string().contains("recorded provenance treeHash"));
    let read = dispatch(
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":selected}),
    )
    .unwrap();
    assert_eq!(read["data"]["sourceState"]["status"], "unknown");
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        before
    );
}

#[test]
fn changed_dirty_state_is_disclosed_even_when_content_and_sha_are_identical() {
    let root = git_fixture();
    fs::write(
        root.path().join("reader.txt"),
        "Recorded dirty fixture bytes\n",
    )
    .unwrap();
    let selected = import(root.path(), "Recorded dirty context", false);
    assert!(
        crate::workspace::target_git_metadata(root.path())
            .unwrap()
            .dirty
    );
    git(
        root.path(),
        &["update-index", "--assume-unchanged", "reader.txt"],
    );
    assert!(
        !crate::workspace::target_git_metadata(root.path())
            .unwrap()
            .dirty
    );
    let read = dispatch(
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":selected}),
    )
    .unwrap();
    assert_eq!(read["data"]["sourceState"]["status"], "drifted");
    assert!(read["data"]["sourceState"]["message"]
        .as_str()
        .unwrap()
        .contains("dirty state changed"));
}

#[test]
fn sha_change_after_publication_preserves_saved_revision_with_partial_receipt() {
    let root = git_fixture();
    let selected = import(root.path(), "Selected", false);
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let document = load_exact_threat_model(root.path(), &selected).unwrap();
    let request = checked_revision_request(root.path(), &selected, None).unwrap();
    let scope = request.scope.clone();
    let snapshot = SourceSnapshot::capture(&ctx, "threat-model:verify", root.path()).unwrap();
    let output = check_and_save(
        &json!({}),
        &ctx,
        root.path(),
        &selected,
        document,
        request,
        &snapshot,
    )
    .unwrap();
    git(
        root.path(),
        &[
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "Fixture post-save revision",
        ],
    );
    let result = finish_exact_check(snapshot, &ctx, root.path(), output, &scope);
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["sourceCheckCurrent"], false);
    assert_eq!(result["data"]["written"], true);
    let saved: ThreatModelRef = serde_json::from_value(result["data"]["modelRef"].clone()).unwrap();
    assert_eq!(
        load_exact_threat_model(root.path(), &saved).unwrap()["provenance"]["revision"],
        scope.target_revision
    );
    assert!(load_threat_model_manifest(root.path())
        .unwrap()
        .unwrap()
        .active
        .is_none());
}

#[test]
fn source_change_during_store_wait_refuses_publication() {
    let root = fixture();
    let selected = import(root.path(), "Selected", false);
    let before = fs::read(threat_model_manifest_path(root.path())).unwrap();
    let lock = crate::file_lock::ExclusiveFileLock::acquire(
        &threat_model_store_path(root.path()).join(".store.lock"),
    )
    .unwrap();
    let target = root.path().to_path_buf();
    let (ready, waiting) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let workspace = crate::WorkspaceTarget::new(&target).unwrap();
        let config = crate::V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let document = load_exact_threat_model(&target, &selected).unwrap();
        let request = checked_revision_request(&target, &selected, None).unwrap();
        let snapshot = SourceSnapshot::capture(&ctx, "threat-model:verify", &target).unwrap();
        ready.send(()).unwrap();
        save_checked_revision(&target, &document, request, true, &ctx, &snapshot)
    });
    waiting
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    fs::write(
        root.path().join("reader.txt"),
        "Source changed while store was locked\n",
    )
    .unwrap();
    drop(lock);
    assert!(worker
        .join()
        .unwrap()
        .unwrap_err()
        .to_string()
        .contains("source changed during execution"));
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        before
    );
}

#[test]
fn canceled_exact_check_waiting_for_store_lock_preserves_manifest() {
    let root = fixture();
    let selected = import(root.path(), "Selected", false);
    let before = fs::read(threat_model_manifest_path(root.path())).unwrap();
    let lock = crate::file_lock::ExclusiveFileLock::acquire(
        &threat_model_store_path(root.path()).join(".store.lock"),
    )
    .unwrap();
    let target = root.path().to_path_buf();
    let cancellation = crate::ScanCancellation::default();
    let worker_cancel = cancellation.clone();
    let (ready, waiting) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let workspace = crate::WorkspaceTarget::new(&target).unwrap();
        let config = crate::V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: Some(&worker_cancel),
            authorization: Default::default(),
        };
        let document = load_exact_threat_model(&target, &selected).unwrap();
        let request = checked_revision_request(&target, &selected, None).unwrap();
        let snapshot = SourceSnapshot::capture(&ctx, "threat-model:verify", &target).unwrap();
        ready.send(()).unwrap();
        save_checked_revision(&target, &document, request, true, &ctx, &snapshot)
    });
    waiting
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    cancellation.cancel();
    assert!(worker.join().unwrap().is_err());
    drop(lock);
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        before
    );
}

#[test]
#[cfg(unix)]
fn recorded_scope_uses_parent_revision_and_rejects_symlink_escape() {
    let root = fixture();
    fs::create_dir(root.path().join("component")).unwrap();
    let selected = import(root.path(), "Selected", false);
    let mut request = checked_revision_request(root.path(), &selected, None).unwrap();
    request.model_id = None;
    request.new_model = true;
    request.scope.rel_path = "component".into();
    let document = load_exact_threat_model(root.path(), &selected).unwrap();
    let scoped = commit_threat_model_revision(root.path(), &document, request)
        .unwrap()
        .model_ref;
    let mut later = checked_revision_request(root.path(), &scoped, None).unwrap();
    later.scope.target_revision = "different-recorded-revision".into();
    commit_threat_model_revision(root.path(), &document, later).unwrap();
    let bound = checked_revision_request(root.path(), &scoped, None).unwrap();
    assert_eq!(bound.scope.rel_path, Path::new("component"));
    assert_eq!(bound.scope.target_revision, "unavailable");
    let roots = recorded_roots(root.path(), &bound.scope).unwrap();
    assert!(roots.scope.is_some());
    assert_eq!(
        roots.analysis_root,
        root.path().join("component").canonicalize().unwrap()
    );
    let outside = tempfile::tempdir().unwrap();
    fs::remove_dir(root.path().join("component")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("component")).unwrap();
    assert!(recorded_roots(root.path(), &bound.scope)
        .unwrap_err()
        .to_string()
        .contains("escapes the workspace"));
}
