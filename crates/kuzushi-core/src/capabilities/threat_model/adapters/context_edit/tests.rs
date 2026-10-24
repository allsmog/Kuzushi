use super::*;
use crate::modules::ModuleRegistry;

fn dispatch(root: &Path, input: Value) -> Result<Value> {
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
    let prepared = registry.prepare_dispatch_input("threat-model:revise", input, &ctx, None)?;
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

#[test]
fn prepared_revision_edit_preserves_base_active_head_scope_and_mirror() {
    let root = tempfile::tempdir().unwrap();
    let base = commit_test_model(root.path(), "Selected original");
    let active = commit_test_model(root.path(), "Other active context");
    let original = load_exact_threat_model(root.path(), &base).unwrap();
    let before = load_threat_model_manifest(root.path()).unwrap().unwrap();
    let mirror = fs::read(persistent_threat_model_path(root.path())).unwrap();
    let result = dispatch(root.path(), json!({"threatModelRef":base,"edits":[{"pointer":"/systemContext","text":"Operator overview"}],"label":"Reviewed copy"})).unwrap();
    let reference: ThreatModelRef =
        serde_json::from_value(result["data"]["modelRef"].clone()).unwrap();
    assert_ne!(reference.model_id, base.model_id);
    assert_eq!(result["data"]["sourceModelRef"], json!(base));
    assert_eq!(result["data"]["activated"], false);
    let revised = load_exact_threat_model(root.path(), &reference).unwrap();
    assert_eq!(revised["systemContext"], "Operator overview");
    assert_eq!(revised["dfd"], original["dfd"]);
    assert_eq!(
        load_exact_threat_model(root.path(), &base).unwrap(),
        original
    );
    let after = load_threat_model_manifest(root.path()).unwrap().unwrap();
    assert_eq!(after.active, Some(active));
    assert_eq!(after.models[0], before.models[0]);
    assert_eq!(after.models[1], before.models[1]);
    assert_eq!(after.models[2].scope, before.models[0].scope);
    assert_eq!(
        after.models[2].revisions[0].source_revision_id,
        Some(base.revision_id)
    );
    assert_eq!(
        after.models[2].revisions[0].source,
        ThreatModelRevisionSource::OperatorEdit
    );
    assert_eq!(
        fs::read(persistent_threat_model_path(root.path())).unwrap(),
        mirror
    );
}

#[test]
fn refused_edits_leave_manifest_unchanged_and_need_no_model() {
    let root = tempfile::tempdir().unwrap();
    let base = commit_test_model(root.path(), "Selected");
    let manifest = fs::read(threat_model_manifest_path(root.path())).unwrap();
    for input in [
        json!({"threatModelRef":null,"edits":[{"pointer":"/systemContext","text":"text"}]}),
        json!({"threatModelRef":base,"edits":[{"pointer":"/verification/verdict","text":"pass"}]}),
        json!({"threatModelRef":base,"edits":[{"pointer":"/systemContext","text":"text"}],"activate":true}),
        json!({"threatModelRef":base,"edits":[],"label":"empty"}),
    ] {
        assert!(dispatch(root.path(), input).is_err());
    }
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        manifest
    );
}

#[test]
fn digest_mismatch_and_duplicate_edits_do_not_publish_a_copy() {
    let root = tempfile::tempdir().unwrap();
    let base = commit_test_model(root.path(), "Selected");
    let mut wrong = base.clone();
    wrong.sha256 = format!("sha256:{}", "0".repeat(64));
    let edit = json!({"pointer":"/systemContext","text":"text"});
    assert!(dispatch(root.path(), json!({"threatModelRef":wrong,"edits":[edit]})).is_err());
    assert!(dispatch(
        root.path(),
        json!({"threatModelRef":base,"edits":[edit,edit]})
    )
    .is_err());
    assert_eq!(
        load_threat_model_manifest(root.path())
            .unwrap()
            .unwrap()
            .models
            .len(),
        1
    );
}

#[test]
fn editing_invalidates_old_verification_without_rewriting_source_receipts() {
    let root = tempfile::tempdir().unwrap();
    let base = commit_test_model(root.path(), "Selected");
    let mut document =
        json!({"verification":{"verdict":"pass"},"provenance":{"sourceRevision":"old"}});
    stamp_operator_context(
        &mut document,
        &base,
        &[ContextTextEdit {
            pointer: "/systemContext".into(),
            text: "changed".into(),
        }],
    )
    .unwrap();
    assert!(document.get("verification").is_none());
    assert_eq!(document["provenance"]["sourceRevision"], "old");
    assert_eq!(
        document["provenance"]["operatorEdit"]["sourceModelRef"],
        json!(base)
    );
    assert_eq!(document["userEdited"], true);
}

#[test]
fn canceled_save_under_a_real_store_lock_publishes_no_revision() {
    let root = tempfile::tempdir().unwrap();
    let base = commit_test_model(root.path(), "Selected");
    let before = fs::read(threat_model_manifest_path(root.path())).unwrap();
    let lock = crate::file_lock::ExclusiveFileLock::acquire(
        &threat_model_store_path(root.path()).join(".store.lock"),
    )
    .unwrap();
    let cancel = crate::ScanCancellation::default();
    let cancel_worker = cancel.clone();
    let target = root.path().to_path_buf();
    let (sent, received) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let workspace = crate::WorkspaceTarget::new(&target).unwrap();
        let config = crate::V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: Some(&cancel_worker),
            authorization: Default::default(),
        };
        sent.send(revise_context_adapter(
            json!({"threatModelRef":base,"edits":[{"pointer":"/systemContext","text":"edited"}]}),
            &ctx,
        ))
        .unwrap();
    });
    assert!(received
        .recv_timeout(std::time::Duration::from_millis(80))
        .is_err());
    cancel.cancel();
    let result = received
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert!(result.unwrap_err().to_string().contains("canceled"));
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        before
    );
    drop(lock);
    worker.join().unwrap();
}

#[test]
fn a_different_inline_target_cannot_redirect_a_workspace_edit() {
    let root = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let base = commit_test_model(root.path(), "Selected");
    let before = fs::read(threat_model_manifest_path(root.path())).unwrap();
    assert!(dispatch(root.path(),json!({"target":other.path(),"threatModelRef":base,"edits":[{"pointer":"/systemContext","text":"edited"}]})).is_err());
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        before
    );
}

#[test]
fn prepared_architecture_correction_is_inactive_and_retains_its_exact_parent() {
    let root = tempfile::tempdir().unwrap();
    let base = commit_test_model(root.path(), "Selected");
    let original = load_exact_threat_model(root.path(), &base).unwrap();
    let active = load_threat_model_manifest(root.path())
        .unwrap()
        .unwrap()
        .active;
    let result = dispatch(
        root.path(),
        json!({"threatModelRef":base,"edits":[
            {"pointer":"/dfd/nodes/0/type","text":"external-entity"},
            {"pointer":"/dfd/nodes/0/name","text":"Human operator"}
        ]}),
    )
    .unwrap();
    let reference: ThreatModelRef =
        serde_json::from_value(result["data"]["modelRef"].clone()).unwrap();
    let copy = load_exact_threat_model(root.path(), &reference).unwrap();
    assert_eq!(copy["dfd"]["nodes"][0]["type"], "external-entity");
    assert_eq!(
        copy["dfd"]["nodes"][0]["id"],
        original["dfd"]["nodes"][0]["id"]
    );
    assert_eq!(
        load_exact_threat_model(root.path(), &base).unwrap(),
        original
    );
    assert_eq!(
        load_threat_model_manifest(root.path())
            .unwrap()
            .unwrap()
            .active,
        active
    );
    assert_eq!(
        copy["provenance"]["operatorEdit"]["sourceModelRef"],
        json!(base)
    );
    assert_eq!(copy["provenance"]["operatorEdit"]["actor"], "operator");
    assert_eq!(result["data"]["activated"], false);
}
