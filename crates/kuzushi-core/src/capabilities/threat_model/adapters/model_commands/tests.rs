use super::*;
use crate::modules::ModuleRegistry;
use std::fs;

fn dispatch(root: &Path, name: &str, input: Value) -> Result<Value> {
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
    let prepared = registry
        .prepare_dispatch_input(name, input, &ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

fn active(root: &Path) -> ThreatModelRef {
    load_threat_model_manifest(root)
        .unwrap()
        .unwrap()
        .active
        .unwrap()
}

#[test]
fn shared_lifecycle_lists_activates_restores_and_keeps_exact_context_isolated() {
    let root = tempfile::tempdir().unwrap();
    let first = commit_test_model(root.path(), "Owned Alpha");
    let second = commit_test_model(root.path(), "Owned Beta");
    let first_document = load_exact_threat_model(root.path(), &first).unwrap();
    let models = dispatch(root.path(), "threat-model:models", json!({})).unwrap();
    assert_eq!(models["data"]["models"].as_array().unwrap().len(), 2);
    dispatch(
        root.path(),
        "threat-model:activate",
        json!({"modelId":first.model_id}),
    )
    .unwrap();
    assert_eq!(active(root.path()), first);
    let exact = dispatch(
        root.path(),
        "threat-model:read",
        json!({"threatModelRef":second}),
    )
    .unwrap();
    assert_eq!(exact["data"]["document"]["title"], "Owned Beta");
    assert_eq!(active(root.path()), first);
    let restored = dispatch(
        root.path(),
        "threat-model:restore",
        json!({"revisionId":first.revision_id}),
    )
    .unwrap();
    let restored_ref: ThreatModelRef =
        serde_json::from_value(restored["data"]["modelRef"].clone()).unwrap();
    assert_ne!(restored_ref.revision_id, first.revision_id);
    assert_eq!(restored_ref.model_id, first.model_id);
    assert_eq!(active(root.path()), restored_ref);
    assert_eq!(
        load_exact_threat_model(root.path(), &first).unwrap(),
        first_document
    );
    let revisions = dispatch(
        root.path(),
        "threat-model:revisions",
        json!({"modelId":first.model_id}),
    )
    .unwrap();
    assert_eq!(revisions["data"]["revisions"].as_array().unwrap().len(), 2);
    let newest = &revisions["data"]["revisions"][0];
    assert_eq!(newest["revisionId"], json!(restored_ref.revision_id));
    assert_eq!(newest["sourceRevisionId"], json!(first.revision_id));
    assert_eq!(newest["source"], "restore");
}

#[test]
fn divergent_mirror_refuses_activation_then_adopts_without_rewriting_history() {
    let root = tempfile::tempdir().unwrap();
    let original = commit_test_model(root.path(), "Owned original");
    let other = commit_test_model(root.path(), "Owned other");
    let mut edited = load_exact_threat_model(root.path(), &other).unwrap();
    edited["systemContext"] = json!("Human edited mirror");
    let mirror_path = persistent_threat_model_path(root.path());
    fs::write(&mirror_path, serde_json::to_vec(&edited).unwrap()).unwrap();
    let manifest = fs::read(threat_model_manifest_path(root.path())).unwrap();
    let mirror = fs::read(&mirror_path).unwrap();
    assert!(dispatch(
        root.path(),
        "threat-model:activate",
        json!({"modelId":original.model_id})
    )
    .is_err());
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        manifest
    );
    assert_eq!(fs::read(&mirror_path).unwrap(), mirror);
    let adopted = dispatch(root.path(), "threat-model:adopt", json!({})).unwrap();
    let adopted_ref: ThreatModelRef =
        serde_json::from_value(adopted["data"]["modelRef"].clone()).unwrap();
    assert_eq!(active(root.path()), adopted_ref);
    assert_eq!(adopted_ref.model_id, other.model_id);
    assert_eq!(
        load_exact_threat_model(root.path(), &adopted_ref).unwrap()["systemContext"],
        "Human edited mirror"
    );
    assert!(load_exact_threat_model(root.path(), &other)
        .unwrap()
        .get("systemContext")
        .is_none());
}

#[test]
fn malformed_and_missing_selections_do_not_change_context_store() {
    let root = tempfile::tempdir().unwrap();
    commit_test_model(root.path(), "Owned selected");
    let manifest = fs::read(threat_model_manifest_path(root.path())).unwrap();
    for (name, input) in [
        ("threat-model:activate", json!({"modelId":"invalid"})),
        (
            "threat-model:restore",
            json!({"revisionId":ThreatModelRevisionId::new()}),
        ),
        ("threat-model:revisions", json!({})),
        ("threat-model:models", json!({"unknown":true})),
    ] {
        assert!(dispatch(root.path(), name, input).is_err(), "{name}");
    }
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        manifest
    );
}

#[test]
fn a_different_inline_target_cannot_be_ignored_by_context_lifecycle_tools() {
    let root = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let original = commit_test_model(root.path(), "Owned selected");
    let manifest = fs::read(threat_model_manifest_path(root.path())).unwrap();
    for (name, mut input) in [
        ("threat-model:models", json!({})),
        (
            "threat-model:revisions",
            json!({"modelId":original.model_id}),
        ),
        (
            "threat-model:activate",
            json!({"modelId":original.model_id}),
        ),
        (
            "threat-model:restore",
            json!({"revisionId":original.revision_id}),
        ),
        ("threat-model:adopt", json!({})),
        (
            "threat-model:diff",
            json!({"from":original.revision_id,"to":original.revision_id}),
        ),
    ] {
        input["target"] = json!(other.path());
        assert!(
            dispatch(root.path(), name, input).is_err(),
            "{name} silently ignored target"
        );
    }
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        manifest
    );
}

#[test]
fn mirror_adoption_invalidates_old_context_verification() {
    let root = tempfile::tempdir().unwrap();
    let initial = commit_test_model(root.path(), "Owned verification fixture");
    let mut document = load_exact_threat_model(root.path(), &initial).unwrap();
    document["verification"] = json!({"verdict":"pass"});
    let verified = commit_threat_model_revision(
        root.path(),
        &document,
        ThreatModelCommit {
            model_id: Some(initial.model_id),
            new_model: false,
            label: "Owned verification fixture".into(),
            scope: ScopeRef::legacy_root(root.path(), &format!("sha256:{}", "1".repeat(64))),
            methodology: "stride".into(),
            source: ThreatModelRevisionSource::Verify,
            source_revision_id: Some(initial.revision_id),
            run_id: None,
            activate: Some(true),
            actor: "owned fixture".into(),
        },
    )
    .unwrap()
    .model_ref;
    document["systemContext"] = json!("Changed operator overview");
    fs::write(
        persistent_threat_model_path(root.path()),
        serde_json::to_vec(&document).unwrap(),
    )
    .unwrap();
    let result = dispatch(root.path(), "threat-model:adopt", json!({})).unwrap();
    let adopted: ThreatModelRef =
        serde_json::from_value(result["data"]["modelRef"].clone()).unwrap();
    let updated = load_exact_threat_model(root.path(), &adopted).unwrap();
    assert!(
        updated.get("verification").is_none(),
        "Old verification must not cover edited content"
    );
    assert_eq!(updated["systemContext"], "Changed operator overview");
    assert_eq!(updated["userEdited"], true);
    let revisions = list_model_revisions(root.path(), &adopted.model_id).unwrap();
    assert!(revisions[0].verification.is_none());
    assert_eq!(
        load_exact_threat_model(root.path(), &verified).unwrap()["verification"]["verdict"],
        "pass"
    );
}

#[test]
fn unchanged_mirror_adoption_is_refused_without_publishing_a_revision() {
    let root = tempfile::tempdir().unwrap();
    let original = commit_test_model(root.path(), "Owned unchanged context");
    let manifest = fs::read(threat_model_manifest_path(root.path())).unwrap();
    let object = load_exact_threat_model(root.path(), &original).unwrap();
    assert!(dispatch(root.path(), "threat-model:adopt", json!({})).is_err());
    assert_eq!(
        fs::read(threat_model_manifest_path(root.path())).unwrap(),
        manifest
    );
    assert_eq!(
        load_exact_threat_model(root.path(), &original).unwrap(),
        object
    );
}
