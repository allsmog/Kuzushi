use super::*;
use crate::modules::ModuleRegistry;

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

#[test]
fn shared_revision_diff_shows_overview_edits_without_activating_the_copy() {
    let root = tempfile::tempdir().unwrap();
    let base = commit_test_model(root.path(), "Owned original");
    let original = load_exact_threat_model(root.path(), &base).unwrap();
    let result = dispatch(root.path(), "threat-model:revise", json!({
        "threatModelRef":base,"edits":[{"pointer":"/systemContext","text":"Operator overview α\nSecond line"}]
    })).unwrap();
    let copy = &result["data"]["modelRef"];
    let manifest = std::fs::read(threat_model_manifest_path(root.path())).unwrap();
    let diff = dispatch(
        root.path(),
        "threat-model:diff",
        json!({
            "from":base.revision_id,"to":copy["revisionId"]
        }),
    )
    .unwrap();
    assert!(
        diff["summary"]
            .as_str()
            .unwrap()
            .contains("context text change"),
        "{diff:#}"
    );
    assert_eq!(diff["data"]["contextText"][0]["pointer"], "/systemContext");
    assert_eq!(
        diff["data"]["contextText"][0]["after"],
        "Operator overview α\nSecond line"
    );
    assert_eq!(
        std::fs::read(threat_model_manifest_path(root.path())).unwrap(),
        manifest
    );
    assert_eq!(
        load_exact_threat_model(root.path(), &base).unwrap(),
        original
    );
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        base
    );
}

#[test]
fn shared_revision_diff_retains_same_id_graph_fields_and_missing_vs_null() {
    let root = tempfile::tempdir().unwrap();
    let base = commit_test_model(root.path(), "Owned original");
    let original = load_exact_threat_model(root.path(), &base).unwrap();
    let mut before = original.clone();
    before["threats"] = json!([]);
    before["dfd"] = json!({"nodes":[{"id":"store","name":"Store","type":"process","trustZone":"app"}],"flows":[],"trustBoundaries":[]});
    let left = commit_diff_document(root.path(), &before, "Before");
    let mut after = before.clone();
    after["dfd"]["nodes"][0]["type"] = json!("data-store");
    after["dfd"]["nodes"][0]["trustZone"] = json!("restricted");
    after["provenance"]["explicitUnknown"] = Value::Null;
    let right = commit_diff_document(root.path(), &after, "After");
    let manifest = std::fs::read(threat_model_manifest_path(root.path())).unwrap();
    let result = dispatch(
        root.path(),
        "threat-model:diff",
        json!({"from":left.revision_id,"to":right.revision_id}),
    )
    .unwrap();
    let changes = result["data"]["contextStructure"]["changes"]
        .as_array()
        .expect("Complete stored field changes must be readable");
    let kind = changes
        .iter()
        .find(|change| change["identity"] == "store" && change["field"] == "/type")
        .expect("A reused node id must not hide a type change");
    assert_eq!(kind["before"], "process");
    assert_eq!(kind["after"], "data-store");
    let unknown = changes
        .iter()
        .find(|change| change["afterPointer"] == "/provenance/explicitUnknown")
        .unwrap();
    assert!(unknown.get("before").is_none());
    assert_eq!(unknown.get("after"), Some(&Value::Null));
    assert_eq!(
        std::fs::read(threat_model_manifest_path(root.path())).unwrap(),
        manifest
    );
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        base
    );
}

fn commit_diff_document(root: &Path, document: &Value, label: &str) -> ThreatModelRef {
    commit_threat_model_revision(
        root,
        document,
        ThreatModelCommit {
            model_id: None,
            new_model: true,
            label: label.into(),
            scope: ScopeRef::legacy_root(root, &format!("sha256:{}", "1".repeat(64))),
            methodology: "stride".into(),
            source: ThreatModelRevisionSource::Import,
            source_revision_id: None,
            run_id: None,
            activate: Some(false),
            actor: "test".into(),
        },
    )
    .unwrap()
    .model_ref
}
