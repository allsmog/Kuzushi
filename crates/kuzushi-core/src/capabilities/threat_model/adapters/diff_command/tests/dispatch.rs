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
