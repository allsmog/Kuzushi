use super::*;

fn context(root: &Path, options: &TaintIrisNextInput) -> TaintIrisNextPlanningContext {
    load_taint_iris_next_planning_context(root, root, options, &[]).unwrap()
}

#[test]
fn actual_initial_planner_consumes_a_pinned_catalog_after_active_state_changes() {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("owned.c"),
        "// Owned inert metadata. Never executed.\n",
    )
    .unwrap();
    let payload = json!({"catalog":[{"cwe":"CWE-20","name":"Owned catalog entry","taintClass":"owned",
        "languages":["any"],"sourceSignals":["owned_input"],"sinkSignals":[],"score":0}]});
    let entries =
        super::super::dynamic_catalog::parse_target_catalog_payload(&payload.to_string()).unwrap();
    super::super::dynamic_catalog::persist_target_catalog(root.path(), &entries).unwrap();
    let path = taint_iris_next_target_catalog_path(root.path());
    let bytes = fs::read(&path).unwrap();
    let digest = crate::content_store::object_hash(crate::content_store::ObjectKind::Blob, &bytes)
        .to_string();
    fs::write(&path, "Different active configuration").unwrap();
    let options = TaintIrisNextInput::from_tool_input(&json!({"catalogDigestRef":digest})).unwrap();
    let catalog =
        initial_taint_iris_next_catalog(root.path(), &options, &context(root.path(), &options))
            .unwrap();
    assert_eq!(catalog.len(), 1);
    assert_eq!(catalog[0].source_signals, vec!["owned_input"]);
    assert_eq!(catalog[0].score, 0);
    assert!(!root.path().join(".kuzushi/cpg-rs").exists());
    assert!(!crate::WorkspaceTarget::new(root.path())
        .unwrap()
        .findings_db_path()
        .exists());
}

#[test]
fn actual_initial_planner_refuses_bad_saved_catalogs_without_implicit_static_fallback() {
    let root = tempfile::tempdir().unwrap();
    crate::WorkspaceTarget::new(root.path())
        .unwrap()
        .ensure_state_dir()
        .unwrap();
    let path = taint_iris_next_target_catalog_path(root.path());
    fs::write(&path, "{malformed").unwrap();
    let options = TaintIrisNextInput::from_tool_input(&json!({})).unwrap();
    assert!(initial_taint_iris_next_catalog(
        root.path(),
        &options,
        &context(root.path(), &options)
    )
    .is_err());
    let digest = crate::content_store::object_hash(
        crate::content_store::ObjectKind::Blob,
        &fs::read(&path).unwrap(),
    )
    .to_string();
    let pinned = TaintIrisNextInput::from_tool_input(&json!({"catalogDigestRef":digest})).unwrap();
    assert!(
        initial_taint_iris_next_catalog(root.path(), &pinned, &context(root.path(), &pinned))
            .is_err()
    );
    let builtin =
        TaintIrisNextInput::from_tool_input(&json!({"catalogDigestRef":"static"})).unwrap();
    assert!(!initial_taint_iris_next_catalog(
        root.path(),
        &builtin,
        &context(root.path(), &builtin)
    )
    .unwrap()
    .is_empty());
    assert_eq!(fs::read_to_string(path).unwrap(), "{malformed");
}
