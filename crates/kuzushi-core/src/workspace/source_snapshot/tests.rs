use super::*;

#[test]
fn source_bound_failure_retains_start_identity_and_runtime_class_without_recapture() {
    let target = tempfile::tempdir().unwrap();
    let source = target.path().join("lib.rs");
    std::fs::write(&source, "fn before() {}\n").unwrap();
    let before = crate::incremental_index::current_workspace_tree_hash(target.path()).unwrap();
    let config = crate::V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let metadata = crate::runtime::RuntimeFailureMetadata::new(
        crate::runtime::RuntimeFailureClass::AllowanceRefused,
        None,
        None,
    );
    let error = run_source_bound_tool(&ctx, "test:source", target.path(), || {
        std::fs::write(&source, "fn after() {}\n")?;
        Err(anyhow::Error::new(crate::runtime::RuntimeFailure::new(
            metadata.clone(),
        )))
    })
    .unwrap_err();
    assert_eq!(
        crate::runtime::runtime_failure_metadata(&error),
        Some(metadata)
    );
    assert!(error.to_string().contains("allowance refused"));
    let output = failed_source_snapshot(&error)
        .unwrap()
        .attach(json!({"data":{}}));
    assert_eq!(output["data"]["treeHash"], before);
    assert_ne!(
        before,
        crate::incremental_index::current_workspace_tree_hash(target.path()).unwrap()
    );
    assert!(failed_source_snapshot(&anyhow::anyhow!("uncaptured failure")).is_none());
}

#[test]
fn source_bound_tool_retains_output_and_spend_when_source_changes() {
    let target = tempfile::tempdir().unwrap();
    let source = target.path().join("lib.rs");
    std::fs::write(&source, "fn before() {}\n").unwrap();
    let config = crate::V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let result = run_source_bound_tool(&ctx, "test:source", target.path(), || {
        std::fs::write(&source, "fn after() {}\n")?;
        Ok(
            json!({"ok": true, "status": "completed", "warnings": ["retained warning"],
            "observedCostUsd": 0.5, "providerSpendUnresolved": true, "data": {"count": 2}}),
        )
    })
    .unwrap();
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["count"], 2);
    assert_eq!(result["observedCostUsd"], 0.5);
    assert_eq!(result["providerSpendUnresolved"], true);
    assert_eq!(result["warnings"][0], "retained warning");
    assert!(result["warnings"][1]
        .as_str()
        .unwrap()
        .contains("source changed"));
    assert_eq!(result["data"]["snapshotHash"].as_str().unwrap().len(), 64);
}

#[test]
fn result_source_snapshot_rejects_changed_source_and_preserves_payload() {
    let target = tempfile::tempdir().unwrap();
    let source = target.path().join("main.py");
    std::fs::write(&source, "print('before')\n").unwrap();
    let config = crate::V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let snapshot = SourceSnapshot::capture(&ctx, "test:source", target.path()).unwrap();
    snapshot
        .ensure_current(&ctx, "test:source", target.path())
        .unwrap();
    std::fs::write(&source, "print('changed')\n").unwrap();
    assert!(snapshot
        .ensure_current(&ctx, "test:source", target.path())
        .unwrap_err()
        .to_string()
        .contains("source changed"));
    let result = snapshot.attach(json!({"ok":true,"data":{"payload":"preserved"}}));
    assert_eq!(result["data"]["payload"], "preserved");
    assert_eq!(result["data"]["snapshotHash"].as_str().unwrap().len(), 64);
    assert_eq!(result["data"]["treeHash"].as_str().unwrap().len(), 64);
}

#[test]
fn a_library_capture_without_an_observed_call_creates_no_start_receipt() {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("hello.txt"), "owned source").unwrap();
    let config = crate::V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    SourceSnapshot::capture(&ctx, "sast:scan", target.path()).unwrap();
    assert!(!crate::run_artifacts::run_dir(target.path(), "absent").exists());
}
