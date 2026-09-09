use super::*;

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
