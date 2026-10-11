use super::*;

#[test]
fn preparation_canonicalizes_limits_and_refuses_unused_options_before_work() {
    let root = tempfile::tempdir().unwrap();
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
    let registry = ModuleRegistry::with_v2_builtins();
    let input = json!({"taskMode":"manual","tasks":["secret-scan"],"secret_scan_max_entries":5,
        "secret_scan_max_total_bytes":1024,"secret_scan_max_file_bytes":1024,"secret_scan_max_findings":1});
    let prepared = registry
        .prepare_dispatch_input("sast:scan", input.clone(), &ctx, None)
        .unwrap();
    assert_eq!(prepared.value()["secretScanMaxEntries"], 5);
    assert_eq!(prepared.value()["secretScanMaxTotalBytes"], 1024);
    assert_eq!(prepared.value()["secretScanMaxFileBytes"], 1024);
    assert_eq!(prepared.value()["secretScanMaxFindings"], 1);
    let mut unused = input.clone();
    unused["tasks"] = json!(["license-scan"]);
    let error = registry
        .prepare_dispatch_input("sast:scan", unused, &ctx, None)
        .unwrap_err();
    assert!(
        error.to_string().contains("require the secret-scan task"),
        "{error:#}"
    );
    assert!(!workspace.root().join(".kuzushi/v3/runs").exists());
}

#[test]
fn preparation_refuses_invalid_secret_limits_without_creating_runs() {
    let root = tempfile::tempdir().unwrap();
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
    let registry = ModuleRegistry::with_v2_builtins();
    for (key, value) in [
        ("secretScanMaxEntries", 0),
        ("secretScanMaxTotalBytes", 1023),
        ("secretScanMaxFileBytes", 1023),
        ("secretScanMaxFindings", 0),
    ] {
        let mut invalid = json!({"taskMode":"manual","tasks":["secret-scan"]});
        invalid[key] = json!(value);
        assert!(registry
            .prepare_dispatch_input("sast:scan", invalid, &ctx, None)
            .is_err());
    }
    assert!(!workspace.root().join(".kuzushi/v3/runs").exists());
}

#[test]
fn native_sast_preserves_per_job_limits_in_result_and_terminal_output() {
    let root = tempfile::tempdir().unwrap();
    for name in ["first", "second"] {
        std::fs::create_dir(root.path().join(name)).unwrap();
        std::fs::write(root.path().join(name).join("fixture.env"), "#".repeat(900)).unwrap();
    }
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let store = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let input = json!({"taskMode":"manual","tasks":["secret-scan"],"paths":["first","second"],
        "secretScanMaxTotalBytes":1024,"triage":false,"verify":false,"autoPatch":false});
    let prepared = registry
        .prepare_dispatch_input("sast:scan", input, &ctx, None)
        .unwrap();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(
        crate::tool_result_status(&result),
        crate::ToolResultStatus::Partial
    );
    let receipts = result["data"]["nativeInspections"].as_array().unwrap();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[1]["configuredLimits"]["maxTotalBytes"], 1024);
    assert_eq!(receipts[1]["totals"]["contentBytesReserved"], 901);
    let output = result["output"].as_str().unwrap();
    assert!(output.contains("1024 content bytes"));
    assert!(output.contains("901 reserved content bytes"));
}
