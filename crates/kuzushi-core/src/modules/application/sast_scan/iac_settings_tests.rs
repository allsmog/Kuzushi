use super::*;

#[test]
fn prepared_iac_limits_are_canonical_and_require_the_selected_task() {
    let config = crate::V2Config::default();
    let root = tempfile::tempdir().unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let input = json!({"taskMode":"manual","tasks":["iac-scan"],
        "iac_scan_max_entries":5,"iac_scan_max_total_bytes":2048,"iac_scan_max_file_bytes":1024});
    let prepared = registry
        .prepare_dispatch_input("sast:scan", input.clone(), &ctx, None)
        .unwrap();
    assert_eq!(prepared.value()["iacScanMaxEntries"], 5);
    assert_eq!(prepared.value()["iacScanMaxTotalBytes"], 2048);
    assert_eq!(prepared.value()["iacScanMaxFileBytes"], 1024);
    let mut unused = input;
    unused["tasks"] = json!(["license-scan"]);
    assert!(registry
        .prepare_dispatch_input("sast:scan", unused, &ctx, None)
        .unwrap_err()
        .to_string()
        .contains("require the iac-scan task"));
}

fn two_roots() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for name in ["first", "second"] {
        std::fs::create_dir(root.path().join(name)).unwrap();
        std::fs::write(
            root.path().join(name).join("Dockerfile"),
            format!("FROM owned:latest\nUSER root\n# {}", "x".repeat(800)),
        )
        .unwrap();
    }
    root
}

#[test]
fn native_iac_receipts_preserve_shared_limits_and_partial_observations() {
    let root = two_roots();
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
    let prepared = registry.prepare_dispatch_input("sast:scan", json!({"taskMode":"manual","tasks":["iac-scan"],
        "paths":["first","second"],"iacScanMaxTotalBytes":1024,"triage":false,"verify":false,"autoPatch":false}),
        &ctx, None).unwrap();
    let result = registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    assert_eq!(
        crate::tool_result_status(&result),
        crate::ToolResultStatus::Partial
    );
    assert!(!store.list_all_findings().unwrap().is_empty());
    let receipts = result["data"]["nativeInspections"].as_array().unwrap();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0]["sharedJobAllowance"]["bytesRead"], 830);
    assert_eq!(receipts[1]["status"], "partial");
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("830 content bytes read"));
    assert!(store
        .list_all_findings()
        .unwrap()
        .iter()
        .all(|finding| finding.file_path.starts_with("first/")));
}
