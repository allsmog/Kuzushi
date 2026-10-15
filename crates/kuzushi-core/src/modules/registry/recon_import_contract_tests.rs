use crate::capabilities::recon::ReconWorkspaceStore;
use crate::{ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};

#[test]
fn precancelled_jsonl_imports_do_not_read_or_create_storage() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = V2Config::default();
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: Some(&cancellation),
        authorization: Default::default(),
    };
    for format in ["amass", "httpx", "nuclei"] {
        let error = crate::recon::execute_recon_tool(
            "recon:import",
            json!({"tool":format,"path":"missing input"}),
            &ctx,
        )
        .unwrap_err();
        assert!(error.to_string().contains("Import cancelled"), "{error}");
    }
    assert!(!workspace.findings_db_path().exists());
}

fn dispatch(workspace: &WorkspaceTarget, tool: &str, input: Value) -> anyhow::Result<Value> {
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input(tool, input, &ctx, None)?
        .authorize_explicit_headless();
    registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)
}

#[test]
fn prepared_httpx_import_keeps_literal_paths_and_reports_scope_and_unusable_rows() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    std::fs::create_dir_all(root.path().join(".kuzushi")).unwrap();
    std::fs::write(
        root.path().join(".kuzushi/scope.toml"),
        "[in_scope]\nhosts=[\"owned.invalid\"]\n",
    )
    .unwrap();
    let path = root.path().join("recorded httpx.jsonl ");
    std::fs::write(&path,"{\"url\":\"https://owned.invalid/public\",\"status_code\":200}\n{\"url\":\"https://outside.invalid/\"}\n{}\n").unwrap();
    let result = dispatch(
        &workspace,
        "recon:import",
        json!({"format":"httpx","path":path}),
    )
    .unwrap();
    assert_eq!(result["status"], "completed");
    assert_eq!(result["data"]["hosts"].as_array().unwrap().len(), 1);
    assert_eq!(result["data"]["skippedOutOfScope"], 1);
    assert_eq!(result["data"]["skippedUnusable"], 1);
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("without a usable host"));
    let store = ReconWorkspaceStore::open(&workspace).unwrap();
    assert_eq!(store.count_hosts().unwrap(), 1);
    assert_eq!(store.count_services().unwrap(), 1);
    assert!(!root.path().join(".kuzushi/v3/campaigns").exists());
}

#[test]
fn malformed_later_httpx_record_discloses_retained_rows_without_success() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let path = root.path().join("broken.jsonl");
    std::fs::write(
        &path,
        "{\"url\":\"https://owned.invalid/public\"}\ninvalid\n",
    )
    .unwrap();
    let error = dispatch(
        &workspace,
        "recon:import",
        json!({"tool":"httpx","path":path}),
    )
    .unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("Earlier saved evidence may remain"),
        "{message}"
    );
    assert!(message.contains("line 2"), "{message}");
    assert_eq!(
        ReconWorkspaceStore::open(&workspace)
            .unwrap()
            .count_hosts()
            .unwrap(),
        1
    );
}

#[test]
fn recorded_har_import_routes_keep_literal_paths_and_inert_request_evidence() {
    for tool in ["recon:import", "bounty:import-har"] {
        let root = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let path = root.path().join("owned capture.har ");
        std::fs::write(&path,json!({"log":{"version":"1.2","entries":[{"request":{"method":"GET","url":"https://owned.invalid/public","headers":[]},"response":{"status":200,"headers":[]}}]}}).to_string()).unwrap();
        let mut input = json!({"path":path});
        if tool == "recon:import" {
            input["tool"] = json!("har");
        }
        let result = dispatch(&workspace, tool, input).unwrap();
        assert_eq!(result["data"]["imported"], 1);
        let findings = crate::FindingStore::open(workspace.findings_db_path())
            .unwrap()
            .list_all_findings()
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence[0].kind, "http-request");
        assert_eq!(findings[0].file_path, "https://owned.invalid/public");
        assert_eq!(findings[0].severity, crate::Severity::Info);
    }
}

#[test]
fn invalid_import_format_unknown_options_and_missing_paths_publish_no_evidence() {
    let root = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    for input in [
        json!({"tool":"invalid","path":"missing"}),
        json!({"tool":"httpx","path":"missing","recursive":true}),
        json!({"tool":"httpx","path":"missing"}),
    ] {
        assert!(dispatch(&workspace, "recon:import", input).is_err());
    }
    assert!(!workspace.findings_db_path().exists());
}
