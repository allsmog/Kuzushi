use crate::{FindingStore, ModuleRegistry, ToolExecutionContext, V2Config, WorkspaceTarget};
use serde_json::{json, Value};

fn dispatch(workspace: &WorkspaceTarget, input: Value) -> Value {
    dispatch_named(workspace, "iac-scan:scan", input)
}

fn dispatch_named(workspace: &WorkspaceTarget, tool: &str, input: Value) -> Value {
    let config = V2Config::default();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let registry = ModuleRegistry::with_v2_builtins();
    let prepared = registry
        .prepare_dispatch_input(tool, input, &ctx, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap()
}

#[test]
fn direct_and_scoped_sast_keep_one_identity_for_the_same_iac_signal() {
    let root = tempfile::tempdir().unwrap();
    let selected = root.path().join("selected");
    std::fs::create_dir(&selected).unwrap();
    std::fs::write(
        selected.join("Dockerfile"),
        "FROM owned:latest\nUSER nobody\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let direct = dispatch(&workspace, json!({"target":selected}));
    let sast = dispatch_named(
        &workspace,
        "sast:scan",
        json!({"taskMode":"manual","tasks":["iac-scan"],
        "paths":["selected"],"triage":false,"verify":false,"autoPatch":false}),
    );
    assert_eq!(direct["data"]["count"], 1);
    assert_eq!(sast["data"]["findingsCount"], 1);
    let findings = FindingStore::open(workspace.findings_db_path())
        .unwrap()
        .list_all_findings()
        .unwrap();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].file_path, "selected/Dockerfile");
    assert_eq!(
        findings[0].fingerprint,
        direct["data"]["coreFindings"][0]["fingerprint"]
    );
}

#[test]
fn oversized_iac_input_keeps_valid_observations_and_partial_source_receipt() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(
        temp.path().join("Dockerfile"),
        "FROM owned:latest\nUSER root\n",
    )
    .unwrap();
    std::fs::write(temp.path().join("Dockerfile.oversized"), "#".repeat(2048)).unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let result = dispatch(&workspace, json!({"maxFileBytes":1024}));
    assert_eq!(result["status"], "partial");
    assert!(result["data"]["count"].as_u64().unwrap() > 0);
    assert_eq!(
        result["data"]["coverageGaps"]["gaps"][0]["path"],
        "Dockerfile.oversized"
    );
    assert!(result["data"]["snapshotHash"]
        .as_str()
        .is_some_and(|value| value.len() == 64));
    assert!(result["output"]
        .as_str()
        .unwrap()
        .contains("coverage is incomplete"));
}

#[test]
fn iac_invalid_utf8_is_an_inspected_coverage_gap() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("Dockerfile"), [0xff, 0xfe]).unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let result = dispatch(&workspace, json!({}));
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["count"], 0);
    assert_eq!(result["data"]["inspection"]["bytesRead"], 2);
    assert_eq!(result["data"]["filesScanned"], 0);
    assert_eq!(result["data"]["filesSkipped"], 1);
    assert_eq!(
        result["data"]["coverageGaps"]["gaps"][0]["path"],
        "Dockerfile"
    );
}

#[test]
fn historical_iac_reports_disclose_unavailable_accounting() {
    let temp = tempfile::tempdir().unwrap();
    let report =
        crate::iac_scan::scan_iac(temp.path(), &Default::default(), &Default::default()).unwrap();
    let mut raw = serde_json::to_value(report).unwrap();
    raw.as_object_mut().unwrap().remove("inspection");
    let historical: crate::iac_scan::IacScanReport = serde_json::from_value(raw).unwrap();
    assert!(historical.to_tool_json()["data"]["inspection"].is_null());
    assert!(historical.output().contains("accounting unavailable"));
    assert!(serde_json::to_value(historical)
        .unwrap()
        .get("inspection")
        .is_none());
}

#[test]
fn scoped_iac_observations_use_workspace_relative_paths() {
    let temp = tempfile::tempdir().unwrap();
    let selected = temp.path().join("selected");
    std::fs::create_dir(&selected).unwrap();
    std::fs::write(
        selected.join("Dockerfile"),
        "FROM owned:latest\nUSER root\n",
    )
    .unwrap();
    std::fs::write(
        temp.path().join("Dockerfile"),
        "FROM excluded:latest\nUSER root\n",
    )
    .unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let result = dispatch(&workspace, json!({"target":selected}));
    let findings = result["data"]["coreFindings"].as_array().unwrap();
    assert!(!findings.is_empty());
    assert!(
        findings
            .iter()
            .all(|finding| finding["file_path"] == "selected/Dockerfile"),
        "{findings:?}"
    );
    let stored = FindingStore::open(workspace.findings_db_path())
        .unwrap()
        .list_all_findings()
        .unwrap();
    assert!(stored
        .iter()
        .all(|finding| finding.file_path == "selected/Dockerfile"));
}

#[test]
fn iac_total_read_allowance_is_exact_and_partial_results_keep_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let document = format!("FROM owned:latest\nUSER root\n# {}", "x".repeat(800));
    std::fs::write(temp.path().join("Dockerfile"), &document).unwrap();
    std::fs::write(temp.path().join("Dockerfile.second"), &document).unwrap();
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let result = dispatch(&workspace, json!({"maxTotalBytes":1024}));
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["inspection"]["bytesRead"], 1024);
    assert!(result["data"]["count"].as_u64().unwrap() > 0);
    assert_eq!(result["data"]["filesScanned"], 1);
}

#[test]
fn iac_entry_and_depth_limits_do_not_claim_clean_coverage() {
    let temp = tempfile::tempdir().unwrap();
    for index in 0..3 {
        std::fs::write(temp.path().join(format!("Dockerfile.{index}")), "# inert").unwrap();
    }
    let workspace = WorkspaceTarget::new(temp.path()).unwrap();
    let result = dispatch(&workspace, json!({"maxEntries":1}));
    assert_eq!(result["status"], "partial");
    assert_eq!(result["data"]["inspection"]["entriesVisited"], 1);
    let mut path = temp.path().to_path_buf();
    for _ in 0..70 {
        path = path.join("nested");
        std::fs::create_dir(&path).unwrap();
    }
    std::fs::write(path.join("Dockerfile"), "FROM owned:latest").unwrap();
    let result = crate::iac_scan::scan_iac(
        temp.path(),
        &crate::iac_scan::IacScanOptions::default(),
        &crate::ScanCancellation::default(),
    )
    .unwrap();
    assert!(result
        .coverage_gaps
        .gaps
        .iter()
        .any(|gap| gap.reason.contains("depth limit")));
}

#[cfg(unix)]
#[test]
fn iac_does_not_follow_external_files_or_directory_cycles() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    std::fs::write(
        external.path().join("Dockerfile"),
        "FROM excluded:latest\nUSER root\n",
    )
    .unwrap();
    symlink(external.path(), root.path().join("outside")).unwrap();
    symlink(root.path(), root.path().join("cycle")).unwrap();
    let report = crate::iac_scan::scan_iac(
        root.path(),
        &crate::iac_scan::IacScanOptions::default(),
        &crate::ScanCancellation::default(),
    )
    .unwrap();
    assert!(report.findings.is_empty());
    assert_eq!(report.inspection.symlinks_excluded, 2);
}

mod child_source;
