use super::*;
use crate::modules::{ModuleRegistry, ToolExecutionContext};
use crate::run_artifacts::{load_scan_stage_data, read_run_artifact_text, RunArtifactRead};

#[cfg(unix)]
fn partial_semgrep_fixture(root: &std::path::Path, finding: bool) -> Value {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir(root.join("service")).unwrap();
    std::fs::write(root.join("service/app.js"), "fixture(1);\n").unwrap();
    let results = if finding {
        json!([{"check_id":"labeled-protocol-fixture", "path":"app.js",
        "start":{"line":1}, "extra":{"severity":"WARNING", "message":"Labeled protocol observation"}}])
    } else {
        json!([])
    };
    let report =
        json!({"results":results, "errors":[{"path":"malformed.js", "message":"parse failed"}]});
    let binary = root.join("semgrep-protocol-fixture.sh");
    std::fs::write(&binary, format!("#!/bin/sh\nprintf '%s' '{report}'\n")).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    json!({"tasks":["semgrep"], "semgrepBinary":binary, "semgrepConfig":["labeled-fixture"]})
}

#[cfg(unix)]
fn unreadable_source(root: &std::path::Path, finding: bool) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir(root.join("service")).unwrap();
    let content = if finding {
        format!("const token = {:?};\n", format!("ghp_{}", "a".repeat(36)))
    } else {
        "const label = 'partial coverage fixture';\n".into()
    };
    std::fs::write(root.join("service/app.js"), content).unwrap();
    let blocked = root.join("service/unreadable.js");
    std::fs::write(&blocked, "const value = 1;\n").unwrap();
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&blocked).is_ok() {
        eprintln!("permission-denial fixture unavailable for this process identity");
        return false;
    }
    true
}

fn dispatch(
    root: &std::path::Path,
    run_id: &str,
    overrides: Value,
) -> anyhow::Result<(crate::WorkspaceTarget, crate::FindingStore, Value)> {
    let registry = ModuleRegistry::with_v2_builtins();
    let config = crate::V2Config::default();
    let workspace = crate::WorkspaceTarget::new(root).unwrap();
    let store = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: Some(&store),
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let mut input = json!({"taskMode":"manual", "tasks":["secret-scan"], "paths":["service"],
        "runId":run_id, "verify":false, "autoPatch":false});
    input
        .as_object_mut()
        .unwrap()
        .extend(overrides.as_object().unwrap().clone());
    let prepared = registry.prepare_dispatch_input("sast:scan", input, &ctx, None)?;
    let result = registry.dispatch_prepared_input_with_runtime(prepared, &ctx, None)?;
    Ok((workspace, store, result))
}

#[cfg(unix)]
#[test]
fn native_partial_scan_preserves_findings_and_authenticated_coverage() {
    let root = tempfile::tempdir().unwrap();
    let input = partial_semgrep_fixture(root.path(), true);
    let (workspace, store, result) = dispatch(root.path(), "native-partial", input).unwrap();
    assert_eq!(
        crate::tool_result_status(&result),
        crate::ToolResultStatus::Partial
    );
    assert_eq!(
        store.run_status("native-partial").unwrap().as_deref(),
        Some("partial")
    );
    let findings = store.list_findings_for_scan_id("native-partial").unwrap();
    assert!(!findings.is_empty());
    assert!(findings
        .iter()
        .all(|finding| finding.file_path == "service/app.js"));
    assert_partial_receipt(workspace.root(), "native-partial");
    assert_authenticated_coverage(workspace.root(), "native-partial", &result);
    drop(store);
    let reopened = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
    assert_eq!(
        reopened
            .list_findings_for_scan_id("native-partial")
            .unwrap()
            .len(),
        findings.len()
    );
    assert_eq!(
        reopened.run_status("native-partial").unwrap().as_deref(),
        Some("partial")
    );
}

#[cfg(unix)]
#[test]
fn native_zero_findings_with_parser_gaps_cannot_be_clean() {
    let root = tempfile::tempdir().unwrap();
    let input = partial_semgrep_fixture(root.path(), false);
    let (_, store, result) = dispatch(root.path(), "native-empty-partial", input).unwrap();
    assert_eq!(
        crate::tool_result_status(&result),
        crate::ToolResultStatus::Partial
    );
    assert!(store
        .list_findings_for_scan_id("native-empty-partial")
        .unwrap()
        .is_empty());
    assert_eq!(
        store.run_status("native-empty-partial").unwrap().as_deref(),
        Some("partial")
    );
}

#[cfg(unix)]
#[test]
fn unreadable_source_identity_blocks_before_discovery_without_forging_coverage() {
    let root = tempfile::tempdir().unwrap();
    if !unreadable_source(root.path(), true) {
        return;
    }
    let error = dispatch(root.path(), "unreadable-source", json!({}))
        .err()
        .expect("source identity must refuse unreadable input");
    assert!(
        format!("{error:#}").contains("Permission denied"),
        "{error:#}"
    );
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let store = crate::FindingStore::open(workspace.findings_db_path()).unwrap();
    assert!(store.list_all_findings().unwrap().is_empty());
    assert!(
        !crate::run_artifacts::run_dir(root.path(), "unreadable-source")
            .join("native-coverage.json")
            .exists()
    );
}

fn assert_partial_receipt(root: &std::path::Path, run_id: &str) {
    let receipt = load_scan_stage_data(root, run_id).unwrap().unwrap();
    assert_eq!(
        receipt.outcome,
        crate::run_artifacts::PhaseStageOutcome::Partial
    );
    let scan = receipt.scan.unwrap();
    assert_eq!(scan.scope.paths, ["service"]);
    assert_eq!(
        scan.engines[0].outcome,
        crate::run_artifacts::ScanEngineStageOutcome::Partial
    );
    let detail = scan.engines[0].detail.as_ref().unwrap();
    assert!(detail.contains("service"), "{detail}");
    assert!(detail.contains("malformed.js"), "{detail}");
}

fn assert_authenticated_coverage(root: &std::path::Path, run_id: &str, result: &Value) {
    let RunArtifactRead::Ready { value, .. } =
        read_run_artifact_text(root, run_id, "native-coverage.json")
    else {
        panic!("coverage artifact must authenticate")
    };
    let coverage: Value = serde_json::from_str(&value).unwrap();
    assert_eq!(coverage, result["data"]["nativeCoverage"]);
    assert!(!coverage["engines"][0]["scanErrors"]
        .as_array()
        .unwrap()
        .is_empty());
}
