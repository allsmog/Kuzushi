#![cfg(not(feature = "private-cpg"))]

use kuzushi_core::findings::{Finding, FindingStore, Severity};
use kuzushi_core::fleet::{fleet_status, FleetTarget};
use kuzushi_core::run_artifacts::{write_run_summary, RunSummary};
use kuzushi_core::workspace::coverage_ledger::workspace_coverage_db_path;
use kuzushi_core::workspace::{export_scan_findings_sarif, WorkspaceTarget};
use kuzushi_core::{
    cpg_artifact_langs, cpg_engine_available, cpg_engine_unavailable_message, cpg_has_artifacts,
    cpg_supported_languages,
};

#[test]
fn credential_free_core_discloses_private_engine_absence() {
    let target = tempfile::tempdir().unwrap();
    let artifact_dir = target.path().join(".kuzushi/cpg-rs");
    std::fs::create_dir_all(&artifact_dir).unwrap();
    std::fs::write(artifact_dir.join("rust.v0.cpg"), b"CPG1").unwrap();

    assert!(!cpg_engine_available());
    assert!(cpg_supported_languages().is_empty());
    assert!(!cpg_has_artifacts(target.path()));
    assert!(cpg_artifact_langs(target.path()).is_empty());
    assert!(cpg_engine_unavailable_message().contains("not compiled"));
}

#[test]
fn fleet_status_distinguishes_missing_ledger_from_unreadable_ledger() {
    let fleet = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let registered = vec![FleetTarget {
        id: "broken-ledger".to_string(),
        path: target.path().to_path_buf(),
        remote: None,
        default_branch: Some("main".to_string()),
        label: None,
    }];

    let clean = fleet_status(fleet.path(), &registered).unwrap();
    assert_eq!(clean.targets[0].baseline_count, 0);
    assert!(clean.targets[0].last_scan_sha.is_none());

    let ledger_path = workspace_coverage_db_path(target.path());
    std::fs::create_dir_all(ledger_path.parent().unwrap()).unwrap();
    let private_marker = "private-sqlite-diagnostic-marker";
    std::fs::write(&ledger_path, private_marker).unwrap();

    let error = fleet_status(fleet.path(), &registered).unwrap_err();
    let message = error.to_string();

    assert_eq!(
        message,
        "fleet:status could not read coverage ledger for target \"broken-ledger\""
    );
    assert!(!message.contains(private_marker));
    assert!(!message.contains(&target.path().display().to_string()));
}

#[test]
fn scan_export_never_substitutes_another_runs_provenance() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    std::fs::create_dir_all(workspace.root().join("src")).unwrap();
    std::fs::write(workspace.root().join("src/present.rs"), "fn present() {}\n").unwrap();
    std::fs::write(workspace.root().join("src/missing.rs"), "fn missing() {}\n").unwrap();

    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("run-present", workspace.root(), "completed")
        .unwrap();
    store
        .record_run_started("run-missing", workspace.root(), "completed")
        .unwrap();
    write_run_summary(
        workspace.root(),
        &RunSummary::running(
            "run-present",
            "scan",
            Some("sast:scan".to_string()),
            workspace.root().display().to_string(),
        )
        .with_model(Some("present:model".to_string()))
        .complete(),
    )
    .unwrap();

    store
        .insert_finding(
            "run-present",
            &Finding::new_tool(
                "fixture",
                "fixture/present",
                "src/present.rs",
                1,
                None,
                Severity::High,
                "present-run finding",
            ),
        )
        .unwrap();
    store
        .insert_finding(
            "run-missing",
            &Finding::new_tool(
                "fixture",
                "fixture/missing",
                "src/missing.rs",
                1,
                None,
                Severity::Medium,
                "missing-summary finding",
            ),
        )
        .unwrap();

    let output = workspace.root().join("exports/findings.sarif");
    export_scan_findings_sarif(
        &workspace,
        &output,
        &["run-present".to_string(), "run-missing".to_string()],
    )
    .unwrap();

    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(output).unwrap()).unwrap();
    let results = document["runs"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|run| run["results"].as_array().unwrap())
        .collect::<Vec<_>>();
    let present = results
        .iter()
        .find(|result| result["ruleId"] == "fixture/present")
        .unwrap();
    let missing = results
        .iter()
        .find(|result| result["ruleId"] == "fixture/missing")
        .unwrap();

    assert_eq!(present["properties"]["kuzushiRunId"], "run-present");
    assert_eq!(present["properties"]["kuzushiRunStatus"], "completed");
    assert_eq!(present["properties"]["kuzushiModel"], "present:model");

    assert_eq!(missing["properties"]["kuzushiRunId"], "run-missing");
    assert!(missing["properties"]["kuzushiRunStatus"].is_null());
    assert!(missing["properties"]["kuzushiVersion"].is_null());
    assert!(missing["properties"]["kuzushiModel"].is_null());
    assert!(missing["properties"]["kuzushiRuntimePlatform"].is_null());
}
