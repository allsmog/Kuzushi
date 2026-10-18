use super::*;

#[test]
fn every_format_delivers_a_receipt_without_rewriting_csv_or_scanner_contracts() {
    let target = tempfile::tempdir().unwrap();
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    super::super::investigation_report::tests::planned_report(target.path());
    for (format, path) in [
        (WorkspaceExportFormat::Json, "study.json"),
        (WorkspaceExportFormat::Jsonl, "study.jsonl"),
        (WorkspaceExportFormat::Sarif, "study.sarif"),
        (WorkspaceExportFormat::Csv, "study.csv"),
        (WorkspaceExportFormat::VulnFindings, "VULN-FINDINGS.json"),
        (WorkspaceExportFormat::MarkdownBundle, "study-bundle"),
    ] {
        let options =
            WorkspaceExportOptions::new(Some(format)).with_campaign(Some("report-study".into()));
        let exported =
            export_workspace_findings_with_options(&workspace, target.path().join(path), &options)
                .unwrap();
        let receipt: serde_json::Value = serde_json::from_slice(
            &fs::read(exported.investigation_receipt_path.unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt["occurrence"]["pending"], 3);
        assert_eq!(receipt["schemaVersion"], 1);
        assert!(receipt["allowance"].is_null());
    }
    let json: serde_json::Value =
        serde_json::from_slice(&fs::read(target.path().join("study.json")).unwrap()).unwrap();
    assert_eq!(
        json["metadata"]["investigation"]["campaignId"],
        "report-study"
    );
    let sarif: serde_json::Value =
        serde_json::from_slice(&fs::read(target.path().join("study.sarif")).unwrap()).unwrap();
    assert_eq!(
        sarif["runs"][0]["properties"]["kuzushiExport"]["investigation"]["campaignId"],
        "report-study"
    );
    let external: serde_json::Value =
        serde_json::from_slice(&fs::read(target.path().join("VULN-FINDINGS.json")).unwrap())
            .unwrap();
    assert_eq!(external["scan_completed"], false);
    let bundle = target.path().join("study-bundle");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(bundle.join("manifest.json")).unwrap()).unwrap();
    for file in manifest["files"].as_array().unwrap() {
        let body = fs::read(bundle.join(file["path"].as_str().unwrap())).unwrap();
        assert_eq!(file["sha256"], text_digest(&body));
    }
    assert!(fs::read_to_string(bundle.join("README.md"))
        .unwrap()
        .contains("(investigation.json)"));
}

#[test]
fn external_completion_requires_nonempty_completed_selected_work() {
    let target = tempfile::tempdir().unwrap();
    let original = super::super::investigation_report::tests::planned_report(target.path());
    for (planned, completed, failed, pending, expected) in [
        (0, 0, 0, 0, false),
        (3, 0, 0, 3, false),
        (3, 2, 1, 0, false),
        (3, 2, 0, 1, false),
        (3, 3, 0, 0, true),
        (3, 3, 1, 0, false),
        (3, 3, 0, 1, false),
    ] {
        let mut receipt = original.clone();
        receipt.occurrence.planned = planned;
        receipt.occurrence.completed = completed;
        receipt.occurrence.failed = failed;
        receipt.occurrence.pending = pending;
        let body = attach_receipt(
            r#"{"scan_completed":false,"findings":[]}"#.into(),
            WorkspaceExportFormat::VulnFindings,
            Some(&InvestigationReportDocument::Study(receipt)),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["scan_completed"], expected);
        assert_eq!(value["findings"], json!([]));
    }
}

#[test]
fn prepared_export_and_preview_keep_an_unstarted_scan_incomplete() {
    let target = tempfile::tempdir().unwrap();
    super::super::investigation_report::tests::planned_report(target.path());
    let workspace = WorkspaceTarget::new(target.path()).unwrap();
    let config = crate::V2Config::default();
    let registry = crate::modules::ModuleRegistry::with_v2_builtins();
    let ctx = crate::modules::ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let prepared = registry
        .prepare_dispatch_input(
            "workspace:export-findings",
            json!({"output":"pending.json", "format":"vuln-findings", "campaign_id":"report-study", "allowEmpty":true}),
            &ctx,
            None,
        )
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(prepared, &ctx, None)
        .unwrap();
    let body = fs::read(target.path().join("pending.json")).unwrap();
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(document["scan_completed"], false);
    let options = WorkspaceExportOptions::default().with_campaign(Some("report-study".into()));
    let preview = preview_workspace_findings_export(
        &workspace,
        WorkspaceExportFormat::VulnFindings,
        &options,
    )
    .unwrap();
    let document: serde_json::Value = serde_json::from_str(&preview.body).unwrap();
    assert_eq!(document["scan_completed"], false);
}
