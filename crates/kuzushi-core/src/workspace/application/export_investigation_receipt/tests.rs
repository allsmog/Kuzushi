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
