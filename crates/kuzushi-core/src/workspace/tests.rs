#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::findings::{Finding, FindingEvidence, FindingStore, Severity};
    use std::fs;

    #[test]
    fn resolves_v2_state_paths_under_project() {
        let tmp = tempfile::tempdir().unwrap();
        let target = WorkspaceTarget::new(tmp.path()).unwrap();

        assert_eq!(target.state_dir(), target.root().join(".kuzushi/v2"));
        assert_eq!(
            target.findings_db_path(),
            target.root().join(".kuzushi/v2/findings.sqlite3")
        );
    }

    #[test]
    fn workspace_export_format_accepts_aliases_and_rejects_unknown_values() {
        assert_eq!(
            WorkspaceExportFormat::from_input(" json ").unwrap(),
            WorkspaceExportFormat::Json
        );
        assert_eq!(
            WorkspaceExportFormat::from_input("NDJSON").unwrap(),
            WorkspaceExportFormat::Jsonl
        );
        assert_eq!(
            WorkspaceExportFormat::from_input("sarif").unwrap(),
            WorkspaceExportFormat::Sarif
        );
        assert_eq!(
            WorkspaceExportFormat::from_input("csv").unwrap(),
            WorkspaceExportFormat::Csv
        );
        assert_eq!(
            WorkspaceExportFormat::from_input("markdown-bundle").unwrap(),
            WorkspaceExportFormat::MarkdownBundle
        );
        assert_eq!(
            WorkspaceExportFormat::from_input("bundle").unwrap(),
            WorkspaceExportFormat::MarkdownBundle
        );
        assert!(WorkspaceExportFormat::from_input("xml")
            .unwrap_err()
            .to_string()
            .contains("unsupported"));
    }

    #[test]
    fn workspace_export_format_resolves_from_output_extension() {
        assert_eq!(
            WorkspaceExportFormat::from_output_path(std::path::Path::new("out.sarif")).unwrap(),
            WorkspaceExportFormat::Sarif
        );
        assert_eq!(
            WorkspaceExportFormat::from_output_path(std::path::Path::new("out.sarif.json"))
                .unwrap(),
            WorkspaceExportFormat::Sarif
        );
        assert_eq!(
            WorkspaceExportFormat::from_output_path(std::path::Path::new("out.csv")).unwrap(),
            WorkspaceExportFormat::Csv
        );
    }

    #[test]
    fn exports_workspace_findings_to_json() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_tool(
            "fixture",
            "fixture/sql",
            "src/app.ts",
            10,
            None,
            Severity::High,
            "request data reaches SQL",
        )
        .with_evidence(vec![FindingEvidence {
            kind: "sink".to_string(),
            file_path: "src/app.ts".to_string(),
            line: 10,
            snippet: "db.query(request.query.q)".to_string(),
            rationale: "The request value is used in a SQL query".to_string(),
            confidence: 91,
        }]);
        store.insert_finding("run-1", &finding).unwrap();

        let output = tmp.path().join("exports/findings.json");
        let report = export_workspace_findings(&workspace, &output, None).unwrap();

        assert_eq!(report.count, 1);
        assert_eq!(report.format, WorkspaceExportFormat::Json);
        let exported: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(exported["count"], serde_json::json!(1));
        assert_eq!(exported["findings"][0]["rule_id"], "fixture/sql");
        assert_eq!(exported["findings"][0]["evidence"][0]["kind"], "sink");
        assert_eq!(
            exported["findings"][0]["evidence"][0]["filePath"],
            "src/app.ts"
        );
    }

    #[test]
    fn workspace_status_reports_persisted_finding_count() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        store
            .insert_finding(
                "run-1",
                &Finding::new_tool(
                    "fixture",
                    "fixture/sql",
                    "src/app.ts",
                    10,
                    None,
                    Severity::High,
                    "request data reaches SQL",
                ),
            )
            .unwrap();

        let status = workspace_status_for_target(Some(workspace.root()), None);

        assert_eq!(status.findings_count, Some(1));
        assert_eq!(status.root.as_deref(), Some(workspace.root()));
        assert!(status.status.contains("workspace ready; 1 finding"));
    }

    #[test]
    fn rejects_unsupported_findings_export_extensions() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let error = export_workspace_findings(&workspace, tmp.path().join("findings.xml"), None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsupported workspace findings export extension"));
        assert!(error.contains(".json"));
    }

    fn fixture_finding(rule_id: &str, severity: Severity, line: u32) -> Finding {
        Finding::new_tool(
            "fixture",
            rule_id,
            "src/app.ts",
            line,
            Some(line + 3),
            severity,
            "request data reaches a dangerous sink",
        )
        .with_evidence(vec![FindingEvidence {
            kind: "sink".to_string(),
            file_path: "src/app.ts".to_string(),
            line,
            snippet: "db.query(request.query.q)".to_string(),
            rationale: "User-controlled value flows into SQL".to_string(),
            confidence: 91,
        }])
    }

    fn seed_workspace_with_findings(workspace: &WorkspaceTarget, count: u32) {
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let severities = [Severity::Critical, Severity::High, Severity::Medium];
        for index in 0..count {
            let severity = severities[(index as usize) % severities.len()];
            let finding =
                fixture_finding(&format!("fixture/rule-{index}"), severity, 10 + index);
            store.insert_finding("run-1", &finding).unwrap();
        }
    }

    #[test]
    fn exports_workspace_findings_to_sarif() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 2);

        let output = tmp.path().join("out.sarif");
        let report = export_workspace_findings(&workspace, &output, None).unwrap();

        assert_eq!(report.format, WorkspaceExportFormat::Sarif);
        assert_eq!(report.count, 2);

        let document: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
        assert_eq!(document["version"], "2.1.0");
        assert_eq!(document["runs"][0]["tool"]["driver"]["name"], "fixture");
        assert!(document["runs"][0]["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| result["ruleId"] == "fixture/rule-0"));
        let first = &document["runs"][0]["results"][0];
        assert!(["error", "warning", "note"]
            .contains(&first["level"].as_str().unwrap()));
        assert!(first["locations"][0]["physicalLocation"]["region"]["startLine"].is_number());
    }

    #[test]
    fn exports_workspace_findings_to_csv() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 2);

        let output = tmp.path().join("out.csv");
        let report = export_workspace_findings(&workspace, &output, None).unwrap();

        assert_eq!(report.format, WorkspaceExportFormat::Csv);
        let body = fs::read_to_string(&output).unwrap();
        let first_line = body.lines().next().unwrap();
        assert!(first_line.starts_with("fingerprint,rule_id,title,severity,tool,file"));
        assert!(body.contains("fixture/rule-0"));
        assert!(body.contains("fixture/rule-1"));
    }

    #[test]
    fn exports_workspace_findings_to_markdown_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 2);

        let output = tmp.path().join("bundle");
        let report = export_workspace_findings(
            &workspace,
            &output,
            Some(WorkspaceExportFormat::MarkdownBundle),
        )
        .unwrap();

        assert_eq!(report.format, WorkspaceExportFormat::MarkdownBundle);
        assert!(output.join("README.md").exists());
        assert!(output.join("manifest.json").exists());

        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["count"], 2);
        let entries = manifest["findings"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        let alias = entries[0]["alias"].as_str().unwrap();
        assert!(output.join("findings").join(format!("{alias}.md")).exists());
    }

    #[test]
    fn markdown_bundle_refuses_non_empty_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        seed_workspace_with_findings(&workspace, 1);

        let output = tmp.path().join("bundle");
        fs::create_dir_all(&output).unwrap();
        fs::write(output.join("stale.txt"), "old").unwrap();

        let err = export_workspace_findings(
            &workspace,
            &output,
            Some(WorkspaceExportFormat::MarkdownBundle),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("must be empty"));
    }
}
