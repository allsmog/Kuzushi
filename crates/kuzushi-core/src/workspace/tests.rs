#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::findings::{Finding, FindingStore, Severity};
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
        assert!(WorkspaceExportFormat::from_input("csv")
            .unwrap_err()
            .to_string()
            .contains("unsupported"));
    }

    #[test]
    fn exports_workspace_findings_to_json() {
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

        let output = tmp.path().join("exports/findings.json");
        let report = export_workspace_findings(&workspace, &output, None).unwrap();

        assert_eq!(report.count, 1);
        assert_eq!(report.format, WorkspaceExportFormat::Json);
        let exported: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(exported["count"], serde_json::json!(1));
        assert_eq!(exported["findings"][0]["rule_id"], "fixture/sql");
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
        let error = export_workspace_findings(&workspace, tmp.path().join("findings.sarif"), None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsupported workspace findings export extension"));
        assert!(error.contains(".json"));
    }
}
