#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::config::V2Config;
    use crate::findings::FindingStore;
    use crate::workspace::WorkspaceTarget;

    #[test]
    fn run_verify_exploit_reports_missing_finding_without_running_backend() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
        };

        let response = run_verify_exploit(json!({"fingerprint": "missing"}), &ctx).unwrap();

        assert_eq!(response["ok"], json!(false));
        assert!(response["output"]
            .as_str()
            .unwrap()
            .contains("No finding with fingerprint 'missing'"));
    }
}
