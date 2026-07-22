#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::config::V2Config;
    use crate::findings::FindingStore;
    use crate::workspace::WorkspaceTarget;

    #[test]
    fn run_trace_expand_reports_missing_finding_without_running_backend() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let runtime = UnusedRuntime;

        let response = run_trace_expand(
            json!({"fingerprint": "missing", "instruction": "follow the length"}),
            &ctx,
            Some(&runtime),
        )
        .unwrap();

        assert_eq!(response["ok"], json!(false));
        assert!(response["output"]
            .as_str()
            .unwrap()
            .contains("No finding with fingerprint 'missing'"));
    }

    struct UnusedRuntime;

    impl crate::runtime::AgentRuntime for UnusedRuntime {
        fn triage_finding_blocking(
            &self,
            _request: crate::runtime::TriageRequest,
        ) -> anyhow::Result<crate::findings::TriageOutcome> {
            anyhow::bail!("runtime must not be consulted before the finding resolves")
        }
    }

    #[test]
    fn run_trace_expand_requires_a_fingerprint() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let runtime = UnusedRuntime;

        let error = run_trace_expand(json!({}), &ctx, Some(&runtime)).unwrap_err();
        assert!(error.to_string().contains("finding fingerprint"));
    }
}
