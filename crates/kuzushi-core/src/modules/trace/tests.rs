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

#[cfg(test)]
mod cost_contract_tests {
    use crate::config::V2Config;
    use crate::findings::{Finding, FindingStore, Severity};
    use crate::modules::ModuleRegistry;
    use crate::runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime};
    use crate::{ToolExecutionContext, WorkspaceTarget};
    use serde_json::{json, Value};

    fn dispatch_expansion(exact: bool) -> Value {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let finding = Finding::new_tool(
            "test",
            "trace",
            "input.c",
            1,
            None,
            Severity::High,
            "unresolved caller",
        );
        store
            .insert_scan_run("scan", temp.path(), "completed")
            .unwrap();
        store.insert_finding("scan", &finding).unwrap();
        let config = V2Config {
            model: Some("openai:gpt-5.5".into()),
            ..Default::default()
        };
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: Some(&store),
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let prepared = registry
            .prepare_dispatch_input(
                "trace:expand",
                json!({"fingerprint": finding.fingerprint}),
                &ctx,
                None,
            )
            .unwrap();
        registry
            .dispatch_prepared_input_with_runtime(prepared, &ctx, Some(&ZeroStepRuntime(exact)))
            .unwrap()
    }

    #[test]
    fn trace_dispatch_preserves_unmetered_zero_and_complete_zero_step_outcome() {
        let output = dispatch_expansion(false);
        let cost = crate::run_artifacts::tool_run_output_cost_report(&output).unwrap();
        assert!(!cost.is_complete());
        assert_eq!(cost.observed_usd(), 0.0);
        assert!(output["data"].get("costUsd").is_none());
        assert_eq!(output["data"]["providerSpendUnresolved"], true);
        assert_eq!(output["data"]["steps"], json!([]));
        assert_eq!(
            output["data"]["openQuestions"],
            json!(["caller unresolved"])
        );
        assert!(output["summary"].as_str().unwrap().contains("0 steps"));
    }

    #[test]
    fn trace_dispatch_preserves_provider_reported_exact_zero() {
        let output = dispatch_expansion(true);
        let cost = crate::run_artifacts::tool_run_output_cost_report(&output).unwrap();
        assert_eq!(cost.exact_usd(), Some(0.0));
        assert!(output["data"].get("observedCostUsd").is_none());
    }

    struct ZeroStepRuntime(bool);
    impl AgentRuntime for ZeroStepRuntime {
        fn query_blocking(&self, request: AgentQueryRequest) -> anyhow::Result<AgentQueryResponse> {
            assert_eq!(request.model, "openai:gpt-5.5");
            Ok(AgentQueryResponse {
                cost_usd_reported: self.0,
                structured: Some(json!({"version":1,"findingFingerprint":"echo",
                    "steps":[],"openQuestions":["caller unresolved"],
                    "evidenceDeltas":["no intermediary hops"]})),
                ..Default::default()
            })
        }
        fn triage_finding_blocking(
            &self,
            _: crate::runtime::TriageRequest,
        ) -> anyhow::Result<crate::findings::TriageOutcome> {
            anyhow::bail!("unexpected triage")
        }
    }
}
