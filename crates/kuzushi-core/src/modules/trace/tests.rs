mod cancellation;

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
    use crate::allowance::{AllowanceBinding, InvestigationWork};
    use crate::config::V2Config;
    use crate::findings::{Finding, FindingStore, Severity};
    use crate::modules::ModuleRegistry;
    use crate::runtime::{
        AgentQueryRequest, AgentQueryResponse, AgentRuntime, RuntimeCost, RuntimeCostReport,
    };
    use crate::{ToolExecutionContext, WorkspaceTarget};
    use serde_json::{json, Value};

    fn dispatch_expansion(exact: bool, calls: Option<u64>) -> anyhow::Result<Value> {
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
        if let Some(calls) = calls {
            approve_expansion(&registry, &ctx, calls);
        }
        let prepared = registry
            .prepare_dispatch_input(
                "trace:expand",
                json!({"fingerprint": finding.fingerprint,
                    "allowanceRef":{"schemaVersion":1,"investigationId":"owned-trace","revision":1,"workId":"trace-1"}}),
                &ctx,
                None,
            )
            ?;
        registry.dispatch_prepared_input_with_runtime(
            prepared,
            &ctx,
            Some(&ZeroStepRuntime {
                exact,
                binding: None,
            }),
        )
    }

    fn approve_expansion(registry: &ModuleRegistry, ctx: &ToolExecutionContext<'_>, calls: u64) {
        let prepared = registry.prepare_dispatch_input("campaign:approve-allowance", json!({
            "investigationId":"owned-trace","expectedRevision":0,"model":"openai:gpt-5.5",
            "maxProviderCalls":calls,"protectedReviewCalls":1,"reason":"Owned source-only trace regression"
        }),ctx,None).unwrap().authorize_explicit_headless();
        registry
            .dispatch_prepared_input_with_runtime(prepared, ctx, None)
            .unwrap();
    }

    #[test]
    fn trace_dispatch_preserves_unmetered_zero_and_partial_zero_step_outcome() {
        let output = dispatch_expansion(false, Some(2)).unwrap();
        assert_eq!(output["status"], "partial");
        assert_eq!(output["data"]["sourceReferencesVerified"], false);
        assert_eq!(output["data"]["dataflowVerified"], false);
        assert_eq!(output["data"]["coverage"]["complete"], false);
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
        let output = dispatch_expansion(true, Some(2)).unwrap();
        let cost = crate::run_artifacts::tool_run_output_cost_report(&output).unwrap();
        assert_eq!(cost.exact_usd(), Some(0.0));
        assert!(output["data"].get("observedCostUsd").is_none());
    }

    #[test]
    fn optional_trace_cannot_borrow_protected_review_capacity() {
        assert!(dispatch_expansion(true, Some(1)).is_err());
        assert!(dispatch_expansion(true, None).is_err());
    }

    #[derive(Clone)]
    struct ZeroStepRuntime {
        exact: bool,
        binding: Option<AllowanceBinding>,
    }
    impl AgentRuntime for ZeroStepRuntime {
        fn allowance_binding(&self) -> Option<&AllowanceBinding> {
            self.binding.as_ref()
        }
        fn with_allowance_binding(
            &self,
            binding: AllowanceBinding,
        ) -> anyhow::Result<Box<dyn AgentRuntime + '_>> {
            Ok(Box::new(Self {
                binding: Some(binding),
                ..self.clone()
            }))
        }
        fn query_blocking(&self, request: AgentQueryRequest) -> anyhow::Result<AgentQueryResponse> {
            assert_eq!(request.model, "openai:gpt-5.5");
            let binding = self.binding.as_ref().unwrap();
            assert_eq!(binding.work().work, InvestigationWork::Discovery);
            let reservation = binding.reserve(&request.model)?;
            let cost = if self.exact {
                RuntimeCostReport::known(RuntimeCost::ZERO)
            } else {
                RuntimeCostReport::incomplete(RuntimeCost::ZERO)
            };
            binding.settle(reservation, cost)?;
            Ok(AgentQueryResponse {
                cost_usd_reported: self.exact,
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
