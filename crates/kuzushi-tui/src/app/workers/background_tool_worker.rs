use super::*;

#[derive(Debug)]
pub(crate) enum ScanEvent {
    Stage(String),
    Finished { result: serde_json::Value },
    Failed { error: String },
}

#[derive(Debug)]
#[allow(dead_code)] // Legacy/unobserved variants remain for in-crate compatibility tests.
pub(crate) enum ToolEvent {
    Finished {
        tool_name: String,
        result: serde_json::Value,
    },
    Failed {
        tool_name: String,
        error: String,
    },
    Refused {
        tool_name: String,
        error: String,
    },
    ObservedFinished {
        tool_name: String,
        result: serde_json::Value,
        completion: kuzushi_core::PendingToolCallCompletion,
    },
    ObservedFailed {
        tool_name: String,
        error: String,
        completion: kuzushi_core::PendingToolCallCompletion,
    },
    ObservedRefused {
        tool_name: String,
        error: String,
        completion: kuzushi_core::PendingToolCallCompletion,
    },
    AuthenticationFailed {
        tool_name: String,
        error: String,
        completion: Option<kuzushi_core::PendingToolCallCompletion>,
    },
}

#[derive(Debug)]
pub(crate) enum AgentEvent {
    ResponseText(kuzushi_openai::langgraph_runtime::ResponseTextEvent),
    Answered {
        text: String,
        audit: AgentCallAudit,
    },
    Failed {
        error: String,
        audit: AgentCallAudit,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct AgentCallAudit {
    pub(crate) cost: kuzushi_core::runtime::RuntimeCostReport,
    pub(crate) call_attempted: bool,
    pub(crate) tool_policy_receipt: Option<kuzushi_core::runtime::AgentToolPolicyReceipt>,
    pub(crate) failure: Option<kuzushi_core::runtime::RuntimeFailureMetadata>,
}

impl AgentCallAudit {
    pub(crate) fn for_prompt(_model: &str, _system_prompt: &str, _prompt: &str) -> Self {
        Self {
            cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
            call_attempted: false,
            tool_policy_receipt: None,
            failure: None,
        }
    }

    pub(crate) fn with_cost(mut self, cost: kuzushi_core::runtime::RuntimeCostReport) -> Self {
        self.cost = cost;
        self.call_attempted = true;
        self
    }

    pub(crate) fn with_outcome(
        mut self,
        cost: kuzushi_core::runtime::RuntimeCostReport,
        call_attempted: bool,
    ) -> Self {
        self.cost = cost;
        self.call_attempted = call_attempted;
        self
    }

    pub(crate) fn with_tool_policy_receipt(
        mut self,
        receipt: kuzushi_core::runtime::AgentToolPolicyReceipt,
    ) -> Self {
        self.tool_policy_receipt = Some(receipt);
        self
    }

    pub(crate) fn settlement_cost(&self) -> kuzushi_core::runtime::RuntimeCostReport {
        if !self.call_attempted {
            return kuzushi_core::runtime::RuntimeCostReport::known(
                kuzushi_core::runtime::RuntimeCost::ZERO,
            );
        }
        if self.cost.is_unavailable() {
            kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO
        } else {
            self.cost
        }
    }

    #[cfg(test)]
    pub(crate) fn test() -> Self {
        Self::for_prompt("test:model", "system", "prompt")
    }
}

pub(crate) type CostedWorkerResult<T> =
    Result<(T, kuzushi_core::runtime::RuntimeCostReport), CostedWorkerError>;

#[derive(Debug)]
pub(crate) struct CostedWorkerError {
    pub(crate) error: anyhow::Error,
    pub(crate) cost: kuzushi_core::runtime::RuntimeCostReport,
    pub(crate) call_attempted: bool,
}

impl CostedWorkerError {
    pub(crate) fn before_call(error: anyhow::Error) -> Self {
        Self {
            error,
            cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
            call_attempted: false,
        }
    }

    pub(crate) fn unresolved(error: anyhow::Error) -> Self {
        Self {
            error,
            cost: kuzushi_core::runtime::RuntimeCostReport::INCOMPLETE_ZERO,
            call_attempted: true,
        }
    }

    pub(crate) fn observed(
        error: anyhow::Error,
        cost: kuzushi_core::runtime::RuntimeCostReport,
    ) -> Self {
        Self {
            error,
            cost,
            call_attempted: true,
        }
    }
}

#[derive(Debug)]
pub(crate) enum PlanEvent {
    // Compatibility event retained for persisted/test event folds; planning now
    // emits reviewed study proposals instead of a worker plan. Only the tests
    // still construct it, so the expectation is scoped to the build where the
    // variant really is dead: a production emitter appearing again leaves the
    // expectation unfulfilled and fails the gate.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "no worker emits a plan proposal any more")
    )]
    Proposed {
        plan: PlanProposal,
        audit: AgentCallAudit,
    },
    Failed {
        error: String,
        audit: AgentCallAudit,
    },
}

#[derive(Debug)]
pub(crate) enum ThreatPatchEvent {
    Proposed {
        patch: ThreatPatch,
        audit: AgentCallAudit,
    },
    #[allow(dead_code)]
    // Compatibility event retained for persisted/test event folds; Ask now uses AgentEvent.
    Answer { text: String, audit: AgentCallAudit },
    Failed {
        error: String,
        audit: AgentCallAudit,
    },
}

pub(crate) fn background_tool_worker(
    registry: ModuleRegistry,
    config: V2Config,
    workspace: WorkspaceTarget,
    tool_name: String,
    input: PreparedToolInput,
    run_id: String,
    thinking_level: Option<String>,
    authorization: ExecutionAuthorization,
    sink: JobEventSink,
    trace_handle: Option<TraceHandle>,
    cancel: ScanCancellation,
) {
    if cancel.is_cancelled() {
        sink.send(ShellEvent::Tool(ToolEvent::Failed {
            tool_name,
            error: "tool run cancelled before start".to_string(),
        }));
        return;
    }
    let result = run_background_tool_observed(
        registry,
        config,
        &workspace,
        &tool_name,
        input,
        &run_id,
        thinking_level,
        authorization,
        trace_handle,
        cancel.clone(),
    );
    send_tool_event(&sink, tool_result_event(tool_name, result));
}

fn send_tool_event(sink: &JobEventSink, event: ToolEvent) {
    sink.send(ShellEvent::Tool(event));
}

fn tool_result_event(
    tool_name: String,
    result: Result<kuzushi_core::ObservedDispatchOutcome>,
) -> ToolEvent {
    match result {
        Ok(outcome) => match outcome.execution {
            Ok(result) => ToolEvent::ObservedFinished {
                tool_name,
                result,
                completion: outcome.completion,
            },
            Err(error) => observed_failure_event(tool_name, error, outcome.completion),
        },
        Err(error) => failed_tool_event(tool_name, error),
    }
}

fn observed_failure_event(
    tool_name: String,
    error: anyhow::Error,
    completion: kuzushi_core::PendingToolCallCompletion,
) -> ToolEvent {
    if is_authentication_failure(&error) {
        return ToolEvent::AuthenticationFailed {
            tool_name,
            error: format!("{error:#}"),
            completion: Some(completion),
        };
    }
    if rejected_before_execution(&completion) {
        return ToolEvent::ObservedRefused {
            tool_name,
            error: format!("{error:#}"),
            completion,
        };
    }
    ToolEvent::ObservedFailed {
        tool_name,
        error: format!("{error:#}"),
        completion,
    }
}

fn rejected_before_execution(completion: &kuzushi_core::PendingToolCallCompletion) -> bool {
    completion.terminal_status() == kuzushi_core::run_lifecycle::RunItemStatus::Blocked
        && !completion.execution_may_have_occurred()
}

fn failed_tool_event(tool_name: String, error: anyhow::Error) -> ToolEvent {
    if error.chain().any(|cause| {
        cause
            .downcast_ref::<kuzushi_core::modules::AutonomyRefusal>()
            .is_some()
    }) {
        return ToolEvent::Refused {
            tool_name,
            error: format!("{error:#}"),
        };
    }
    if is_authentication_failure(&error) {
        return ToolEvent::AuthenticationFailed {
            tool_name,
            error: format!("{error:#}"),
            completion: None,
        };
    }
    ToolEvent::Failed {
        tool_name,
        // `{:#}` walks the full anyhow chain so operators see the
        // underlying provider/bridge cause (e.g. "Anthropic API 429
        // Too Many Requests"), not just the topmost wrap
        // ("agent loop step 0 failed"). Without this, debugging
        // model-side failures from the shell requires digging into
        // `.kuzushi/v3/runs/<id>/items.jsonl` or rerunning under `kuzushi run`.
        error: format!("{error:#}"),
    }
}

fn is_authentication_failure(error: &anyhow::Error) -> bool {
    kuzushi_core::runtime::runtime_failure_metadata(error).is_some_and(|metadata| {
        metadata.error_class == kuzushi_core::runtime::RuntimeFailureClass::Authentication
    })
}

#[cfg(test)]
pub(crate) mod admission_event_tests {
    use super::*;
    use kuzushi_core::{ToolExecutionContext, WorkspaceTarget};

    pub(crate) struct RuntimeMustNotRun;
    impl kuzushi_core::AgentRuntime for RuntimeMustNotRun {
        fn triage_finding_blocking(
            &self,
            _: kuzushi_core::TriageRequest,
        ) -> Result<kuzushi_core::TriageOutcome> {
            panic!("admission must refuse before any model request")
        }
    }

    pub(crate) fn dispatch(
        target: &std::path::Path,
        tool: &str,
        input: serde_json::Value,
        runtime: Option<&dyn kuzushi_core::AgentRuntime>,
    ) -> kuzushi_core::ObservedDispatchOutcome {
        let workspace = WorkspaceTarget::new(target).unwrap();
        let config = V2Config {
            model: Some("openai:gpt-5.5".into()),
            ..Default::default()
        };
        let observation =
            kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(target, "event-fixture")
                .unwrap();
        let trace = observation.trace_handle();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: Some(&trace),
            cancellation: None,
            authorization: Default::default(),
        };
        let registry = ModuleRegistry::with_v2_builtins();
        let prepared = registry
            .prepare_dispatch_input(tool, input, &ctx, None)
            .unwrap()
            .authorize_explicit_headless();
        registry
            .dispatch_prepared_input_observed_with_runtime(prepared, &ctx, runtime)
            .unwrap()
    }

    #[test]
    fn refused_model_admission_is_a_terminal_blocked_event() {
        let root = tempfile::tempdir().unwrap();
        let outcome = dispatch(
            root.path(),
            "context:build",
            serde_json::json!({"enrichment":true}),
            Some(&RuntimeMustNotRun),
        );
        let event = tool_result_event("context:build".into(), Ok(outcome));
        let ToolEvent::ObservedRefused {
            error, completion, ..
        } = event
        else {
            panic!("blocked event required")
        };
        assert!(error.contains("approved investigation allowance"));
        assert_eq!(
            completion.terminal_status(),
            kuzushi_core::run_lifecycle::RunItemStatus::Blocked
        );
        assert!(!completion.execution_may_have_occurred());
        completion.finish(None).unwrap();
        assert!(!root.path().join(".kuzushi/context-snapshot.json").exists());
    }

    #[test]
    fn an_executor_error_keeps_failure_and_possible_work_evidence() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".kuzushi/runs/old")).unwrap();
        let outcome = dispatch(
            root.path(),
            "threat-model:read",
            serde_json::json!({"scope":"id:api","outputDir":".kuzushi/runs/old"}),
            None,
        );
        let event = tool_result_event("threat-model:read".into(), Ok(outcome));
        let ToolEvent::ObservedFailed { completion, .. } = event else {
            panic!("executor failure required")
        };
        assert!(completion.execution_may_have_occurred());
        assert_eq!(
            completion.terminal_status(),
            kuzushi_core::run_lifecycle::RunItemStatus::Failed
        );
        completion.finish(None).unwrap();
    }
}
