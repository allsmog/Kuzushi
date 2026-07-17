use super::*;

#[cfg(test)]
pub(crate) fn run_background_tool(
    registry: ModuleRegistry,
    config: V2Config,
    workspace: &WorkspaceTarget,
    tool_name: &str,
    input: PreparedToolInput,
    run_id: &str,
    thinking_level: Option<String>,
    authorization: ExecutionAuthorization,
    trace_handle: Option<TraceHandle>,
    cancel: ScanCancellation,
) -> Result<serde_json::Value> {
    run_background_tool_observed(
        registry,
        config,
        workspace,
        tool_name,
        input,
        run_id,
        thinking_level,
        authorization,
        trace_handle,
        cancel,
    )?
    .settle_without_result_artifact()
}

pub(crate) fn run_background_tool_observed(
    registry: ModuleRegistry,
    config: V2Config,
    workspace: &WorkspaceTarget,
    tool_name: &str,
    input: PreparedToolInput,
    run_id: &str,
    thinking_level: Option<String>,
    authorization: ExecutionAuthorization,
    trace_handle: Option<TraceHandle>,
    cancel: ScanCancellation,
) -> Result<kuzushi_core::ObservedDispatchOutcome> {
    let store = background_findings_store(&registry, tool_name, workspace)?;
    let runtime = background_agent_runtime(
        &registry,
        &config,
        tool_name,
        input.value(),
        thinking_level,
        &cancel,
        workspace,
    )?;
    let trace = background_tool_trace(trace_handle, workspace, run_id, tool_name)?;
    let runtime_ref = runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime);
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: store.as_ref(),
        trace: Some(&trace),
        cancellation: Some(&cancel),
        authorization: Default::default(),
    };
    let prepared = authorize_background_prepared_input(input, authorization)?;
    mark_background_task_running(&trace)?;
    registry.dispatch_prepared_input_observed_with_runtime(prepared, &ctx, runtime_ref)
}

fn mark_background_task_running(trace: &TraceHandle) -> Result<()> {
    if let Some(task) = trace
        .run_observation()
        .and_then(|observation| observation.task_handle())
    {
        task.update_and_flush(kuzushi_core::run_lifecycle::RunItemStatus::Running, None)?;
    }
    Ok(())
}

fn background_tool_trace(
    trace_handle: Option<TraceHandle>,
    workspace: &WorkspaceTarget,
    run_id: &str,
    tool_name: &str,
) -> Result<TraceHandle> {
    let trace = match trace_handle {
        Some(trace) => trace,
        None => kuzushi_core::run_lifecycle::RunObservationHandle::jsonl(workspace.root(), run_id)?
            .start_root_task(format!("Run {tool_name}"))?
            .trace_handle(),
    };
    Ok(trace.for_tool(tool_name).child(1))
}

fn authorize_background_prepared_input(
    prepared: kuzushi_core::PreparedToolInput,
    authorization: ExecutionAuthorization,
) -> Result<kuzushi_core::PreparedToolInput> {
    if prepared.tool_name() == "patch:reverify" {
        let detector = prepared
            .value()
            .get("detectorTool")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        if let Some(detector) = detector {
            return prepared
                .authorize_requested_with_delegated_tools(authorization, &[detector.as_str()]);
        }
    }
    let delegates_patch = prepared.tool_name() == "sast:scan"
        && prepared
            .value()
            .get("autoPatch")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
    let prepared = if delegates_patch {
        prepared.authorize_requested_with_delegated_tools(authorization, &["patch:finding"])?
    } else {
        prepared.authorize_requested(authorization)?
    };
    Ok(prepared)
}

fn background_findings_store(
    registry: &ModuleRegistry,
    tool_name: &str,
    workspace: &WorkspaceTarget,
) -> Result<Option<FindingStore>> {
    if registry.tool_requires_finding_store(tool_name) {
        return Ok(Some(FindingStore::open(workspace.findings_db_path())?));
    }
    Ok(None)
}

fn background_agent_runtime(
    registry: &ModuleRegistry,
    config: &V2Config,
    tool_name: &str,
    input: &serde_json::Value,
    thinking_level: Option<String>,
    cancel: &ScanCancellation,
    workspace: &WorkspaceTarget,
) -> Result<Option<LangGraphRuntime>> {
    if !registry.tool_wants_runtime(tool_name, input, config) {
        return Ok(None);
    }
    Ok(Some(
        LangGraphRuntime::from_config(config, workspace.root().to_path_buf())?
            .with_thinking_level(thinking_level)
            .with_cancellation(cancel.clone()),
    ))
}

#[cfg(test)]
pub(crate) fn tool_requires_findings_store(tool_name: &str) -> bool {
    ModuleRegistry::with_v2_builtins().tool_requires_finding_store(tool_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::tool_uses_agent_runtime;

    #[test]
    fn full_mode_hunt_requires_agent_runtime() {
        // Regression: full-mode:hunt was missing from the predicate, so the
        // shell worker passed runtime=None and the tool failed with
        // "full-mode:hunt requires an agent runtime; none configured" the
        // moment a non-dry-run scan started.
        assert!(tool_uses_agent_runtime("full-mode:hunt"));
    }

    #[test]
    fn deep_audit_run_requires_agent_runtime() {
        // Regression: deep-audit:run was missing from the shell-worker
        // predicate even though the CLI listed it, so `run deep-audit:run`
        // from the TUI failed immediately with "requires an agent runtime;
        // none configured".
        assert!(tool_uses_agent_runtime("deep-audit:run"));
    }

    #[test]
    fn taint_iris_next_review_requires_agent_runtime() {
        assert!(tool_uses_agent_runtime("taint-iris-next:finding-review"));
    }

    #[test]
    fn offense_review_threat_hunt_requires_agent_runtime() {
        assert!(tool_uses_agent_runtime("offense-review:threat-hunt"));
    }

    #[test]
    fn deterministic_tools_skip_runtime() {
        assert!(!tool_uses_agent_runtime("semgrep:scan"));
        assert!(!tool_uses_agent_runtime("cargo-audit:scan"));
        assert!(!tool_uses_agent_runtime("secret-scan:scan"));
        assert!(!tool_uses_agent_runtime("context:build"));
        assert!(!tool_uses_agent_runtime("module-recommender:recommend"));
        assert!(!tool_uses_agent_runtime("findings:list"));
        assert!(!tool_uses_agent_runtime("taint-iris-next:dataflow-plan"));
        assert!(!tool_uses_agent_runtime(
            "taint-iris-next:source-sink-trace"
        ));
        // Hidden DAG node that's purely deterministic surface gathering.
        assert!(!tool_uses_agent_runtime(
            "systems-hunt:systems-context-gatherer"
        ));
    }

    #[test]
    fn recommender_can_force_deterministic_ranking_without_runtime() {
        let mut config = kuzushi_core::V2Config::default();
        config.model = Some("openai:gpt-5.4".to_string());
        let input = serde_json::json!({ "useModelRanking": false });

        assert!(
            !kuzushi_core::ModuleRegistry::with_v2_builtins().tool_wants_runtime(
                "module-recommender:recommend",
                &input,
                &config,
            )
        );
    }

    #[test]
    fn recommender_has_finding_store_access() {
        assert!(!super::tool_requires_findings_store(
            "module-recommender:recommend"
        ));
        assert!(super::tool_requires_findings_store(
            "taint-iris-next:finding-review"
        ));
        assert!(super::tool_requires_findings_store(
            "offense-review:threat-hunt"
        ));
        assert!(super::tool_requires_findings_store("offense:chain"));
        assert!(!super::tool_requires_findings_store(
            "variant:any-future-tool"
        ));
        assert!(super::tool_requires_findings_store("cargo-audit:scan"));
        assert!(!super::tool_requires_findings_store("sbom-scan:scan"));
        assert!(super::tool_requires_findings_store("secret-scan:scan"));
        assert!(super::tool_requires_findings_store("android-apk:scan"));
        assert!(!super::tool_requires_findings_store(
            "taint-iris-next:dataflow-plan"
        ));
    }

    #[test]
    fn direct_worker_cannot_forge_approval_for_external_effect() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let registry = ModuleRegistry::with_v2_builtins();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        let input = registry
            .prepare_dispatch_input(
                "recon:nmap",
                serde_json::json!({"target": "127.0.0.1"}),
                &ctx,
                None,
            )
            .unwrap();
        let error = run_background_tool(
            registry,
            config,
            &workspace,
            "recon:nmap",
            input,
            "run-test",
            None,
            ExecutionAuthorization::default(),
            None,
            ScanCancellation::default(),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("explicit operator authorization"), "{error}");
    }
}
