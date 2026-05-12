use super::*;

pub(crate) fn run_background_tool(
    registry: ModuleRegistry,
    config: V2Config,
    workspace: &WorkspaceTarget,
    tool_name: &str,
    input: serde_json::Value,
    run_id: &str,
    thinking_level: Option<String>,
    trace_handle: Option<TraceHandle>,
) -> Result<serde_json::Value> {
    let store = if tool_requires_findings_store(tool_name) {
        Some(FindingStore::open(workspace.findings_db_path())?)
    } else {
        None
    };
    // Input-aware check: `sast:scan` skips the runtime in
    // scanner-only mode (whitebox-static, no triage/verify/agentic
    // sub-tasks). Name-only tools fall through to the allowlist. See
    // `kuzushi_core::tool_needs_runtime`.
    let runtime = if tool_needs_runtime(tool_name, &input) {
        Some(
            PiAgentCoreRuntime::from_config(
                &config,
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            )?
            .with_thinking_level(thinking_level),
        )
    } else {
        None
    };
    let trace = trace_handle
        .unwrap_or_else(|| TraceHandle::jsonl(workspace.root(), run_id))
        .for_tool(tool_name)
        .child(1);
    let traced_runtime = runtime
        .as_ref()
        .map(|runtime| TracedRuntime::new(runtime as &dyn AgentRuntime, trace.clone()));
    let runtime_ref = traced_runtime
        .as_ref()
        .map(|runtime| runtime as &dyn AgentRuntime)
        .or_else(|| runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime));
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: store.as_ref(),
        trace: Some(&trace),
    };
    registry.execute_tool_with_runtime(tool_name, input, &ctx, runtime_ref)
}

pub(crate) fn tool_requires_findings_store(tool_name: &str) -> bool {
    tool_name.starts_with("findings:")
        || tool_name.starts_with("systems-hunt:")
        || tool_name.starts_with("chrome-rce:")
        || tool_name.starts_with("uaf-hunt:")
        || matches!(
            tool_name,
            "triage:run"
                | "verify:finding"
                | "verify:exploit"
                | "patch:finding"
                | "agentic-sast:scan"
                | "carlini-threat-hunt:run"
                | "vuln-scout:audit"
                | "tob:audit"
                | "shinsa:scan"
                | "shinsa:quick-check"
                | "shinsa:nist-scan"
                | "shinsa:nist-quick-check"
                | "prompt-armor:scan"
                | "prompt-armor:analyze"
                | "prompt-armor:attack"
                | "variant:lift-pattern"
                | "variant:hunt"
                | "ndiff:hunt-variants"
                | "taint-iris:hunt"
                | "taint-iris-next:hunt"
                | "sast:scan"
                | "semgrep:scan"
                | "codeql:scan"
                | "iac-scan:scan"
        )
}

#[cfg(test)]
mod tests {
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
    fn deterministic_tools_skip_runtime() {
        assert!(!tool_uses_agent_runtime("semgrep:scan"));
        assert!(!tool_uses_agent_runtime("secret-scan:scan"));
        assert!(!tool_uses_agent_runtime("context:build"));
        assert!(!tool_uses_agent_runtime("findings:list"));
        // Hidden DAG node that's purely deterministic surface gathering.
        assert!(!tool_uses_agent_runtime(
            "systems-hunt:systems-context-gatherer"
        ));
    }
}
