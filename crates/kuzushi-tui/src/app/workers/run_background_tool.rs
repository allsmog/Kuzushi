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
    cancel: ScanCancellation,
) -> Result<serde_json::Value> {
    let store = background_findings_store(tool_name, workspace)?;
    let runtime = background_agent_runtime(&config, tool_name, &input, thinking_level, cancel)?;
    let trace = trace_handle
        .unwrap_or_else(|| TraceHandle::jsonl(workspace.root(), run_id))
        .for_tool(tool_name)
        .child(1);
    let runtime_ref = runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime);
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: store.as_ref(),
        trace: Some(&trace),
    };
    registry.execute_tool_with_runtime(tool_name, input, &ctx, runtime_ref)
}

fn background_findings_store(
    tool_name: &str,
    workspace: &WorkspaceTarget,
) -> Result<Option<FindingStore>> {
    if tool_requires_findings_store(tool_name) {
        return Ok(Some(FindingStore::open(workspace.findings_db_path())?));
    }
    Ok(None)
}

fn background_agent_runtime(
    config: &V2Config,
    tool_name: &str,
    input: &serde_json::Value,
    thinking_level: Option<String>,
    cancel: ScanCancellation,
) -> Result<Option<LangGraphRuntime>> {
    if !wants_background_runtime(config, tool_name, input) {
        return Ok(None);
    }
    Ok(Some(
        LangGraphRuntime::from_config(config, background_current_dir())?
            .with_thinking_level(thinking_level)
            .with_cancellation(cancel),
    ))
}

/// Whether to construct a runtime for a background tool. Required tools always
/// get one; the recommender opts in *only* when a model is configured, so it
/// can rank with the session model yet still run deterministically (no runtime)
/// when no model is set.
fn wants_background_runtime(config: &V2Config, tool_name: &str, input: &serde_json::Value) -> bool {
    if tool_needs_runtime(tool_name, input) {
        return true;
    }
    tool_name == "module-recommender:recommend" && config.model.is_some()
}

fn background_current_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub(crate) fn tool_requires_findings_store(tool_name: &str) -> bool {
    tool_name.starts_with("findings:")
        || tool_name.starts_with("module-recommender:")
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
                | "offense-review:threat-hunt"
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
                | "taint-iris-next:finding-review"
                | "taint-iris-next:hunt"
                | "sast:scan"
                | "semgrep:scan"
                | "codeql:scan"
                | "iac-scan:scan"
                | "license-scan:scan"
                | "cargo-audit:scan"
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
    fn recommender_has_finding_store_access() {
        assert!(super::tool_requires_findings_store(
            "module-recommender:recommend"
        ));
        assert!(super::tool_requires_findings_store(
            "taint-iris-next:finding-review"
        ));
        assert!(super::tool_requires_findings_store(
            "offense-review:threat-hunt"
        ));
        assert!(super::tool_requires_findings_store("cargo-audit:scan"));
        assert!(!super::tool_requires_findings_store(
            "taint-iris-next:dataflow-plan"
        ));
    }
}
