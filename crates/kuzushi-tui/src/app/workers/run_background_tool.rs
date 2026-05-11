use super::*;

pub(crate) fn run_background_tool(
    registry: ModuleRegistry,
    config: V2Config,
    workspace: &WorkspaceTarget,
    tool_name: &str,
    input: serde_json::Value,
    thinking_level: Option<String>,
) -> Result<serde_json::Value> {
    let store = if tool_requires_findings_store(tool_name) {
        Some(FindingStore::open(workspace.findings_db_path())?)
    } else {
        None
    };
    let runtime = if tool_uses_agent_runtime(tool_name) {
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
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: store.as_ref(),
    };
    registry.execute_tool_with_runtime(
        tool_name,
        input,
        &ctx,
        runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime),
    )
}

pub(crate) fn tool_requires_findings_store(tool_name: &str) -> bool {
    tool_name.starts_with("findings:")
        || tool_name.starts_with("systems-hunt:")
        || tool_name.starts_with("chrome-rce:")
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

pub(crate) fn tool_uses_agent_runtime(tool_name: &str) -> bool {
    // Both `sast:scan` and the names in `kuzushi_core::RUNTIME_TOOL_NAMES`
    // need a live runtime. We treat `sast:scan` unconditionally here
    // because the shell worker doesn't have the input ready to inspect the
    // way the CLI does — running it without a runtime fails fast enough
    // that always wiring one in is the cheaper default.
    tool_name == "sast:scan" || kuzushi_core::tool_requires_agent_runtime(tool_name)
}

#[cfg(test)]
mod tests {
    use super::tool_uses_agent_runtime;

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
