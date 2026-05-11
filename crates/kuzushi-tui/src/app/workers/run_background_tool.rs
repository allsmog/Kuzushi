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

