use super::*;

pub(crate) fn run_background_tool(
    registry: ModuleRegistry,
    config: V2Config,
    workspace: &WorkspaceTarget,
    tool_name: &str,
    input: serde_json::Value,
    run_id: &str,
    thinking_level: Option<String>,
) -> Result<serde_json::Value> {
    let store = if tool_requires_findings_store(tool_name) {
        Some(FindingStore::open(workspace.findings_db_path())?)
    } else {
        None
    };
    let runtime = if tool_uses_agent_runtime_for(tool_name, &input) {
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
    let trace = TraceHandle::jsonl(workspace.root(), run_id)
        .for_tool(tool_name)
        .child(1);
    let traced_runtime = runtime
        .as_ref()
        .map(|runtime| TracedRuntime::new(runtime as &dyn AgentRuntime, trace));
    let runtime_ref = traced_runtime
        .as_ref()
        .map(|runtime| runtime as &dyn AgentRuntime)
        .or_else(|| runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime));
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: Some(workspace),
        findings_store: store.as_ref(),
    };
    registry.execute_tool_with_runtime(tool_name, input, &ctx, runtime_ref)
}

pub(crate) fn tool_uses_agent_runtime_for(tool_name: &str, input: &serde_json::Value) -> bool {
    if tool_name == "sast:scan" {
        return kuzushi_core::modules::wants_sast_runtime(input);
    }
    tool_uses_agent_runtime(tool_name)
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
    matches!(
        tool_name,
        "triage:run"
            | "verify:finding"
            | "patch:finding"
            | "agentic-sast:scan"
            | "carlini-threat-hunt:run"
            | "vendor-assessment:assess"
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
            | "ndiff:extract-fix-pattern"
            | "ndiff:hunt-variants"
            | "systems-hunt:systems-invariant-extract"
            | "systems-hunt:systems-trigger-synth"
            | "systems-hunt:systems-hunt"
            | "systems-hunt:deep-semantic-cwe-select"
            | "systems-hunt:deep-semantic-hunt"
            | "taint-iris:hunt"
            | "taint-iris-next:hunt"
            | "threat-model:build"
            | "randori:pasta"
            | "x-ray:run"
            | "x-ray:x-ray"
    )
}
