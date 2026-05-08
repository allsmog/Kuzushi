use super::prelude::*;
use super::*;

pub(in crate::modules) const AGENTIC_SAST_SYSTEM_PROMPT: &str = r#"You are Kuzushi's agentic SAST scanner.
Return only JSON matching:
{"findings":[{"ruleId":"short-rule-id","filePath":"relative/path","startLine":1,"endLine":1,"severity":"ERROR|WARNING|INFO","message":"short finding summary","confidence":"HIGH|MEDIUM|LOW","subcategory":["vuln"],"likelihood":"HIGH|MEDIUM|LOW","impact":"HIGH|MEDIUM|LOW","cwe":["CWE-..."],"evidence":"source-to-sink proof"}]}.
Only report concrete vulnerabilities you can justify from the provided repository inventory and snippets."#;

pub(in crate::modules) fn run_agentic_sast_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<AgenticSastReport> {
    let runtime = required_agentic_sast_runtime(runtime)?;
    let run = AgenticSastRun::from_input(input, ctx)?;
    let mut findings = query_agentic_sast_findings(runtime, &run, None)?;
    findings = maybe_review_agentic_sast_findings(runtime, &run, findings)?;
    if run.whitebox_static {
        mark_whitebox_static_findings(&mut findings, StaticProofState::CodeCited)?;
    }

    let persisted = persist_agentic_sast_findings(&run.target, &findings, ctx)?;
    Ok(AgenticSastReport {
        target: run.target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        cost_usd: 0.0,
    })
}

pub(in crate::modules) struct AgenticSastRun {
    pub(in crate::modules) target: PathBuf,
    pub(in crate::modules) options: AgenticSastInput,
    pub(in crate::modules) model: String,
    pub(in crate::modules) system_prompt: String,
    pub(in crate::modules) tool_policy: AgentToolPolicy,
    pub(in crate::modules) whitebox_static: bool,
    pub(in crate::modules) inventory: Vec<(String, String)>,
}

impl AgenticSastRun {
    pub(in crate::modules) fn from_input(
        input: &Value,
        ctx: &ToolExecutionContext<'_>,
    ) -> Result<Self> {
        let target = resolve_agentic_sast_target(input, ctx)?;
        let options = AgenticSastInput::from_tool_input(input)?;
        let model = agentic_sast_model(input, ctx)?;
        let whitebox_static = whitebox_static_profile_requested(input)?;
        let system_prompt = agentic_sast_system_prompt(whitebox_static);
        let tool_policy = agent_tool_policy_for_input(input)?;
        let inventory = collect_agentic_repo_inventory(&target, 80, 2048)?;
        Ok(Self {
            target,
            options,
            model,
            system_prompt,
            tool_policy,
            whitebox_static,
            inventory,
        })
    }
}

pub(in crate::modules) fn required_agentic_sast_runtime(
    runtime: Option<&dyn AgentRuntime>,
) -> Result<&dyn AgentRuntime> {
    runtime.context(
        "agentic-sast:scan requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )
}

pub(in crate::modules) fn resolve_agentic_sast_target(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    let target = resolve_tool_target(input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "agentic-sast: target is not a directory: {}",
            target.display()
        );
    }
    Ok(target)
}

pub(in crate::modules) fn agentic_sast_model(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<String> {
    optional_nonempty_string(input, "model")?
        .or_else(|| ctx.config.model.clone())
        .context(
            "agentic-sast:scan requires an explicit model in config.toml, KUZUSHI_MODEL, or tool input; Kuzushi will not choose a fallback model",
        )
}

pub(in crate::modules) fn agentic_sast_system_prompt(whitebox_static: bool) -> String {
    if whitebox_static {
        whitebox_static_triage_system_prompt().to_string()
    } else {
        AGENTIC_SAST_SYSTEM_PROMPT.to_string()
    }
}
