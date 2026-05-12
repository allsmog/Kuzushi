use super::*;

pub(crate) const AGENTIC_SAST_SYSTEM_PROMPT: &str = r#"You are Kuzushi's agentic SAST scanner.
Return only JSON matching:
{"findings":[{"ruleId":"short-rule-id","filePath":"relative/path","startLine":1,"endLine":1,"severity":"ERROR|WARNING|INFO","message":"short finding summary","confidence":"HIGH|MEDIUM|LOW","subcategory":["vuln"],"likelihood":"HIGH|MEDIUM|LOW","impact":"HIGH|MEDIUM|LOW","cwe":["CWE-..."],"evidence":"source-to-sink proof"}]}.
Only report concrete vulnerabilities you can justify from the provided repository inventory and snippets."#;

pub(crate) fn run_agentic_sast_report(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<AgenticSastReport> {
    let runtime = required_agentic_sast_runtime(runtime)?;
    let run = AgenticSastRun::from_input(input, ctx)?;
    let parent_step = ctx.trace.and_then(|trace| {
        Some(
            trace
                .step(
                    "tool",
                    "scan",
                    format!(
                        "agentic-sast start · target={} inventory={}",
                        run.target.display(),
                        run.inventory.len()
                    ),
                )
                .emit(),
        )
    });
    let agent_call_phase = match (ctx.trace, parent_step) {
        (Some(trace), Some(parent)) => Some(
            trace
                .child(parent)
                .step("reasoning", "scan", "agent-call")
                .emit(),
        ),
        _ => None,
    };
    // Push the agent-call phase as parent so every inner LLM round-trip
    // surfaces as an indented child in the feed.
    let _llm_scope = match (ctx.trace, agent_call_phase) {
        (Some(trace), Some(phase)) => Some(trace.parent_scope(phase)),
        _ => None,
    };
    let mut findings = query_agentic_sast_findings(runtime, &run, None)?;
    drop(_llm_scope);
    if let (Some(trace), Some(parent)) = (ctx.trace, parent_step) {
        let _ = trace
            .child(parent)
            .step(
                "reasoning",
                "scan",
                format!("static-validation · {} candidate findings", findings.len()),
            )
            .emit();
    }
    let _validation_scope = match (ctx.trace, parent_step) {
        (Some(trace), Some(parent)) => {
            let phase = trace
                .child(parent)
                .step("reasoning", "scan", "static-validation review-loop")
                .emit();
            Some(trace.parent_scope(phase))
        }
        _ => None,
    };
    findings = maybe_review_agentic_sast_findings(runtime, &run, findings)?;
    drop(_validation_scope);
    if run.whitebox_static {
        mark_whitebox_static_findings(&mut findings, StaticProofState::CodeCited)?;
    }

    let persisted = persist_agentic_sast_findings(&run.target, &findings, ctx)?;
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "scan",
                format!("agentic-sast complete · {} findings", findings.len()),
            )
            .emit();
    }
    Ok(AgenticSastReport {
        target: run.target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        cost_usd: 0.0,
    })
}

pub(crate) struct AgenticSastRun {
    pub(crate) target: PathBuf,
    pub(crate) options: AgenticSastInput,
    pub(crate) model: String,
    pub(crate) system_prompt: String,
    pub(crate) tool_policy: AgentToolPolicy,
    pub(crate) whitebox_static: bool,
    pub(crate) inventory: Vec<(String, String)>,
}

impl AgenticSastRun {
    pub(crate) fn from_input(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Self> {
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

pub(crate) fn required_agentic_sast_runtime(
    runtime: Option<&dyn AgentRuntime>,
) -> Result<&dyn AgentRuntime> {
    runtime.context(
        "agentic-sast:scan requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
    )
}

pub(crate) fn resolve_agentic_sast_target(
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

pub(crate) fn agentic_sast_model(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<String> {
    crate::runtime::resolve_explicit_model(
        "agentic-sast:scan",
        optional_nonempty_string(input, "model")?,
        ctx.config.model.as_deref(),
    )
}

pub(crate) fn agentic_sast_system_prompt(whitebox_static: bool) -> String {
    if whitebox_static {
        whitebox_static_triage_system_prompt().to_string()
    } else {
        AGENTIC_SAST_SYSTEM_PROMPT.to_string()
    }
}
