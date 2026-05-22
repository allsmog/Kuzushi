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
    let parent_step = emit_agentic_sast_start(ctx, &run);
    let mut result = collect_agentic_sast_findings(runtime, &run, ctx, parent_step)?;
    apply_agentic_sast_whitebox_profile(&run, &mut result.value)?;
    let persisted = persist_agentic_sast_findings(&run.target, &result.value, ctx)?;
    emit_agentic_sast_done(ctx, result.value.len());
    Ok(agentic_sast_report(
        &run,
        result.value,
        persisted,
        result.cost_usd,
    ))
}

fn collect_agentic_sast_findings(
    runtime: &dyn AgentRuntime,
    run: &AgenticSastRun,
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
) -> Result<CostedStructuredJson<Vec<Finding>>> {
    let mut result = query_agentic_sast_with_scope(runtime, run, ctx, parent_step)?;
    emit_agentic_sast_validation_count(ctx, parent_step, result.value.len());
    let review = review_agentic_sast_with_scope(runtime, run, result.value, ctx, parent_step)?;
    result.value = review.value;
    result.cost_usd += review.cost_usd;
    Ok(result)
}

fn query_agentic_sast_with_scope(
    runtime: &dyn AgentRuntime,
    run: &AgenticSastRun,
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
) -> Result<CostedStructuredJson<Vec<Finding>>> {
    let _llm_scope = begin_agentic_sast_child_scope(ctx, parent_step, "agent-call");
    let findings = query_agentic_sast_findings_with_cost(runtime, run, None)?;
    drop(_llm_scope);
    Ok(findings)
}

fn review_agentic_sast_with_scope(
    runtime: &dyn AgentRuntime,
    run: &AgenticSastRun,
    findings: Vec<Finding>,
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
) -> Result<CostedStructuredJson<Vec<Finding>>> {
    if run.options.passes != 2 || findings.is_empty() {
        return Ok(CostedStructuredJson {
            value: findings,
            cost_usd: 0.0,
        });
    }
    let _validation_scope =
        begin_agentic_sast_child_scope(ctx, parent_step, "static-validation review-loop");
    let review_context = summarize_agentic_findings_for_review(&findings);
    let review = query_agentic_sast_findings_with_cost(runtime, run, Some(&review_context))?;
    let findings = merge_agentic_sast_findings(findings, review.value, run.options.max_findings);
    drop(_validation_scope);
    Ok(CostedStructuredJson {
        value: findings,
        cost_usd: review.cost_usd,
    })
}

fn apply_agentic_sast_whitebox_profile(
    run: &AgenticSastRun,
    findings: &mut [Finding],
) -> Result<()> {
    if run.whitebox_static {
        mark_whitebox_static_findings(findings, StaticProofState::CodeCited)?;
    }
    Ok(())
}

fn agentic_sast_report(
    run: &AgenticSastRun,
    findings: Vec<Finding>,
    persisted: Option<AgenticSastPersistedRun>,
    cost_usd: f64,
) -> AgenticSastReport {
    AgenticSastReport {
        target: run.target.display().to_string(),
        count: findings.len(),
        findings,
        persisted,
        cost_usd,
    }
}

fn emit_agentic_sast_start(ctx: &ToolExecutionContext<'_>, run: &AgenticSastRun) -> Option<usize> {
    ctx.trace.map(|trace| {
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
            .emit()
    })
}

fn emit_agentic_sast_validation_count(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    finding_count: usize,
) {
    if let (Some(trace), Some(parent)) = (ctx.trace, parent_step) {
        let _ = trace
            .child(parent)
            .step(
                "reasoning",
                "scan",
                format!("static-validation · {finding_count} candidate findings"),
            )
            .emit();
    }
}

fn begin_agentic_sast_child_scope(
    ctx: &ToolExecutionContext<'_>,
    parent_step: Option<usize>,
    label: &str,
) -> Option<crate::run_artifacts::ParentScope> {
    let trace = ctx.trace?;
    let parent = parent_step?;
    let phase = trace.child(parent).step("reasoning", "scan", label).emit();
    Some(trace.parent_scope(phase))
}

fn emit_agentic_sast_done(ctx: &ToolExecutionContext<'_>, finding_count: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                "scan",
                format!("agentic-sast complete · {finding_count} findings"),
            )
            .emit();
    }
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
        let tool_policy = agent_tool_policy_for_input_and_target(input, &target)?;
        let inventory = collect_agentic_repo_inventory_with_filters(
            &target,
            options.max_inventory_files,
            options.max_bytes_per_file,
            &options.include_patterns,
            &options.exclude_patterns,
        )?;
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
