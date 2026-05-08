use super::prelude::*;
use super::*;

pub fn run_deep_auditor(
    runtime: &RoutedRuntime,
    spend: Option<&SpendLimiter>,
    cfg: &DeepAuditConfig,
    finding: &Finding,
) -> Result<DeepAuditOutcome> {
    // 1. Resolve model via router.
    let model = runtime
        .resolve_model(AgentRole::DeepAuditor, 0, None)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no model configured for the deep_auditor role: \
                 set models.toml [roles.deep_auditor] or `setg MODEL_DEEP_AUDITOR`"
            )
        })?;

    // 2. Open spend ticket.
    let ticket = match spend {
        Some(limiter) => Some(
            limiter
                .deposit(Operation::DeepAudit, cfg.deposit_usd)
                .context("deep_audit deposit failed (cap reached?)")?,
        ),
        None => None,
    };

    // 3. Build request + toolbox.
    let mut user_prompt = render_user_prompt(finding);
    if cfg.include_static_evidence {
        let mut sources = crate::static_context::StaticContextSources::new(&cfg.workspace_root);
        if !finding.title.trim().is_empty() {
            sources.symbol_hint = Some(finding.title.as_str());
        }
        if !finding.message.trim().is_empty() {
            sources.source_snippet = Some(finding.message.as_str());
        }
        if let Some(block) = crate::static_context::assemble_static_context(finding, &sources) {
            user_prompt.push_str("\n\n");
            user_prompt.push_str(&block);
        }
    }

    let request = AgentToolLoopRequest {
        model,
        cwd: cfg.workspace_root.clone(),
        system_prompt: cfg
            .system_prompt
            .clone()
            .unwrap_or_else(|| DEFAULT_SYSTEM_PROMPT.to_string()),
        prompt: user_prompt,
        tools: code_nav_tool_specs(),
        max_steps: cfg.max_steps.max(1),
    };

    let mut toolbox = code_nav_toolbox(CodeNavConfig::new(&cfg.workspace_root));

    // 4. Drive the loop.
    let outcome: AgentLoopOutcome =
        run_tool_loop(runtime as &dyn AgentRuntime, &request, &mut toolbox)
            .context("deep_audit tool loop failed")?;

    // 5. Settle spend.
    if let (Some(limiter), Some(ticket)) = (spend, ticket) {
        let actual = if outcome.cost_usd > 0.0 {
            outcome.cost_usd
        } else {
            cfg.deposit_usd
        };
        limiter
            .refund(ticket, actual)
            .context("deep_audit refund failed")?;
    }

    // 6. Parse final structured output.
    let analysis = parse_vuln_analysis(&outcome);
    let triage = build_triage_outcome(&analysis, &outcome);

    Ok(DeepAuditOutcome {
        triage,
        evidence: analysis.evidence,
        cost_usd: outcome.cost_usd,
        steps_used: outcome.steps_used,
        truncated: outcome.truncated,
    })
}

pub(crate) fn render_user_prompt(finding: &Finding) -> String {
    let location = match finding.end_line {
        Some(end) if end != finding.start_line => {
            format!("{}:{}–{}", finding.file_path, finding.start_line, end)
        }
        _ => format!("{}:{}", finding.file_path, finding.start_line),
    };
    format!(
        "Audit this candidate finding:\n\n\
         tool       : {tool}\n\
         rule_id    : {rule}\n\
         severity   : {sev}\n\
         location   : {loc}\n\
         title      : {title}\n\
         message    :\n{msg}\n\n\
         Decide if it is genuinely triggerable. Use the tools to verify before answering.",
        tool = finding.tool,
        rule = finding.rule_id,
        sev = finding.severity.as_str(),
        loc = location,
        title = finding.title,
        msg = finding.message,
    )
}
