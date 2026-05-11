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
    let mut outcome: AgentLoopOutcome =
        run_tool_loop(runtime as &dyn AgentRuntime, &request, &mut toolbox)
            .context("deep_audit tool loop failed")?;

    // 4b. Synthesis fallback. The model can exhaust its tool budget reading
    // code without ever emitting a structured verdict — Sonnet does this
    // routinely on multi-frame caller-chain audits. Run one more pass with
    // NO tools and a forcing prompt; the absence of tools means the only
    // valid response is an assistant message, which the bridge surfaces as
    // a Final step with `text`.
    if outcome.truncated && outcome.structured.is_none() && outcome.text.trim().is_empty() {
        outcome = force_verdict_synthesis(
            runtime as &dyn AgentRuntime,
            &request,
            outcome,
        )
        .unwrap_or_else(|err| AgentLoopOutcome {
            text: format!("synthesis pass failed: {err}"),
            structured: None,
            steps_used: cfg.max_steps,
            truncated: true,
            cost_usd: 0.0,
            transcript: Vec::new(),
        });
    }

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

/// Run one final pass with no tools, asking the model to synthesize a
/// verdict from what it already read. Returns a fresh `AgentLoopOutcome`
/// whose `text` should contain the JSON verdict (parsed downstream by
/// `parse_vuln_analysis`'s loose-JSON path). Preserves the original
/// transcript so `collect_implicit_evidence` still works.
fn force_verdict_synthesis(
    runtime: &dyn AgentRuntime,
    original_request: &AgentToolLoopRequest,
    truncated_outcome: AgentLoopOutcome,
) -> Result<AgentLoopOutcome> {
    let summary = summarize_transcript_for_synthesis(&truncated_outcome.transcript);
    let synthesis_prompt = format!(
        "{original}\n\n\
         --- SYNTHESIS PASS ---\n\
         You exhausted your tool budget without emitting the verdict. Based ONLY \
         on what you already read (listed below), emit the JSON verdict now. \
         This message is the last turn — no more tool calls will be honoured.\n\n\
         Calibrate confidence to the evidence you actually saw, not to whether \
         the loop truncated:\n\
         - If you saw a centralized validator / upstream guard that defeats the \
           alleged primitive, that IS strong evidence — report triggerable=false \
           with confidence >= 0.5 and cite the guard's file:line as evidence.\n\
         - If you saw a clear unguarded path from attacker-controlled input to \
           the sink, report triggerable=true with confidence >= 0.5 and cite \
           the source and sink.\n\
         - Only use confidence < 0.5 if your evidence is genuinely mixed or you \
           never reached the relevant code.\n\n\
         Regions read in this audit:\n{summary}\n\n\
         Emit the JSON verdict now.",
        original = original_request.prompt,
        summary = if summary.trim().is_empty() {
            "(no source regions recorded)".to_string()
        } else {
            summary
        },
    );
    let synthesis_request = AgentQueryRequest::new(
        original_request.model.clone(),
        original_request.cwd.clone(),
        original_request.system_prompt.clone(),
        synthesis_prompt,
    );
    let response = runtime.query_blocking(synthesis_request)?;
    Ok(AgentLoopOutcome {
        text: response.text,
        structured: response.structured,
        steps_used: truncated_outcome.steps_used,
        truncated: truncated_outcome.truncated,
        cost_usd: truncated_outcome.cost_usd,
        transcript: truncated_outcome.transcript,
    })
}

fn summarize_transcript_for_synthesis(transcript: &[LoopHistoryEntry]) -> String {
    let mut lines = Vec::new();
    let mut pending_call: Option<&serde_json::Value> = None;
    for entry in transcript {
        match entry {
            LoopHistoryEntry::AssistantToolCall(call) => {
                pending_call = Some(&call.input);
                let target = call
                    .input
                    .get("file")
                    .or_else(|| call.input.get("symbol"))
                    .or_else(|| call.input.get("name"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?");
                let start = call
                    .input
                    .get("start_line")
                    .and_then(serde_json::Value::as_u64);
                let end = call
                    .input
                    .get("end_line")
                    .and_then(serde_json::Value::as_u64);
                lines.push(match (start, end) {
                    (Some(s), Some(e)) => format!("  - {}({}:{}-{})", call.name, target, s, e),
                    (Some(s), None) => format!("  - {}({}:{})", call.name, target, s),
                    _ => format!("  - {}({})", call.name, target),
                });
            }
            LoopHistoryEntry::ToolResult(result) if result.is_error => {
                lines.push(format!("    -> error"));
                pending_call = None;
            }
            LoopHistoryEntry::ToolResult(_) => {
                pending_call = None;
            }
            LoopHistoryEntry::AssistantText(_) => {}
        }
    }
    lines.join("\n")
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
