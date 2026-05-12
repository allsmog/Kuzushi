use super::*;

pub fn run_deep_auditor(
    runtime: &RoutedRuntime,
    spend: Option<&SpendLimiter>,
    cfg: &DeepAuditConfig,
    finding: &Finding,
) -> Result<DeepAuditOutcome> {
    let passes = cfg.passes.max(1);
    if passes == 1 {
        return run_deep_audit_pass(runtime, spend, cfg, finding);
    }
    // Multi-pass consensus voting. We run the single-pass auditor N times
    // — each pass is independent (separate spend ticket, separate tool
    // budget, separate temperature-controlled exploration) — and then
    // combine the verdicts. The goal is to suppress one-off swings on
    // borderline findings: if a finding flips between TP and FP between
    // runs the consensus is needs_review, with the union of evidence
    // attached so the human reviewer can see what each pass found.
    let mut outcomes = Vec::with_capacity(passes as usize);
    for _ in 0..passes {
        outcomes.push(run_deep_audit_pass(runtime, spend, cfg, finding)?);
    }
    Ok(consensus_outcome(outcomes))
}

fn run_deep_audit_pass(
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
        runtime_options: None,
        temperature: Some(cfg.temperature),
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
        outcome = force_verdict_synthesis(runtime as &dyn AgentRuntime, &request, outcome)
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

/// Combine N independent deep-audit outcomes into one consensus verdict.
///
/// Rules:
///   - Each pass casts a vote: TruePositive | FalsePositive | NeedsReview.
///   - If a verdict has strictly more votes than every other, take it; its
///     reported confidence is the mean confidence among the *winning*
///     votes, and the reported rationale is from the highest-confidence
///     winning pass.
///   - On a tie (e.g. 1 TP, 1 FP) we surface NeedsReview with the mean
///     confidence across all passes and a synthetic rationale that lists
///     the disagreement.
///   - Evidence is the union (deduplicated by file+span+kind) of every
///     pass's evidence so the human reviewer sees the full audit trail.
///   - cost_usd / steps_used / truncated are summed-or-OR'd in the
///     intuitive way (sum cost, max steps, OR truncated).
fn consensus_outcome(outcomes: Vec<DeepAuditOutcome>) -> DeepAuditOutcome {
    debug_assert!(!outcomes.is_empty(), "consensus_outcome needs >= 1 pass");
    let mut counts: std::collections::BTreeMap<String, u32> = Default::default();
    for outcome in &outcomes {
        *counts
            .entry(format!("{:?}", outcome.triage.verdict))
            .or_default() += 1;
    }
    let max_votes = counts.values().copied().max().unwrap_or(0);
    let winners: Vec<&String> = counts
        .iter()
        .filter(|(_, c)| **c == max_votes)
        .map(|(v, _)| v)
        .collect();

    let (winning_label, is_tie) = if winners.len() == 1 {
        (winners[0].clone(), false)
    } else {
        ("NeedsReview".to_string(), true)
    };

    let winning_passes: Vec<&DeepAuditOutcome> = outcomes
        .iter()
        .filter(|o| format!("{:?}", o.triage.verdict) == winning_label)
        .collect();
    let best_winning = winning_passes.iter().copied().max_by(|a, b| {
        a.triage
            .confidence
            .partial_cmp(&b.triage.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mean_conf = if !winning_passes.is_empty() && !is_tie {
        let sum: f32 = winning_passes.iter().map(|o| o.triage.confidence).sum();
        sum / winning_passes.len() as f32
    } else {
        let sum: f32 = outcomes.iter().map(|o| o.triage.confidence).sum();
        sum / outcomes.len() as f32
    };

    let verdict = if is_tie {
        crate::findings::TriageVerdict::NeedsReview
    } else {
        best_winning
            .map(|o| o.triage.verdict)
            .unwrap_or(crate::findings::TriageVerdict::NeedsReview)
    };

    let rationale = if is_tie {
        let breakdown: Vec<String> = counts.iter().map(|(v, c)| format!("{v}:{c}")).collect();
        format!(
            "[deep-audit consensus] passes disagree ({}); reverting to needs_review. \
             Best per-pass rationale: {}",
            breakdown.join(", "),
            best_winning
                .map(|o| o.triage.rationale.as_str())
                .unwrap_or(""),
        )
    } else {
        format!(
            "[deep-audit consensus {}/{}] {}",
            max_votes,
            outcomes.len(),
            best_winning
                .map(|o| o.triage.rationale.as_str())
                .unwrap_or(""),
        )
    };

    // Union evidence (file + span + kind).
    let mut seen = std::collections::BTreeSet::new();
    let mut evidence: Vec<EvidenceCitation> = Vec::new();
    for outcome in &outcomes {
        for e in &outcome.evidence {
            let key = (e.file.clone(), e.start_line, e.end_line, e.kind.clone());
            if seen.insert(key) {
                evidence.push(e.clone());
            }
        }
    }

    DeepAuditOutcome {
        triage: crate::findings::TriageOutcome {
            verdict,
            confidence: mean_conf,
            rationale,
            cost_usd: outcomes.iter().map(|o| o.triage.cost_usd).sum(),
        },
        evidence,
        cost_usd: outcomes.iter().map(|o| o.cost_usd).sum(),
        steps_used: outcomes.iter().map(|o| o.steps_used).max().unwrap_or(0),
        truncated: outcomes.iter().any(|o| o.truncated),
    }
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
    let mut synthesis_request = AgentQueryRequest::new(
        original_request.model.clone(),
        original_request.cwd.clone(),
        original_request.system_prompt.clone(),
        synthesis_prompt,
    );
    if let Some(temperature) = original_request.temperature {
        synthesis_request = synthesis_request.with_temperature(temperature);
    }
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
    for entry in transcript {
        match entry {
            LoopHistoryEntry::AssistantToolCall(call) => {
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
            }
            LoopHistoryEntry::ToolResult(_) => {}
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

#[cfg(test)]
mod consensus_tests {
    use super::*;
    use crate::findings::{TriageOutcome, TriageVerdict};

    fn outcome(verdict: TriageVerdict, conf: f32, rationale: &str) -> DeepAuditOutcome {
        DeepAuditOutcome {
            triage: TriageOutcome {
                verdict,
                confidence: conf,
                rationale: rationale.to_string(),
                cost_usd: 0.0,
            },
            evidence: vec![],
            cost_usd: 0.5,
            steps_used: 8,
            truncated: false,
        }
    }

    #[test]
    fn unanimous_majority_keeps_verdict_with_mean_confidence() {
        let outcomes = vec![
            outcome(TriageVerdict::TruePositive, 0.9, "real"),
            outcome(TriageVerdict::TruePositive, 0.7, "real"),
            outcome(TriageVerdict::TruePositive, 0.8, "real"),
        ];
        let c = consensus_outcome(outcomes);
        assert_eq!(c.triage.verdict, TriageVerdict::TruePositive);
        // 3/3 winners, mean = 0.8
        assert!((c.triage.confidence - 0.8).abs() < 1e-4);
        assert!(c.triage.rationale.starts_with("[deep-audit consensus 3/3]"));
    }

    #[test]
    fn two_of_three_majority_wins() {
        let outcomes = vec![
            outcome(TriageVerdict::FalsePositive, 0.85, "guard at X"),
            outcome(TriageVerdict::FalsePositive, 0.7, "guard at X"),
            outcome(TriageVerdict::TruePositive, 0.5, "looked unguarded"),
        ];
        let c = consensus_outcome(outcomes);
        assert_eq!(c.triage.verdict, TriageVerdict::FalsePositive);
        // mean of winning pair = 0.775
        assert!((c.triage.confidence - 0.775).abs() < 1e-3);
        assert!(c.triage.rationale.starts_with("[deep-audit consensus 2/3]"));
    }

    #[test]
    fn three_way_tie_collapses_to_needs_review() {
        let outcomes = vec![
            outcome(TriageVerdict::TruePositive, 0.8, "real"),
            outcome(TriageVerdict::FalsePositive, 0.6, "guarded"),
            outcome(TriageVerdict::NeedsReview, 0.4, "unsure"),
        ];
        let c = consensus_outcome(outcomes);
        assert_eq!(c.triage.verdict, TriageVerdict::NeedsReview);
        assert!(c.triage.rationale.contains("disagree"));
    }

    #[test]
    fn evidence_union_dedups_by_file_span_kind() {
        let mut o1 = outcome(TriageVerdict::TruePositive, 0.8, "real");
        o1.evidence = vec![
            EvidenceCitation {
                file: "a.c".into(),
                start_line: 10,
                end_line: 20,
                note: "x".into(),
                kind: "sink".into(),
            },
            EvidenceCitation {
                file: "b.c".into(),
                start_line: 5,
                end_line: 7,
                note: "y".into(),
                kind: "source".into(),
            },
        ];
        let mut o2 = outcome(TriageVerdict::TruePositive, 0.7, "real");
        o2.evidence = vec![
            // duplicate of a.c:10-20:sink
            EvidenceCitation {
                file: "a.c".into(),
                start_line: 10,
                end_line: 20,
                note: "different note".into(),
                kind: "sink".into(),
            },
            // new one
            EvidenceCitation {
                file: "c.c".into(),
                start_line: 1,
                end_line: 2,
                note: "z".into(),
                kind: "guard".into(),
            },
        ];
        let c = consensus_outcome(vec![o1, o2]);
        assert_eq!(c.evidence.len(), 3);
    }
}
