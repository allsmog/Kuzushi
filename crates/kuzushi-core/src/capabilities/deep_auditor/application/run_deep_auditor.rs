use super::*;

pub fn run_deep_auditor(
    runtime: &RoutedRuntime<'_>,
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
    runtime: &RoutedRuntime<'_>,
    spend: Option<&SpendLimiter>,
    cfg: &DeepAuditConfig,
    finding: &Finding,
) -> Result<DeepAuditOutcome> {
    // 1. Resolve model via router.
    let model = resolve_deep_audit_model(runtime)?;

    // 2. Open spend ticket.
    let ticket = open_deep_audit_spend_ticket(spend, cfg)?;

    // 3. Build request + toolbox.
    let request = build_deep_audit_request(model, cfg, finding);

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
    outcome = synthesize_truncated_deep_audit(runtime, &request, cfg, outcome);

    // 5. Settle spend.
    settle_deep_audit_spend(spend, ticket, cfg, &outcome)?;

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

fn resolve_deep_audit_model(runtime: &RoutedRuntime<'_>) -> Result<String> {
    runtime
        .resolve_model(AgentRole::DeepAuditor, 0, None)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no model configured for the deep_auditor role: \
                 set models.toml [roles.deep_auditor] or `setg MODEL_DEEP_AUDITOR`"
            )
        })
}

fn open_deep_audit_spend_ticket(
    spend: Option<&SpendLimiter>,
    cfg: &DeepAuditConfig,
) -> Result<Option<crate::spend::SpendTicket>> {
    spend
        .map(|limiter| {
            limiter
                .deposit(Operation::DeepAudit, cfg.deposit_usd)
                .context("deep_audit deposit failed (cap reached?)")
        })
        .transpose()
}

fn build_deep_audit_request(
    model: String,
    cfg: &DeepAuditConfig,
    finding: &Finding,
) -> AgentToolLoopRequest {
    AgentToolLoopRequest {
        model,
        cwd: cfg.workspace_root.clone(),
        system_prompt: cfg
            .system_prompt
            .clone()
            .unwrap_or_else(|| DEFAULT_SYSTEM_PROMPT.to_string()),
        prompt: deep_audit_user_prompt(cfg, finding),
        tools: code_nav_tool_specs(),
        max_steps: cfg.max_steps.max(1),
        runtime_options: None,
        temperature: Some(cfg.temperature),
    }
}

fn deep_audit_user_prompt(cfg: &DeepAuditConfig, finding: &Finding) -> String {
    let mut user_prompt = render_user_prompt(finding);
    if cfg.include_static_evidence {
        append_static_evidence_prompt(&mut user_prompt, cfg, finding);
    }
    user_prompt
}

fn append_static_evidence_prompt(
    user_prompt: &mut String,
    cfg: &DeepAuditConfig,
    finding: &Finding,
) {
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

fn synthesize_truncated_deep_audit(
    runtime: &RoutedRuntime<'_>,
    request: &AgentToolLoopRequest,
    cfg: &DeepAuditConfig,
    outcome: AgentLoopOutcome,
) -> AgentLoopOutcome {
    if !needs_deep_audit_synthesis(&outcome) {
        return outcome;
    }
    force_verdict_synthesis(runtime as &dyn AgentRuntime, request, outcome)
        .unwrap_or_else(|err| failed_synthesis_outcome(cfg, err))
}

fn needs_deep_audit_synthesis(outcome: &AgentLoopOutcome) -> bool {
    outcome.truncated && outcome.structured.is_none() && outcome.text.trim().is_empty()
}

fn failed_synthesis_outcome(cfg: &DeepAuditConfig, error: anyhow::Error) -> AgentLoopOutcome {
    AgentLoopOutcome {
        text: format!("synthesis pass failed: {error}"),
        structured: None,
        steps_used: cfg.max_steps,
        truncated: true,
        cost_usd: 0.0,
        transcript: Vec::new(),
    }
}

fn settle_deep_audit_spend(
    spend: Option<&SpendLimiter>,
    ticket: Option<crate::spend::SpendTicket>,
    cfg: &DeepAuditConfig,
    outcome: &AgentLoopOutcome,
) -> Result<()> {
    let (Some(limiter), Some(ticket)) = (spend, ticket) else {
        return Ok(());
    };
    limiter
        .refund(ticket, actual_deep_audit_cost(cfg, outcome))
        .context("deep_audit refund failed")
}

fn actual_deep_audit_cost(cfg: &DeepAuditConfig, outcome: &AgentLoopOutcome) -> f64 {
    if outcome.cost_usd > 0.0 {
        outcome.cost_usd
    } else {
        cfg.deposit_usd
    }
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
    let vote = consensus_vote(&outcomes);
    let winning_passes = winning_consensus_passes(&outcomes, &vote.winning_label);
    let best_winning = highest_confidence_pass(&winning_passes);
    let mean_confidence = mean_consensus_confidence(&outcomes, &winning_passes, vote.is_tie);

    DeepAuditOutcome {
        triage: crate::findings::TriageOutcome {
            verdict: consensus_verdict(vote.is_tie, best_winning),
            confidence: mean_confidence,
            rationale: consensus_rationale(&vote, outcomes.len(), best_winning),
            cost_usd: outcomes.iter().map(|o| o.triage.cost_usd).sum(),
        },
        evidence: consensus_evidence(&outcomes),
        cost_usd: outcomes.iter().map(|o| o.cost_usd).sum(),
        steps_used: outcomes.iter().map(|o| o.steps_used).max().unwrap_or(0),
        truncated: outcomes.iter().any(|o| o.truncated),
    }
}

struct ConsensusVote {
    counts: std::collections::BTreeMap<String, u32>,
    winning_label: String,
    max_votes: u32,
    is_tie: bool,
}

fn consensus_vote(outcomes: &[DeepAuditOutcome]) -> ConsensusVote {
    let counts = consensus_vote_counts(outcomes);
    let max_votes = counts.values().copied().max().unwrap_or(0);
    let winning_labels = consensus_winning_labels(&counts, max_votes);
    let is_tie = winning_labels.len() != 1;
    let winning_label = consensus_winning_label(&winning_labels, is_tie);

    ConsensusVote {
        counts,
        winning_label,
        max_votes,
        is_tie,
    }
}

fn consensus_vote_counts(outcomes: &[DeepAuditOutcome]) -> std::collections::BTreeMap<String, u32> {
    let mut counts = std::collections::BTreeMap::new();
    for outcome in outcomes {
        *counts.entry(verdict_label(outcome)).or_default() += 1;
    }
    counts
}

fn verdict_label(outcome: &DeepAuditOutcome) -> String {
    format!("{:?}", outcome.triage.verdict)
}

fn consensus_winning_labels(
    counts: &std::collections::BTreeMap<String, u32>,
    max_votes: u32,
) -> Vec<&String> {
    counts
        .iter()
        .filter(|(_, count)| **count == max_votes)
        .map(|(verdict, _)| verdict)
        .collect()
}

fn consensus_winning_label(winning_labels: &[&String], is_tie: bool) -> String {
    if is_tie {
        "NeedsReview".to_string()
    } else {
        winning_labels[0].clone()
    }
}

fn winning_consensus_passes<'a>(
    outcomes: &'a [DeepAuditOutcome],
    winning_label: &str,
) -> Vec<&'a DeepAuditOutcome> {
    outcomes
        .iter()
        .filter(|outcome| verdict_label(outcome) == winning_label)
        .collect()
}

fn highest_confidence_pass<'a>(passes: &[&'a DeepAuditOutcome]) -> Option<&'a DeepAuditOutcome> {
    passes.iter().copied().max_by(|a, b| {
        a.triage
            .confidence
            .partial_cmp(&b.triage.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    })
}

fn mean_consensus_confidence(
    outcomes: &[DeepAuditOutcome],
    winning_passes: &[&DeepAuditOutcome],
    is_tie: bool,
) -> f32 {
    if is_tie || winning_passes.is_empty() {
        return mean_confidence(outcomes.iter().map(|outcome| outcome.triage.confidence));
    }

    mean_confidence(
        winning_passes
            .iter()
            .map(|outcome| outcome.triage.confidence),
    )
}

fn mean_confidence(confidences: impl Iterator<Item = f32>) -> f32 {
    let values: Vec<f32> = confidences.collect();
    values.iter().sum::<f32>() / values.len() as f32
}

fn consensus_verdict(
    is_tie: bool,
    best_winning: Option<&DeepAuditOutcome>,
) -> crate::findings::TriageVerdict {
    if is_tie {
        return crate::findings::TriageVerdict::NeedsReview;
    }

    best_winning
        .map(|outcome| outcome.triage.verdict)
        .unwrap_or(crate::findings::TriageVerdict::NeedsReview)
}

fn consensus_rationale(
    vote: &ConsensusVote,
    pass_count: usize,
    best_winning: Option<&DeepAuditOutcome>,
) -> String {
    let best_rationale = best_winning
        .map(|outcome| outcome.triage.rationale.as_str())
        .unwrap_or("");

    if vote.is_tie {
        return format!(
            "[deep-audit consensus] passes disagree ({}); reverting to needs_review. \
             Best per-pass rationale: {}",
            consensus_breakdown(&vote.counts),
            best_rationale,
        );
    }

    format!(
        "[deep-audit consensus {}/{}] {}",
        vote.max_votes, pass_count, best_rationale,
    )
}

fn consensus_breakdown(counts: &std::collections::BTreeMap<String, u32>) -> String {
    counts
        .iter()
        .map(|(verdict, count)| format!("{verdict}:{count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn consensus_evidence(outcomes: &[DeepAuditOutcome]) -> Vec<EvidenceCitation> {
    let mut seen = std::collections::BTreeSet::new();
    let mut evidence = Vec::new();

    for outcome in outcomes {
        push_unique_evidence(&mut evidence, &mut seen, &outcome.evidence);
    }

    evidence
}

fn push_unique_evidence(
    evidence: &mut Vec<EvidenceCitation>,
    seen: &mut std::collections::BTreeSet<(String, u32, u32, String)>,
    citations: &[EvidenceCitation],
) {
    for citation in citations {
        let key = evidence_key(citation);
        if seen.insert(key) {
            evidence.push(citation.clone());
        }
    }
}

fn evidence_key(citation: &EvidenceCitation) -> (String, u32, u32, String) {
    (
        citation.file.clone(),
        citation.start_line,
        citation.end_line,
        citation.kind.clone(),
    )
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
                lines.push("    -> error".to_string());
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
    use crate::runtime::{ToolCall, ToolResult};

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

    #[test]
    fn synthesis_summary_lists_tool_regions_and_errors() {
        let transcript = vec![
            LoopHistoryEntry::AssistantToolCall(ToolCall {
                name: "read_file".to_string(),
                input: serde_json::json!({
                    "file": "src/lib.c",
                    "start_line": 10,
                    "end_line": 20
                }),
                call_id: "call-1".to_string(),
            }),
            LoopHistoryEntry::ToolResult(ToolResult {
                call_id: "call-1".to_string(),
                output: serde_json::json!({"content": "ok"}),
                is_error: false,
            }),
            LoopHistoryEntry::AssistantToolCall(ToolCall {
                name: "find_symbol".to_string(),
                input: serde_json::json!({"symbol": "dangerous_copy", "start_line": 7}),
                call_id: "call-2".to_string(),
            }),
            LoopHistoryEntry::ToolResult(ToolResult {
                call_id: "call-2".to_string(),
                output: serde_json::json!({"error": "missing"}),
                is_error: true,
            }),
            LoopHistoryEntry::AssistantText("intermediate note".to_string()),
        ];

        let summary = summarize_transcript_for_synthesis(&transcript);

        assert!(summary.contains("read_file(src/lib.c:10-20)"));
        assert!(summary.contains("find_symbol(dangerous_copy:7)"));
        assert!(summary.contains("-> error"));
        assert!(!summary.contains("intermediate note"));
    }
}
