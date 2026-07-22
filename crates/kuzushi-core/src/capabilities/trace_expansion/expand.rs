use super::contract::{
    parse_trace_expansion_result, trace_expansion_schema, TraceExpansionRequest,
    TraceExpansionResult, MAX_TRACE_EXPANSION_STEPS,
};
use crate::findings::Finding;
use crate::proof::whitebox_static_policy_for_target;
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::{
    query_required_structured_json_with_cost, CostedStructuredJson, StructuredJsonContract,
};
use anyhow::Result;
use std::fmt::Write as _;
use std::path::Path;

const MAX_PROMPT_EVIDENCE_ANCHORS: usize = 6;
const MAX_PROMPT_PATH_NODE_IDS: usize = 24;

const TRACE_EXPANSION_SYSTEM_PROMPT: &str = "You are a static data-flow tracer. \
You expand the recorded source-to-sink path of one security finding by reading \
the repository — you never execute code, never modify files, and never claim a \
hop you cannot cite to a file and line. Every step must name the symbol the \
value passes through and annotate what happens to it there (copied, bounds \
checked, sanitized, cast, stored). When the flow cannot be followed further, \
record the reason as an open question instead of inventing a step.";

/// Parsed expansion plus the observed provider spend for the pass.
#[derive(Debug, Clone)]
pub struct TraceExpansionOutcome {
    pub result: TraceExpansionResult,
    pub cost_usd: f64,
    pub cost_usd_exact: bool,
}

impl From<CostedStructuredJson<TraceExpansionResult>> for TraceExpansionOutcome {
    fn from(costed: CostedStructuredJson<TraceExpansionResult>) -> Self {
        Self {
            result: costed.value,
            cost_usd: costed.cost_usd,
            cost_usd_exact: costed.cost_usd_exact,
        }
    }
}

/// Run one bounded read-only agent pass expanding the finding's data-flow
/// path. Pure query-and-parse: persistence is the caller's decision.
pub fn run_trace_expansion(
    runtime: &dyn AgentRuntime,
    model: &str,
    workspace_root: &Path,
    finding: &Finding,
    request: &TraceExpansionRequest,
) -> Result<TraceExpansionOutcome> {
    let query = AgentQueryRequest::new(
        model.to_string(),
        workspace_root.to_path_buf(),
        TRACE_EXPANSION_SYSTEM_PROMPT.to_string(),
        expansion_prompt(finding, request),
    )
    .with_tool_policy(whitebox_static_policy_for_target(workspace_root));
    let fingerprint = finding.fingerprint.clone();
    query_required_structured_json_with_cost(
        runtime,
        query,
        StructuredJsonContract::new(
            "trace:expand",
            "TraceExpansionResult",
            trace_expansion_schema(),
        ),
        move |raw| {
            let mut result = parse_trace_expansion_result(raw)?;
            // The agent echoes the fingerprint; the request is the authority.
            result.finding_fingerprint = fingerprint.clone();
            Ok(result)
        },
    )
    .map(TraceExpansionOutcome::from)
    .map_err(anyhow::Error::from)
}

fn expansion_prompt(finding: &Finding, request: &TraceExpansionRequest) -> String {
    let mut prompt = String::new();
    let _ = writeln!(
        prompt,
        "Expand the data-flow trace for this finding. Return JSON matching the \
         TraceExpansionResult schema (version 1) with at most {MAX_TRACE_EXPANSION_STEPS} steps, \
         ordered from the value's origin toward the sink.\n"
    );
    let _ = writeln!(prompt, "FINDING {}", finding.fingerprint);
    let _ = writeln!(
        prompt,
        "{} · {:?} · {}:{}",
        finding.title, finding.severity, finding.file_path, finding.start_line
    );
    if !finding.message.trim().is_empty() {
        let _ = writeln!(prompt, "{}", finding.message.trim());
    }
    write_evidence_anchors(&mut prompt, finding);
    write_current_path(&mut prompt, request);
    if let Some(instruction) = request
        .operator_instruction
        .as_deref()
        .map(str::trim)
        .filter(|instruction| !instruction.is_empty())
    {
        let _ = writeln!(prompt, "\nOPERATOR INSTRUCTION\n{instruction}");
    }
    let _ = writeln!(
        prompt,
        "\nRecover only the intermediary hops NOT already on the recorded path. \
         Use Read/Grep/Glob to cite each step to a real file and line. \
         List what the expansion adds under evidenceDeltas and anything you \
         could not resolve under openQuestions."
    );
    prompt
}

fn write_evidence_anchors(prompt: &mut String, finding: &Finding) {
    let anchors: Vec<&crate::findings::FindingEvidence> = finding
        .evidence
        .iter()
        .filter(|evidence| !evidence.file_path.trim().is_empty())
        .take(MAX_PROMPT_EVIDENCE_ANCHORS)
        .collect();
    if anchors.is_empty() {
        return;
    }
    let _ = writeln!(prompt, "\nRECORDED EVIDENCE ANCHORS");
    for evidence in anchors {
        let _ = writeln!(
            prompt,
            "- {} · {}:{}",
            evidence.kind, evidence.file_path, evidence.line
        );
    }
}

fn write_current_path(prompt: &mut String, request: &TraceExpansionRequest) {
    if request.current_path_node_ids.is_empty() {
        return;
    }
    let _ = writeln!(
        prompt,
        "\nCURRENT PATH NODE IDS (already rendered; extend, do not restate)"
    );
    for node_id in request
        .current_path_node_ids
        .iter()
        .take(MAX_PROMPT_PATH_NODE_IDS)
    {
        let _ = writeln!(prompt, "- {node_id}");
    }
}
