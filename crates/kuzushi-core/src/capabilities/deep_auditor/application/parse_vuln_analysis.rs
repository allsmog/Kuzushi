use super::*;

const SYNTHESIZED_FALLBACK_PREFIX: &str =
    "[deep-auditor synthesized fallback: could not parse structured verdict]";

pub(crate) fn parse_vuln_analysis(outcome: &AgentLoopOutcome) -> VulnAnalysis {
    structured_vuln_analysis(outcome)
        .or_else(|| text_vuln_analysis(outcome))
        .unwrap_or_else(|| fallback_vuln_analysis(outcome))
}

fn structured_vuln_analysis(outcome: &AgentLoopOutcome) -> Option<VulnAnalysis> {
    outcome
        .structured
        .as_ref()
        .and_then(|structured| serde_json::from_value::<VulnAnalysis>(structured.clone()).ok())
        .map(clamp)
}

fn text_vuln_analysis(outcome: &AgentLoopOutcome) -> Option<VulnAnalysis> {
    if outcome.text.is_empty() {
        return None;
    }
    try_parse_loose_json::<VulnAnalysis>(&outcome.text).map(clamp)
}

fn fallback_vuln_analysis(outcome: &AgentLoopOutcome) -> VulnAnalysis {
    // Conservative fallback: not triggerable, low confidence, attach the
    // raw text so an operator can review.
    VulnAnalysis {
        triggerable: false,
        rationale: synthesized_fallback_rationale(&outcome.text),
        confidence: 0.25,
        evidence: collect_implicit_evidence(&outcome.transcript),
    }
}

fn synthesized_fallback_rationale(text: &str) -> String {
    if text.trim().is_empty() {
        return format!("{SYNTHESIZED_FALLBACK_PREFIX} no model text returned");
    }
    format!("{SYNTHESIZED_FALLBACK_PREFIX} raw model text: {}", text.trim())
}

pub(crate) fn collect_implicit_evidence(transcript: &[LoopHistoryEntry]) -> Vec<EvidenceCitation> {
    let mut out = Vec::new();
    let mut last_call_args: Option<Value> = None;
    for entry in transcript {
        match entry {
            LoopHistoryEntry::AssistantToolCall(call) if call.name == "read_source" => {
                last_call_args = Some(call.input.clone());
            }
            LoopHistoryEntry::ToolResult(result)
                if !result.is_error && last_call_args.is_some() =>
            {
                let args = last_call_args.take().unwrap();
                let file = args
                    .get("file")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if file.is_empty() {
                    continue;
                }
                let start = result
                    .output
                    .get("start_line")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u32;
                let end = result
                    .output
                    .get("end_line")
                    .and_then(Value::as_u64)
                    .unwrap_or(start as u64) as u32;
                out.push(EvidenceCitation {
                    file,
                    start_line: start,
                    end_line: end,
                    note: "auditor read this region".to_string(),
                    kind: "context".to_string(),
                });
            }
            _ => {}
        }
    }
    out
}

pub(crate) fn try_parse_loose_json<T: serde::de::DeserializeOwned>(text: &str) -> Option<T> {
    // Delegate to the shared parser in `structured_output`. That module
    // handles: leading-fence strip, last-fenced ```json…``` block
    // extraction, balanced-brace walk from the LAST `{` backward. Using
    // the shared implementation means agentic-sast / systems-hunt /
    // taint-iris all benefit from the same robustness improvements.
    crate::structured_output::try_parse_typed_from_agent_text(text)
}

pub(crate) fn clamp(mut a: VulnAnalysis) -> VulnAnalysis {
    a.confidence = a.confidence.clamp(0.0, 1.0);
    a
}
