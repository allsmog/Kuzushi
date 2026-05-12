use super::*;

pub(crate) fn parse_vuln_analysis(outcome: &AgentLoopOutcome) -> VulnAnalysis {
    if let Some(ref structured) = outcome.structured {
        if let Ok(analysis) = serde_json::from_value::<VulnAnalysis>(structured.clone()) {
            return clamp(analysis);
        }
    }
    if !outcome.text.is_empty() {
        if let Some(parsed) = try_parse_loose_json::<VulnAnalysis>(&outcome.text) {
            return clamp(parsed);
        }
    }
    // Conservative fallback: not triggerable, low confidence, attach the
    // raw text so an operator can review.
    VulnAnalysis {
        triggerable: false,
        rationale: if outcome.text.is_empty() {
            "deep auditor returned no structured verdict".to_string()
        } else {
            outcome.text.clone()
        },
        confidence: 0.25,
        evidence: collect_implicit_evidence(&outcome.transcript),
    }
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
