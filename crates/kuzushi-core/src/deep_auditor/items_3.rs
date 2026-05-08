use super::prelude::*;
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
    // Strip ```json fences if present, then locate the outermost {...}.
    let trimmed = text.trim();
    let stripped = if trimmed.starts_with("```") {
        let after = trimmed
            .trim_start_matches("```json")
            .trim_start_matches("```");
        after.trim_end_matches("```").trim().to_string()
    } else {
        trimmed.to_string()
    };
    if let Ok(value) = serde_json::from_str::<T>(&stripped) {
        return Some(value);
    }
    let start = stripped.find('{')?;
    let end = stripped.rfind('}')?;
    if end <= start {
        return None;
    }
    serde_json::from_str(&stripped[start..=end]).ok()
}

pub(crate) fn clamp(mut a: VulnAnalysis) -> VulnAnalysis {
    a.confidence = a.confidence.clamp(0.0, 1.0);
    a
}
