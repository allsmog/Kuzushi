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
    let trimmed = text.trim();

    // Direct parse — the whole response is JSON.
    if let Ok(value) = serde_json::from_str::<T>(trimmed) {
        return Some(value);
    }

    // Strip a *leading* ```json fence if it wraps the entire response.
    let leading_stripped = if trimmed.starts_with("```") {
        trimmed
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim()
    } else {
        trimmed
    };
    if let Ok(value) = serde_json::from_str::<T>(leading_stripped) {
        return Some(value);
    }

    // Embedded ```json blocks anywhere in the body. The deep-auditor often
    // writes a paragraph of analysis followed by a fenced JSON verdict; the
    // outermost-brace approach below picks up `{` from C code snippets in
    // that paragraph and chokes. Pulling the explicit ```json…``` first
    // sidesteps that.
    if let Some(value) = extract_fenced_json_block::<T>(text) {
        return Some(value);
    }

    // Last resort: walk balanced-brace candidates from largest to smallest.
    extract_balanced_brace_json::<T>(text)
}

fn extract_fenced_json_block<T: serde::de::DeserializeOwned>(text: &str) -> Option<T> {
    // Find every ```json … ``` pair and try each (last fence wins because
    // the verdict is usually emitted at the end).
    let mut found: Option<T> = None;
    let mut rest = text;
    while let Some(start) = rest.find("```json") {
        let after_open = &rest[start + "```json".len()..];
        let after_open = after_open.trim_start_matches('\n');
        let Some(close) = after_open.find("```") else {
            break;
        };
        let body = after_open[..close].trim();
        if let Ok(value) = serde_json::from_str::<T>(body) {
            found = Some(value);
        }
        rest = &after_open[close + 3..];
    }
    found
}

fn extract_balanced_brace_json<T: serde::de::DeserializeOwned>(text: &str) -> Option<T> {
    // Scan for `{` and find the matching `}` (depth-balanced, ignoring
    // braces inside string literals). Try each candidate from the *last*
    // top-level `{` backward — the verdict tends to be at the bottom of
    // the response, after any prose that may contain stray braces.
    let bytes = text.as_bytes();
    let mut starts = Vec::new();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'{' {
            starts.push(i);
        }
    }
    for &start in starts.iter().rev() {
        if let Some(end) = matching_brace(bytes, start) {
            if let Ok(value) = serde_json::from_str::<T>(&text[start..=end]) {
                return Some(value);
            }
        }
    }
    None
}

fn matching_brace(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut escape = false;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn clamp(mut a: VulnAnalysis) -> VulnAnalysis {
    a.confidence = a.confidence.clamp(0.0, 1.0);
    a
}
