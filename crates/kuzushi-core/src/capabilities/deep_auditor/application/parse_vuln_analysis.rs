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
        first_link: None,
        refute_reason: None,
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
    let mut pending: Option<(String, Value)> = None;
    for entry in transcript {
        match entry {
            LoopHistoryEntry::AssistantToolCall(call) if is_evidence_call(&call.name) => {
                pending = Some((call.name.clone(), call.input.clone()));
            }
            LoopHistoryEntry::ToolResult(result) if !result.is_error => {
                append_pending_evidence(&mut out, &mut pending, &result.output);
            }
            _ => {}
        }
    }
    out
}

fn is_evidence_call(name: &str) -> bool {
    matches!(name, "read_source" | "cpg_taint_paths")
}

fn append_pending_evidence(
    out: &mut Vec<EvidenceCitation>,
    pending: &mut Option<(String, Value)>,
    output: &Value,
) {
    if let Some((name, args)) = pending.take() {
        out.extend(evidence_from_result(&name, &args, output));
    }
}

fn evidence_from_result(name: &str, args: &Value, output: &Value) -> Vec<EvidenceCitation> {
    match name {
        "read_source" => read_source_evidence(args, output),
        "cpg_taint_paths" => taint_evidence_from_result(args, output),
        _ => Vec::new(),
    }
}

fn read_source_evidence(args: &Value, output: &Value) -> Vec<EvidenceCitation> {
    let file = args.get("file").and_then(Value::as_str).unwrap_or("");
    if file.is_empty() {
        return Vec::new();
    }
    let start = output.get("start_line").and_then(Value::as_u64).unwrap_or(0) as u32;
    let end = output
        .get("end_line")
        .and_then(Value::as_u64)
        .unwrap_or(start as u64) as u32;
    vec![EvidenceCitation {
        file: file.to_string(),
        start_line: start,
        end_line: end,
        note: "auditor read this region".to_string(),
        kind: "context".to_string(),
        origin: EvidenceOrigin::CodeRead,
    }]
}

/// Mine the source/sink witness from a `cpg_taint_paths` result so a truncated
/// or unparseable audit still surfaces the guard/authz falsification evidence.
/// Every returned flow is mined — not just the first — so guard/authz carried
/// on later flows is not silently dropped from the persisted evidence.
fn taint_evidence_from_result(args: &Value, output: &Value) -> Vec<EvidenceCitation> {
    let sink = args.get("sink").and_then(Value::as_str).unwrap_or("");
    let source = args.get("source").and_then(Value::as_str).unwrap_or("");
    let Some(flows) = output.get("flows").and_then(Value::as_array) else {
        return Vec::new();
    };
    flows
        .iter()
        .filter_map(|flow| taint_citation_from_flow(source, sink, flow))
        .collect()
}

fn taint_citation_from_flow(source: &str, sink: &str, flow: &Value) -> Option<EvidenceCitation> {
    let file = flow.get("sinkFile").and_then(Value::as_str).unwrap_or("");
    if file.is_empty() {
        return None;
    }
    let line = flow.get("sinkLine").and_then(Value::as_u64).unwrap_or(0) as u32;
    Some(EvidenceCitation {
        file: file.to_string(),
        start_line: line,
        end_line: line,
        note: taint_note(source, sink, flow),
        kind: taint_kind(flow),
        // Witnessed by the cpg-rs engine — the one place cpg-rs provenance is
        // truthful; model-cited guard rows keep the default CodeRead origin.
        origin: EvidenceOrigin::CpgPath,
    })
}

fn taint_kind(flow: &Value) -> String {
    if flow_has_guard(flow) {
        "guard".to_string()
    } else {
        "sink".to_string()
    }
}

fn flow_has_guard(flow: &Value) -> bool {
    flow.get("guard").is_some_and(|guard| !guard.is_null())
        || flow.get("authz").is_some_and(|authz| !authz.is_null())
}

fn taint_note(source: &str, sink: &str, flow: &Value) -> String {
    let base = format!("cpg-rs taint witness {source} → {sink}");
    if flow_has_guard(flow) {
        return format!("{base}; guard/authz present (falsifying evidence)");
    }
    base
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

#[cfg(test)]
mod taint_evidence_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mines_guard_authz_across_all_flows_not_just_the_first() {
        // flow[0] is unguarded; flow[1] carries the authz annotation. Mining
        // only flows.first() would drop the falsifying evidence from the
        // persisted citation set.
        let args = json!({"source": "req\\.query", "sink": "query"});
        let output = json!({
            "flows": [
                {"sinkFile": "a.ts", "sinkLine": 5, "guard": null, "authz": null},
                {"sinkFile": "b.ts", "sinkLine": 9, "guard": null, "authz": "authorized(req)"}
            ]
        });

        let citations = taint_evidence_from_result(&args, &output);

        assert_eq!(citations.len(), 2, "both flows must be mined");
        // Every cpg-mined citation is tagged with cpg-rs provenance.
        assert!(citations
            .iter()
            .all(|c| c.origin == EvidenceOrigin::CpgPath));
        // flow[1]'s authz survives as a guard citation naming the gate.
        let guarded = &citations[1];
        assert_eq!(guarded.file, "b.ts");
        assert_eq!(guarded.kind, "guard");
        assert!(
            guarded.note.contains("falsifying"),
            "authz on flow[1] must be surfaced as falsifying evidence: {}",
            guarded.note
        );
    }
}
