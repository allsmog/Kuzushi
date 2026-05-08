use super::prelude::*;
use super::*;

pub(crate) fn noise_adjustment(
    finding: &Finding,
    evidence_nodes: &[StaticEvidenceNode],
    corpus: &str,
    reasons: &mut Vec<String>,
) -> i32 {
    let mut adjustment = 0;
    let has_dataflow = evidence_nodes
        .iter()
        .any(|node| node.kind == StaticEvidenceNodeKind::DataflowStep);
    let has_code_or_source_sink = evidence_nodes.iter().any(|node| {
        matches!(
            node.kind,
            StaticEvidenceNodeKind::CodeSpan
                | StaticEvidenceNodeKind::Source
                | StaticEvidenceNodeKind::Sink
        )
    });
    if finding.tool == "semgrep"
        && finding
            .static_proof_state
            .unwrap_or(StaticProofState::SignalOnly)
            == StaticProofState::SignalOnly
        && !has_dataflow
        && !has_code_or_source_sink
    {
        adjustment -= 14;
    }
    if contains_any(
        corpus,
        &[
            "generic",
            "style",
            "lint",
            "best practice",
            "dead code",
            "unused",
        ],
    ) {
        adjustment -= 8;
    }
    if adjustment < 0 {
        reasons.push("scanner_noise_penalty".to_string());
    }
    adjustment
}

pub(crate) fn threat_model_score(
    finding: &Finding,
    threat_model: Option<&Value>,
    corpus: &str,
    reasons: &mut Vec<String>,
) -> i32 {
    let Some(threats) = threat_model
        .and_then(|model| model.get("threats"))
        .and_then(Value::as_array)
    else {
        return 0;
    };
    let finding_cwe = extract_cwe(&finding.rule_id, &finding.title, &finding.message)
        .map(|cwe| cwe.to_ascii_lowercase());
    let mut best = 0;
    let mut best_id = None;
    for threat in threats {
        let score = threat_match_score(finding, threat, corpus, finding_cwe.as_deref());
        if score > best {
            best = score;
            best_id = threat
                .get("id")
                .and_then(Value::as_str)
                .map(ToString::to_string);
        }
    }
    if best > 0 {
        let label = best_id.unwrap_or_else(|| "unnamed".to_string());
        reasons.push(format!("threat_model_priority={label}"));
    }
    best
}

pub(crate) fn threat_match_score(
    finding: &Finding,
    threat: &Value,
    corpus: &str,
    finding_cwe: Option<&str>,
) -> i32 {
    let mut score = threat_impact_score(threat);
    if threat_affected_file_matches(threat, &finding.file_path) {
        score += 18;
    }
    if threat_related_cwe_matches(threat, finding_cwe) {
        score += 12;
    }
    if threat_text_matches(threat, corpus) {
        score += 8;
    }
    score.min(36)
}

pub(crate) fn threat_impact_score(threat: &Value) -> i32 {
    match threat
        .get("impact")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "critical" => 14,
        "high" => 10,
        "medium" => 6,
        "low" => 2,
        _ => 0,
    }
}
