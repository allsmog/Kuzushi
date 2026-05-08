use super::prelude::*;
use super::*;

pub(crate) fn codeql_flow_score(
    finding: &Finding,
    evidence_nodes: &[StaticEvidenceNode],
    corpus: &str,
    reasons: &mut Vec<String>,
) -> i32 {
    let dataflow_steps = evidence_nodes
        .iter()
        .filter(|node| node.kind == StaticEvidenceNodeKind::DataflowStep)
        .count() as i32;
    let metadata_steps = evidence_nodes
        .iter()
        .filter_map(|node| {
            node.metadata
                .pointer("/codeFlowStepCount")
                .and_then(serde_json::Value::as_i64)
        })
        .max()
        .unwrap_or(0)
        .max(0) as i32;
    let steps = dataflow_steps.max(metadata_steps);
    let mut score = if finding.tool == "codeql" { 8 } else { 0 };
    if steps > 0 {
        score += 6 + (steps * 4).min(18);
    } else if corpus.contains("code flow:") || corpus.contains("flows_to") {
        score += 10;
    }
    if score > 0 {
        reasons.push("codeql_flow_quality".to_string());
    }
    score
}

pub(crate) fn confidence_score(finding: &Finding, corpus: &str, reasons: &mut Vec<String>) -> i32 {
    if let Some(triage) = &finding.triage {
        let score = match triage.verdict {
            TriageVerdict::TruePositive => 10 + confidence_bucket_score(triage.confidence),
            TriageVerdict::FalsePositive | TriageVerdict::ByDesign => -40,
            TriageVerdict::NeedsReview => confidence_bucket_score(triage.confidence) / 2,
        };
        reasons.push(format!("triage_confidence={:.2}", triage.confidence));
        return score;
    }

    if contains_any(
        corpus,
        &[
            "confidence: high",
            "\"confidence\":\"high\"",
            "confidence high",
        ],
    ) {
        reasons.push("confidence=high".to_string());
        12
    } else if contains_any(
        corpus,
        &[
            "confidence: medium",
            "\"confidence\":\"medium\"",
            "confidence medium",
        ],
    ) {
        reasons.push("confidence=medium".to_string());
        7
    } else if contains_any(
        corpus,
        &[
            "confidence: low",
            "\"confidence\":\"low\"",
            "confidence low",
        ],
    ) {
        reasons.push("confidence=low".to_string());
        2
    } else {
        0
    }
}

pub(crate) fn confidence_bucket_score(confidence: f32) -> i32 {
    if confidence >= 0.85 {
        14
    } else if confidence >= 0.65 {
        9
    } else if confidence >= 0.45 {
        5
    } else {
        1
    }
}
