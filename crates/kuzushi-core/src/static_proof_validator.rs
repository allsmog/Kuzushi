use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::findings::{Finding, StaticProofState, TriageOutcome, TriageVerdict};
use crate::source_span::extract_source_span;
use crate::static_evidence::{StaticEvidenceEdge, StaticEvidenceNode, StaticEvidenceNodeKind};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StaticProofClaim {
    pub finding: Finding,
    #[serde(default)]
    pub evidence_nodes: Vec<StaticEvidenceNode>,
    #[serde(default)]
    pub evidence_edges: Vec<StaticEvidenceEdge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_explanation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_direct_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitizer_assessment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard_assessment: Option<String>,
    #[serde(default)]
    pub assumptions: Vec<String>,
    #[serde(default)]
    pub missing_evidence: Vec<String>,
}

impl StaticProofClaim {
    pub fn new(finding: Finding) -> Self {
        Self {
            finding,
            evidence_nodes: Vec::new(),
            evidence_edges: Vec::new(),
            path_explanation: None,
            local_direct_reason: None,
            sanitizer_assessment: None,
            guard_assessment: None,
            assumptions: Vec::new(),
            missing_evidence: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedStaticCitation {
    pub node_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticProofValidationReport {
    pub requested_static_proof_state: StaticProofState,
    pub validated_static_proof_state: StaticProofState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_verdict: Option<TriageVerdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validated_verdict: Option<TriageVerdict>,
    pub complete: bool,
    pub downgraded: bool,
    pub reasons: Vec<String>,
    pub verified_citations: Vec<VerifiedStaticCitation>,
}

pub fn validate_static_proof_claim(
    repo_root: impl AsRef<Path>,
    claim: &StaticProofClaim,
) -> Result<StaticProofValidationReport> {
    let requested_state = claim
        .finding
        .static_proof_state
        .unwrap_or(StaticProofState::SignalOnly);
    let requested_verdict = claim.finding.triage.as_ref().map(|triage| triage.verdict);
    let mut reasons = Vec::new();

    validate_edge_endpoints(&claim.evidence_nodes, &claim.evidence_edges, &mut reasons);
    let verified_citations =
        verify_code_citations(repo_root.as_ref(), &claim.evidence_nodes, &mut reasons);

    let needs_confirmation_gate = requested_state == StaticProofState::StaticallyConfirmed
        || requested_verdict == Some(TriageVerdict::TruePositive);

    if requested_verdict == Some(TriageVerdict::TruePositive)
        && requested_state != StaticProofState::StaticallyConfirmed
    {
        reasons.push(
            "true_positive verdict in whitebox-static requires staticProofState=statically_confirmed"
                .to_string(),
        );
    }

    if needs_confirmation_gate {
        if !has_source_or_entrypoint_evidence(&claim.evidence_nodes) {
            reasons.push("statically_confirmed requires source or entrypoint evidence".to_string());
        }
        if !has_sink_or_security_sensitive_evidence(&claim.evidence_nodes) {
            reasons.push(
                "statically_confirmed requires sink or security-sensitive operation evidence"
                    .to_string(),
            );
        }
        if !has_text(&claim.path_explanation) && !has_text(&claim.local_direct_reason) {
            reasons.push(
                "statically_confirmed requires a path explanation or local/direct reason"
                    .to_string(),
            );
        }
        if !has_text(&claim.sanitizer_assessment) {
            reasons.push("statically_confirmed requires a sanitizer assessment".to_string());
        }
        if !has_text(&claim.guard_assessment) {
            reasons.push("statically_confirmed requires a guard assessment".to_string());
        }
        if !has_recorded_items(&claim.assumptions) {
            reasons.push("statically_confirmed requires recorded assumptions".to_string());
        }
        if !has_recorded_items(&claim.missing_evidence) {
            reasons.push("statically_confirmed requires recorded missing evidence".to_string());
        }
        if verified_citations.is_empty() {
            reasons.push(
                "statically_confirmed requires at least one verified code citation".to_string(),
            );
        }
    }

    let complete = reasons.is_empty();
    let mut validated_state = requested_state;
    let mut validated_verdict = requested_verdict;
    if !complete && needs_confirmation_gate {
        validated_state = StaticProofState::NeedsRuntimeEvidence;
        if requested_verdict == Some(TriageVerdict::TruePositive) {
            validated_verdict = Some(TriageVerdict::NeedsReview);
        }
    }

    Ok(StaticProofValidationReport {
        requested_static_proof_state: requested_state,
        validated_static_proof_state: validated_state,
        requested_verdict,
        validated_verdict,
        complete,
        downgraded: validated_state != requested_state || validated_verdict != requested_verdict,
        reasons,
        verified_citations,
    })
}

pub fn apply_static_proof_validation_to_finding(
    finding: &mut Finding,
    report: &StaticProofValidationReport,
) {
    finding.static_proof_state = Some(report.validated_static_proof_state);
    if report.validated_verdict == report.requested_verdict {
        return;
    }

    let Some(validated_verdict) = report.validated_verdict else {
        return;
    };
    match finding.triage.as_mut() {
        Some(triage) => {
            triage.verdict = validated_verdict;
            if report.downgraded {
                triage.rationale = render_downgrade_rationale(report);
                triage.confidence = triage.confidence.min(0.5);
            }
        }
        None => {
            finding.triage = Some(TriageOutcome {
                verdict: validated_verdict,
                confidence: if report.downgraded { 0.5 } else { 0.0 },
                rationale: render_downgrade_rationale(report),
            });
        }
    }
}

fn verify_code_citations(
    repo_root: &Path,
    nodes: &[StaticEvidenceNode],
    reasons: &mut Vec<String>,
) -> Vec<VerifiedStaticCitation> {
    let mut verified = Vec::new();
    for node in nodes.iter().filter(|node| is_code_citation_node(node)) {
        let Some(file_path) = node.source_path.as_deref() else {
            reasons.push(format!(
                "code citation node {} is missing source_path",
                node.id
            ));
            continue;
        };
        let Some(start_line) = node.start_line else {
            reasons.push(format!(
                "code citation node {} is missing start_line",
                node.id
            ));
            continue;
        };
        let end_line = node.end_line.unwrap_or(start_line);
        match extract_source_span(repo_root, file_path, start_line, end_line) {
            Ok(span) if span.snippet == node.body && span.content_hash == node.content_hash => {
                verified.push(VerifiedStaticCitation {
                    node_id: node.id.clone(),
                    file_path: span.file_path,
                    start_line: span.start_line,
                    end_line: span.end_line,
                    content_hash: span.content_hash,
                });
            }
            Ok(span) => {
                reasons.push(format!(
                    "code citation node {} is stale for {}:{}-{}",
                    node.id, span.file_path, span.start_line, span.end_line
                ));
            }
            Err(error) => {
                reasons.push(format!(
                    "code citation node {} is invalid: {error}",
                    node.id
                ));
            }
        }
    }
    verified
}

fn validate_edge_endpoints(
    nodes: &[StaticEvidenceNode],
    edges: &[StaticEvidenceEdge],
    reasons: &mut Vec<String>,
) {
    let node_ids = nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    for edge in edges {
        if !node_ids.contains(edge.from_node_id.as_str()) {
            reasons.push(format!(
                "static evidence edge {} references missing from_node_id {}",
                edge.id, edge.from_node_id
            ));
        }
        if !node_ids.contains(edge.to_node_id.as_str()) {
            reasons.push(format!(
                "static evidence edge {} references missing to_node_id {}",
                edge.id, edge.to_node_id
            ));
        }
    }
}

fn is_code_citation_node(node: &StaticEvidenceNode) -> bool {
    matches!(
        node.kind,
        StaticEvidenceNodeKind::CodeSpan
            | StaticEvidenceNodeKind::Source
            | StaticEvidenceNodeKind::Sink
            | StaticEvidenceNodeKind::DataflowStep
            | StaticEvidenceNodeKind::Sanitizer
            | StaticEvidenceNodeKind::Guard
    )
}

fn has_source_or_entrypoint_evidence(nodes: &[StaticEvidenceNode]) -> bool {
    nodes.iter().any(|node| {
        matches!(
            node.kind,
            StaticEvidenceNodeKind::Source | StaticEvidenceNodeKind::AttackSurface
        ) || metadata_has_any_role(node, &["source", "entrypoint", "attack_surface"])
    })
}

fn has_sink_or_security_sensitive_evidence(nodes: &[StaticEvidenceNode]) -> bool {
    nodes.iter().any(|node| {
        node.kind == StaticEvidenceNodeKind::Sink
            || metadata_bool(&node.metadata, &["securitySensitive", "security_sensitive"])
            || metadata_has_any_role(node, &["sink", "security_sensitive_operation"])
    })
}

fn metadata_has_any_role(node: &StaticEvidenceNode, expected: &[&str]) -> bool {
    metadata_string_matches(
        &node.metadata,
        &["role", "staticRole", "proofRole"],
        expected,
    ) || metadata_array_contains(
        &node.metadata,
        &["roles", "staticRoles", "proofRoles"],
        expected,
    )
}

fn metadata_string_matches(metadata: &Value, keys: &[&str], expected: &[&str]) -> bool {
    keys.iter().any(|key| {
        metadata
            .get(*key)
            .and_then(Value::as_str)
            .is_some_and(|value| expected.iter().any(|item| value.eq_ignore_ascii_case(item)))
    })
}

fn metadata_array_contains(metadata: &Value, keys: &[&str], expected: &[&str]) -> bool {
    keys.iter().any(|key| {
        metadata
            .get(*key)
            .and_then(Value::as_array)
            .is_some_and(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|value| expected.iter().any(|item| value.eq_ignore_ascii_case(item)))
            })
    })
}

fn metadata_bool(metadata: &Value, keys: &[&str]) -> bool {
    keys.iter()
        .any(|key| metadata.get(*key).and_then(Value::as_bool).unwrap_or(false))
}

fn has_text(value: &Option<String>) -> bool {
    value
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
}

fn has_recorded_items(values: &[String]) -> bool {
    values.iter().any(|value| !value.trim().is_empty())
}

fn render_downgrade_rationale(report: &StaticProofValidationReport) -> String {
    if report.reasons.is_empty() {
        return "Static proof validator accepted the whitebox-static claim.".to_string();
    }
    format!(
        "Static proof validator downgraded the whitebox-static claim: {}",
        report.reasons.join("; ")
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::findings::Severity;
    use crate::static_evidence::{StaticEvidenceEdge, StaticEvidenceEdgeKind};

    #[test]
    fn static_proof_validator_accepts_complete_statically_confirmed_claim() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(
            temp.path().join("src/routes.ts"),
            "app.get('/users', (req, res) => {\nlet id = req.query.id;\ndb.query(`select * from users where id = ${id}`);\n});\n",
        )
        .unwrap();
        let mut finding = Finding::new_tool(
            "whitebox-static",
            "demo.sql-injection",
            "src/routes.ts",
            2,
            Some(3),
            Severity::High,
            "request parameter reaches raw SQL query",
        )
        .with_static_proof_state(StaticProofState::StaticallyConfirmed);
        finding.triage = Some(TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.9,
            rationale: "source reaches sink with no sanitizer".to_string(),
        });

        let source = node_from_span(
            temp.path(),
            StaticEvidenceNodeKind::Source,
            finding.fingerprint.as_str(),
            "request query source",
            "src/routes.ts",
            2,
            json!({"role": "source"}),
        );
        let sink = node_from_span(
            temp.path(),
            StaticEvidenceNodeKind::Sink,
            finding.fingerprint.as_str(),
            "raw SQL sink",
            "src/routes.ts",
            3,
            json!({"role": "sink", "securitySensitive": true}),
        );
        let flow = StaticEvidenceEdge::new(
            StaticEvidenceEdgeKind::FlowsTo,
            source.id.clone(),
            sink.id.clone(),
        )
        .with_finding_fingerprint(finding.fingerprint.clone());

        let claim = StaticProofClaim {
            finding,
            evidence_nodes: vec![source, sink],
            evidence_edges: vec![flow],
            path_explanation: Some(
                "req.query.id is assigned to id and interpolated into db.query".to_string(),
            ),
            local_direct_reason: None,
            sanitizer_assessment: Some(
                "No parameter binding or validation is present on the cited path.".to_string(),
            ),
            guard_assessment: Some(
                "The route is public; no authorization guard appears in the cited handler."
                    .to_string(),
            ),
            assumptions: vec!["Express query parameters are attacker controlled.".to_string()],
            missing_evidence: vec![
                "Runtime exploitability is not assessed in whitebox-static mode.".to_string(),
            ],
        };

        let report = validate_static_proof_claim(temp.path(), &claim).unwrap();

        assert!(report.complete, "{:?}", report.reasons);
        assert!(!report.downgraded);
        assert_eq!(
            report.validated_static_proof_state,
            StaticProofState::StaticallyConfirmed
        );
        assert_eq!(report.validated_verdict, Some(TriageVerdict::TruePositive));
        assert_eq!(report.verified_citations.len(), 2);
    }

    #[test]
    fn static_proof_validator_accepts_local_direct_reason_without_flow_edge() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(
            temp.path().join("src/app.ts"),
            "res.send(req.query.name);\n",
        )
        .unwrap();
        let mut finding = Finding::new_tool(
            "whitebox-static",
            "demo.xss",
            "src/app.ts",
            1,
            Some(1),
            Severity::High,
            "request query is directly rendered into the response",
        )
        .with_static_proof_state(StaticProofState::StaticallyConfirmed);
        finding.triage = Some(TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.8,
            rationale: "local source and sink on one cited line".to_string(),
        });
        let source = node_from_span(
            temp.path(),
            StaticEvidenceNodeKind::Source,
            finding.fingerprint.as_str(),
            "query source",
            "src/app.ts",
            1,
            json!({"role": "source"}),
        );
        let sink = node_from_span(
            temp.path(),
            StaticEvidenceNodeKind::Sink,
            finding.fingerprint.as_str(),
            "response sink",
            "src/app.ts",
            1,
            json!({"role": "sink"}),
        );

        let claim = StaticProofClaim {
            finding,
            evidence_nodes: vec![source, sink],
            evidence_edges: vec![],
            path_explanation: None,
            local_direct_reason: Some(
                "Source and sink occur in the same expression on the cited line.".to_string(),
            ),
            sanitizer_assessment: Some(
                "No escaping call is present in the expression.".to_string(),
            ),
            guard_assessment: Some("No guard affects output encoding on this line.".to_string()),
            assumptions: vec!["req.query.name is request-controlled.".to_string()],
            missing_evidence: vec!["No runtime browser execution was performed.".to_string()],
        };

        let report = validate_static_proof_claim(temp.path(), &claim).unwrap();

        assert!(report.complete, "{:?}", report.reasons);
        assert_eq!(
            report.validated_static_proof_state,
            StaticProofState::StaticallyConfirmed
        );
    }

    #[test]
    fn static_proof_validator_downgrades_missing_sink_true_positive() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(
            temp.path().join("src/routes.ts"),
            "let id = req.query.id;\n",
        )
        .unwrap();
        let mut finding = Finding::new_tool(
            "whitebox-static",
            "demo.incomplete",
            "src/routes.ts",
            1,
            Some(1),
            Severity::High,
            "claimed without sink",
        )
        .with_static_proof_state(StaticProofState::StaticallyConfirmed);
        finding.triage = Some(TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.95,
            rationale: "claimed vulnerable".to_string(),
        });
        let source = node_from_span(
            temp.path(),
            StaticEvidenceNodeKind::Source,
            finding.fingerprint.as_str(),
            "query source",
            "src/routes.ts",
            1,
            json!({"role": "source"}),
        );
        let claim = StaticProofClaim {
            finding: finding.clone(),
            evidence_nodes: vec![source],
            evidence_edges: vec![],
            path_explanation: Some("Only source evidence is present.".to_string()),
            local_direct_reason: None,
            sanitizer_assessment: Some("No sanitizer assessment for a sink exists.".to_string()),
            guard_assessment: Some("No guard assessment for a sink exists.".to_string()),
            assumptions: vec!["Request input is attacker controlled.".to_string()],
            missing_evidence: vec!["Sink evidence is missing.".to_string()],
        };

        let report = validate_static_proof_claim(temp.path(), &claim).unwrap();

        assert!(!report.complete);
        assert!(report
            .reasons
            .iter()
            .any(|reason| reason.contains("sink or security-sensitive")));
        assert_eq!(
            report.validated_static_proof_state,
            StaticProofState::NeedsRuntimeEvidence
        );
        assert_eq!(report.validated_verdict, Some(TriageVerdict::NeedsReview));

        let mut updated = finding;
        apply_static_proof_validation_to_finding(&mut updated, &report);
        assert_eq!(
            updated.static_proof_state,
            Some(StaticProofState::NeedsRuntimeEvidence)
        );
        assert_eq!(
            updated.triage.as_ref().map(|triage| triage.verdict),
            Some(TriageVerdict::NeedsReview)
        );
        assert!(updated
            .triage
            .as_ref()
            .unwrap()
            .rationale
            .contains("downgraded"));
    }

    #[test]
    fn static_proof_validator_downgrades_stale_code_citation() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(
            temp.path().join("src/routes.ts"),
            "let id = req.query.id;\n",
        )
        .unwrap();
        let mut finding = Finding::new_tool(
            "whitebox-static",
            "demo.stale",
            "src/routes.ts",
            1,
            Some(1),
            Severity::High,
            "stale citation claim",
        )
        .with_static_proof_state(StaticProofState::StaticallyConfirmed);
        finding.triage = Some(TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.9,
            rationale: "claimed vulnerable".to_string(),
        });
        let mut source = node_from_span(
            temp.path(),
            StaticEvidenceNodeKind::Source,
            finding.fingerprint.as_str(),
            "query source",
            "src/routes.ts",
            1,
            json!({"role": "source"}),
        );
        source.body = "let id = req.body.id;".to_string();
        let sink = node_from_span(
            temp.path(),
            StaticEvidenceNodeKind::Sink,
            finding.fingerprint.as_str(),
            "query sink",
            "src/routes.ts",
            1,
            json!({"role": "sink"}),
        );
        let claim = StaticProofClaim {
            finding,
            evidence_nodes: vec![source, sink],
            evidence_edges: vec![],
            path_explanation: Some("claimed path".to_string()),
            local_direct_reason: None,
            sanitizer_assessment: Some("claimed sanitizer assessment".to_string()),
            guard_assessment: Some("claimed guard assessment".to_string()),
            assumptions: vec!["assumption recorded".to_string()],
            missing_evidence: vec!["missing evidence recorded".to_string()],
        };

        let report = validate_static_proof_claim(temp.path(), &claim).unwrap();

        assert!(!report.complete);
        assert!(report.reasons.iter().any(|reason| reason.contains("stale")));
        assert_eq!(
            report.validated_static_proof_state,
            StaticProofState::NeedsRuntimeEvidence
        );
    }

    #[test]
    fn static_proof_validator_downgrades_true_positive_without_static_confirmation() {
        let temp = tempfile::tempdir().unwrap();
        let mut finding = Finding::new_tool(
            "semgrep",
            "demo.signal",
            "src/app.ts",
            1,
            Some(1),
            Severity::Medium,
            "scanner signal",
        )
        .with_static_proof_state(StaticProofState::CodeCited);
        finding.triage = Some(TriageOutcome {
            verdict: TriageVerdict::TruePositive,
            confidence: 0.7,
            rationale: "model said true positive".to_string(),
        });
        let claim = StaticProofClaim::new(finding);

        let report = validate_static_proof_claim(temp.path(), &claim).unwrap();

        assert!(!report.complete);
        assert!(report
            .reasons
            .iter()
            .any(|reason| reason.contains("requires staticProofState=statically_confirmed")));
        assert_eq!(
            report.validated_static_proof_state,
            StaticProofState::NeedsRuntimeEvidence
        );
        assert_eq!(report.validated_verdict, Some(TriageVerdict::NeedsReview));
    }

    fn node_from_span(
        repo_root: &Path,
        kind: StaticEvidenceNodeKind,
        fingerprint: &str,
        title: &str,
        file_path: &str,
        line: u32,
        metadata: serde_json::Value,
    ) -> StaticEvidenceNode {
        let span = extract_source_span(repo_root, file_path, line, line).unwrap();
        StaticEvidenceNode::new(kind, title, span.snippet.clone())
            .with_finding_fingerprint(fingerprint)
            .with_source_span(span.file_path, span.start_line, Some(span.end_line))
            .with_metadata(metadata)
    }
}
