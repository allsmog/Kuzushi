use super::prelude::*;
use super::*;

pub fn score_static_finding_with_threats(
    finding: &Finding,
    attack_surface: Option<&AttackSurfaceMap>,
    evidence_nodes: &[StaticEvidenceNode],
    threat_model: Option<&Value>,
) -> StaticImpactScore {
    let mut factors = StaticImpactFactors::default();
    let mut reasons = Vec::new();
    let corpus = finding_corpus(finding, evidence_nodes);

    factors.severity = severity_score(finding.severity);
    if factors.severity > 0 {
        reasons.push(format!("severity={}", finding.severity.as_str()));
    }

    factors.static_proof = static_proof_score(finding.static_proof_state);
    if let Some(state) = finding.static_proof_state {
        reasons.push(format!("static_proof_state={}", state.as_str()));
    }

    factors.attack_surface_reachability =
        attack_surface_score(finding, attack_surface, evidence_nodes, &mut reasons);
    factors.source_sink_class = source_sink_score(&corpus, &mut reasons);
    factors.data_sensitivity = data_sensitivity_score(&corpus, &mut reasons);
    factors.privilege_boundary =
        privilege_boundary_score(&corpus, attack_surface, finding, &mut reasons);
    factors.sanitizer_absence = sanitizer_absence_score(
        &corpus,
        evidence_nodes,
        finding.static_proof_state,
        &mut reasons,
    );
    factors.framework_context = framework_context_score(&corpus, attack_surface, finding);
    if factors.framework_context > 0 {
        reasons.push("framework_context".to_string());
    }
    factors.codeql_flow_quality = codeql_flow_score(finding, evidence_nodes, &corpus, &mut reasons);
    factors.confidence = confidence_score(finding, &corpus, &mut reasons);
    factors.threat_model_priority =
        threat_model_score(finding, threat_model, &corpus, &mut reasons);
    factors.noise_adjustment = noise_adjustment(finding, evidence_nodes, &corpus, &mut reasons);

    let total = factors.severity
        + factors.static_proof
        + factors.attack_surface_reachability
        + factors.source_sink_class
        + factors.data_sensitivity
        + factors.privilege_boundary
        + factors.sanitizer_absence
        + factors.framework_context
        + factors.codeql_flow_quality
        + factors.confidence
        + factors.threat_model_priority
        + factors.noise_adjustment;

    StaticImpactScore {
        total,
        factors,
        reasons,
    }
}

pub(crate) fn compare_ranked_findings(
    left: &StaticRankedFinding,
    right: &StaticRankedFinding,
) -> Ordering {
    right
        .impact
        .total
        .cmp(&left.impact.total)
        .then_with(|| severity_score_str(&right.severity).cmp(&severity_score_str(&left.severity)))
        .then_with(|| left.file_path.cmp(&right.file_path))
        .then_with(|| left.start_line.cmp(&right.start_line))
        .then_with(|| left.rule_id.cmp(&right.rule_id))
        .then_with(|| left.fingerprint.cmp(&right.fingerprint))
}

pub(crate) fn finding_corpus(finding: &Finding, evidence_nodes: &[StaticEvidenceNode]) -> String {
    let mut parts = vec![
        finding.rule_id.as_str(),
        finding.title.as_str(),
        finding.message.as_str(),
        finding.file_path.as_str(),
        finding.tool.as_str(),
    ];
    let mut owned = Vec::new();
    for node in evidence_nodes {
        parts.push(node.title.as_str());
        parts.push(node.body.as_str());
        if !node.metadata.is_null() {
            owned.push(node.metadata.to_string());
        }
    }
    for value in &owned {
        parts.push(value.as_str());
    }
    parts.join("\n").to_ascii_lowercase()
}

pub(crate) fn severity_score(severity: Severity) -> i32 {
    match severity {
        Severity::Critical => 30,
        Severity::High => 20,
        Severity::Medium => 10,
        Severity::Low => 4,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}
