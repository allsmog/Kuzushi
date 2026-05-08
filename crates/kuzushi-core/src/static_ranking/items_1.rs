use super::prelude::*;
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticRankedFinding {
    pub rank: usize,
    pub fingerprint: String,
    pub rule_id: String,
    pub title: String,
    pub tool: String,
    pub file_path: String,
    pub start_line: u32,
    pub severity: String,
    pub static_proof_state: Option<String>,
    pub impact: StaticImpactScore,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticImpactScore {
    pub total: i32,
    pub factors: StaticImpactFactors,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticImpactFactors {
    pub severity: i32,
    pub static_proof: i32,
    pub attack_surface_reachability: i32,
    pub source_sink_class: i32,
    pub data_sensitivity: i32,
    pub privilege_boundary: i32,
    pub sanitizer_absence: i32,
    pub framework_context: i32,
    pub codeql_flow_quality: i32,
    pub confidence: i32,
    pub threat_model_priority: i32,
    pub noise_adjustment: i32,
}

pub fn rank_static_findings(
    findings: &[Finding],
    attack_surface: Option<&AttackSurfaceMap>,
    evidence_store: Option<&StaticEvidenceStore>,
) -> Result<Vec<StaticRankedFinding>> {
    rank_static_findings_with_threats(findings, attack_surface, evidence_store, None)
}

pub fn rank_static_findings_with_threats(
    findings: &[Finding],
    attack_surface: Option<&AttackSurfaceMap>,
    evidence_store: Option<&StaticEvidenceStore>,
    threat_model: Option<&Value>,
) -> Result<Vec<StaticRankedFinding>> {
    let mut ranked = Vec::new();
    for finding in findings {
        let evidence_nodes = match evidence_store {
            Some(store) => store.list_nodes_for_finding(&finding.fingerprint)?,
            None => Vec::new(),
        };
        ranked.push(StaticRankedFinding {
            rank: 0,
            fingerprint: finding.fingerprint.clone(),
            rule_id: finding.rule_id.clone(),
            title: finding.title.clone(),
            tool: finding.tool.clone(),
            file_path: finding.file_path.clone(),
            start_line: finding.start_line,
            severity: finding.severity.as_str().to_string(),
            static_proof_state: finding
                .static_proof_state
                .map(|state| state.as_str().to_string()),
            impact: score_static_finding_with_threats(
                finding,
                attack_surface,
                &evidence_nodes,
                threat_model,
            ),
        });
    }

    ranked.sort_by(compare_ranked_findings);
    for (index, finding) in ranked.iter_mut().enumerate() {
        finding.rank = index + 1;
    }
    Ok(ranked)
}

pub fn score_static_finding(
    finding: &Finding,
    attack_surface: Option<&AttackSurfaceMap>,
    evidence_nodes: &[StaticEvidenceNode],
) -> StaticImpactScore {
    score_static_finding_with_threats(finding, attack_surface, evidence_nodes, None)
}
