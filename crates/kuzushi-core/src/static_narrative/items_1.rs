use super::prelude::*;
use super::*;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticNarrativeReport {
    pub count: usize,
    pub narratives: Vec<StaticFindingNarrative>,
    pub deterministic: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StaticFindingNarrative {
    pub fingerprint: String,
    pub rule_id: String,
    pub title: String,
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_impact_score: Option<i32>,
    pub static_trigger_path: String,
    pub potential_impact: String,
    pub evidence_limits: String,
}

pub fn build_static_narrative_report(
    findings: &[Finding],
    ranked: &[StaticRankedFinding],
) -> Result<StaticNarrativeReport> {
    let ranked_by_fingerprint = ranked
        .iter()
        .map(|finding| (finding.fingerprint.as_str(), finding))
        .collect::<HashMap<_, _>>();
    let mut narratives = findings
        .iter()
        .map(|finding| {
            let ranked = ranked_by_fingerprint
                .get(finding.fingerprint.as_str())
                .copied();
            static_finding_narrative(finding, ranked)
        })
        .collect::<Result<Vec<_>>>()?;
    narratives.sort_by(compare_narratives);

    Ok(StaticNarrativeReport {
        count: narratives.len(),
        narratives,
        deterministic: true,
    })
}

pub fn validate_static_narrative_text(
    static_trigger_path: &str,
    potential_impact: &str,
    evidence_limits: &str,
) -> Result<()> {
    let combined =
        format!("{static_trigger_path}\n{potential_impact}\n{evidence_limits}").to_lowercase();
    for forbidden in FORBIDDEN_STATIC_NARRATIVE_TERMS {
        if combined.contains(forbidden) {
            anyhow::bail!(
                "whitebox-static narrative must not include forbidden term {forbidden:?}"
            );
        }
    }
    Ok(())
}
