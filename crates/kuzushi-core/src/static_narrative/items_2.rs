use super::prelude::*;
use super::*;

pub(crate) fn static_finding_narrative(
    finding: &Finding,
    ranked: Option<&StaticRankedFinding>,
) -> Result<StaticFindingNarrative> {
    let location = finding_location(finding);
    let proof_state = finding
        .static_proof_state
        .map(StaticProofState::as_str)
        .unwrap_or("signal_only");
    let rank_reason = ranked
        .map(|ranked| {
            format!(
                " Static rank {} has score {} with factors: {}.",
                ranked.rank,
                ranked.impact.total,
                ranked.impact.reasons.join(", ")
            )
        })
        .unwrap_or_default();
    let static_trigger_path = format!(
        "Static trigger path: {} is the cited source location for rule {} with proof state {}.{}",
        location, finding.rule_id, proof_state, rank_reason
    );
    let potential_impact = format!(
        "Potential impact: {} severity source evidence may affect the security boundary described by {} if the static assumptions hold.",
        finding.severity.as_str(),
        concise_title(finding)
    );
    let evidence_limits = [
        "Evidence limits: whitebox-static uses source citations, scanner signals, and deterministic static context only.",
        "Runtime reachability, deployment configuration, live inputs, and active behavior are not assessed.",
        "Use needs_runtime_evidence when source evidence is insufficient.",
    ]
    .join(" ");
    validate_static_narrative_text(&static_trigger_path, &potential_impact, &evidence_limits)?;

    Ok(StaticFindingNarrative {
        fingerprint: finding.fingerprint.clone(),
        rule_id: finding.rule_id.clone(),
        title: finding.title.clone(),
        location,
        rank: ranked.map(|ranked| ranked.rank),
        static_impact_score: ranked.map(|ranked| ranked.impact.total),
        static_trigger_path,
        potential_impact,
        evidence_limits,
    })
}

pub(crate) fn compare_narratives(
    left: &StaticFindingNarrative,
    right: &StaticFindingNarrative,
) -> std::cmp::Ordering {
    left.rank
        .unwrap_or(usize::MAX)
        .cmp(&right.rank.unwrap_or(usize::MAX))
        .then_with(|| left.location.cmp(&right.location))
        .then_with(|| left.rule_id.cmp(&right.rule_id))
        .then_with(|| left.fingerprint.cmp(&right.fingerprint))
}

pub(crate) fn finding_location(finding: &Finding) -> String {
    let end_line = finding.end_line.unwrap_or(finding.start_line);
    if end_line == finding.start_line {
        format!("{}:{}", finding.file_path, finding.start_line)
    } else {
        format!("{}:{}-{}", finding.file_path, finding.start_line, end_line)
    }
}

pub(crate) fn concise_title(finding: &Finding) -> String {
    finding
        .title
        .lines()
        .next()
        .unwrap_or(finding.rule_id.as_str())
        .trim()
        .chars()
        .take(120)
        .collect()
}

pub(crate) const FORBIDDEN_STATIC_NARRATIVE_TERMS: &[&str] = &[
    "exploited",
    "confirmed exploit",
    "proof of concept",
    "proof-of-concept",
    "poc",
    "payload",
    "curl ",
    "http replay",
    "replay request",
    "fuzz",
    "live target",
];
