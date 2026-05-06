use std::collections::HashMap;

use anyhow::Result;
use serde::Serialize;

use crate::findings::{Finding, StaticProofState};
use crate::static_ranking::StaticRankedFinding;

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

fn static_finding_narrative(
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

fn compare_narratives(
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

fn finding_location(finding: &Finding) -> String {
    let end_line = finding.end_line.unwrap_or(finding.start_line);
    if end_line == finding.start_line {
        format!("{}:{}", finding.file_path, finding.start_line)
    } else {
        format!("{}:{}-{}", finding.file_path, finding.start_line, end_line)
    }
}

fn concise_title(finding: &Finding) -> String {
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

const FORBIDDEN_STATIC_NARRATIVE_TERMS: &[&str] = &[
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Finding, Severity, StaticProofState};
    use crate::static_ranking::{StaticImpactFactors, StaticImpactScore, StaticRankedFinding};

    #[test]
    fn static_narrative_report_includes_trigger_impact_and_limits() {
        let finding = Finding::new_tool(
            "codeql",
            "js/sql-injection",
            "src/routes.ts",
            10,
            Some(12),
            Severity::High,
            "SQL query uses request input",
        )
        .with_static_proof_state(StaticProofState::SourceSinkLinked);
        let ranked = ranked_for(&finding, 1, 94);

        let report = build_static_narrative_report(&[finding], &[ranked]).unwrap();

        assert_eq!(report.count, 1);
        let narrative = &report.narratives[0];
        assert!(narrative
            .static_trigger_path
            .contains("Static trigger path"));
        assert!(narrative
            .static_trigger_path
            .contains("src/routes.ts:10-12"));
        assert!(narrative.potential_impact.contains("Potential impact"));
        assert!(narrative.evidence_limits.contains("Evidence limits"));
        assert!(narrative.evidence_limits.contains("Runtime reachability"));
        assert_eq!(narrative.rank, Some(1));
        assert_eq!(narrative.static_impact_score, Some(94));
        assert_no_forbidden_language(narrative);
    }

    #[test]
    fn static_narrative_validation_rejects_exploit_and_poc_language() {
        for bad in [
            "The issue was exploited through the route.",
            "This is a confirmed exploit.",
            "PoC payload: curl http://127.0.0.1",
        ] {
            let error = validate_static_narrative_text(
                "Static trigger path: source reaches sink.",
                bad,
                "Evidence limits: runtime behavior is not assessed.",
            )
            .unwrap_err()
            .to_string();

            assert!(
                error.contains("forbidden term"),
                "unexpected error for {bad:?}: {error}"
            );
        }
    }

    #[test]
    fn static_narratives_are_ordered_by_static_rank_then_location() {
        let high = Finding::new_tool(
            "codeql",
            "js/sql-injection",
            "src/b.ts",
            20,
            Some(20),
            Severity::High,
            "source reaches sink",
        );
        let low = Finding::new_tool(
            "semgrep",
            "generic.warning",
            "src/a.ts",
            2,
            Some(2),
            Severity::Medium,
            "generic warning",
        );
        let high_ranked = ranked_for(&high, 1, 80);
        let low_ranked = ranked_for(&low, 2, 10);

        let report =
            build_static_narrative_report(&[low.clone(), high.clone()], &[low_ranked, high_ranked])
                .unwrap();

        assert_eq!(report.narratives[0].fingerprint, high.fingerprint);
        assert_eq!(report.narratives[1].fingerprint, low.fingerprint);
    }

    fn ranked_for(finding: &Finding, rank: usize, total: i32) -> StaticRankedFinding {
        StaticRankedFinding {
            rank,
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
            impact: StaticImpactScore {
                total,
                factors: StaticImpactFactors::default(),
                reasons: vec!["attack_surface_reachable".to_string()],
            },
        }
    }

    fn assert_no_forbidden_language(narrative: &StaticFindingNarrative) {
        validate_static_narrative_text(
            &narrative.static_trigger_path,
            &narrative.potential_impact,
            &narrative.evidence_limits,
        )
        .unwrap();
    }
}
