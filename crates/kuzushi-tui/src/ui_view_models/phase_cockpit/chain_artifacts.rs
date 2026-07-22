//! Attack chains as artifacts over the triaged result set.
//!
//! The deterministic `chains.rs` fold runs live over the confirmed findings
//! (the same fold `findings:chains` persists), so every candidate names its
//! constituent findings by alias. Grounded chains from `exploit-chain:scan`
//! render beside the fold. The triage mutation a chain implies — a low
//! constituent inside a high-impact chain — is advisory copy until the core
//! chain-triage pass makes it durable.

use super::super::review_state::EffectiveReviewStateIndex;
use super::{ChainArtifactsModel, ChainCandidateModel, ChainLinkModel};
use crate::ShellApp;
use kuzushi_core::capabilities::chains::{fold_chains, ChainCandidate, ChainLink};
use kuzushi_core::findings::ReviewDecisionVerdict;
use kuzushi_core::Finding;
use std::collections::BTreeMap;

const MAX_CHAIN_CANDIDATES: usize = 6;

pub(super) fn chain_artifacts_model(app: &ShellApp) -> Option<ChainArtifactsModel> {
    if !app.router.workbench().chains_view_open() {
        return None;
    }
    let confirmed = confirmed_findings(app);
    let report = fold_chains(&confirmed, MAX_CHAIN_CANDIDATES);
    let aliases = alias_by_fingerprint(app);
    Some(ChainArtifactsModel {
        confirmed_count: report.confirmed_count,
        identity: super::identity::engagement_identity_line(app),
        candidates: report
            .chains
            .iter()
            .map(|candidate| candidate_model(candidate, &aliases))
            .collect(),
        grounded: app.domain.exploit_chains().to_vec(),
    })
}

/// Confirmed = the same semantics the core fold uses: latest effective
/// review decision is Confirmed or ToFix, suppressed findings excluded.
fn confirmed_findings(app: &ShellApp) -> Vec<Finding> {
    let findings = app.findings();
    let index =
        EffectiveReviewStateIndex::from_findings_and_decisions(findings, app.review_decisions());
    findings
        .iter()
        .filter(|finding| !finding.suppressed)
        .filter(|finding| {
            index
                .effective_decision_for(finding)
                .is_some_and(|decision| {
                    matches!(
                        decision.verdict(),
                        ReviewDecisionVerdict::Confirmed | ReviewDecisionVerdict::ToFix
                    )
                })
        })
        .cloned()
        .collect()
}

fn alias_by_fingerprint(app: &ShellApp) -> BTreeMap<String, String> {
    let findings = app.findings();
    kuzushi_core::sorted_finding_alias_indices(findings)
        .into_iter()
        .filter_map(|(alias, index)| {
            findings
                .get(index)
                .map(|finding| (finding.fingerprint.clone(), alias))
        })
        .collect()
}

fn candidate_model(
    candidate: &ChainCandidate,
    aliases: &BTreeMap<String, String>,
) -> ChainCandidateModel {
    let links: Vec<ChainLinkModel> = candidate
        .pivots
        .iter()
        .fold(
            vec![link_model(&candidate.entry, aliases)],
            |mut acc, pivot| {
                acc.push(link_model(pivot, aliases));
                acc
            },
        )
        .into_iter()
        .chain(std::iter::once(link_model(&candidate.impact, aliases)))
        .collect();
    let open_command = format!("open {}", links[0].reference);
    ChainCandidateModel {
        surface: candidate.surface.clone(),
        mutation_note: mutation_note(&links),
        rationale: candidate.rationale.clone(),
        links,
        open_command,
    }
}

fn link_model(link: &ChainLink, aliases: &BTreeMap<String, String>) -> ChainLinkModel {
    ChainLinkModel {
        role: format!("{:?}", link.role).to_lowercase(),
        reference: aliases
            .get(&link.fingerprint)
            .cloned()
            .unwrap_or_else(|| short_fingerprint(&link.fingerprint)),
        severity: link.severity.clone(),
        title: link.title.clone(),
        file: link.file_path.clone(),
    }
}

fn short_fingerprint(fingerprint: &str) -> String {
    fingerprint.chars().take(10).collect()
}

/// The composed chain reaches further than its weakest constituent: name the
/// constituents whose recorded severity understates their role in the chain.
/// Advisory — chain triage in core will make this a durable severity revision.
fn mutation_note(links: &[ChainLinkModel]) -> Option<String> {
    let max = links
        .iter()
        .map(|link| severity_rank(&link.severity))
        .max()?;
    let raised: Vec<&str> = links
        .iter()
        .filter(|link| severity_rank(&link.severity) < max)
        .map(|link| link.reference.as_str())
        .collect();
    if raised.is_empty() {
        return None;
    }
    Some(format!(
        "chain would raise {} toward the composed impact (advisory — chain triage lands in core)",
        raised.join(", ")
    ))
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(role: &str, reference: &str, severity: &str) -> ChainLinkModel {
        ChainLinkModel {
            role: role.to_string(),
            reference: reference.to_string(),
            severity: severity.to_string(),
            title: String::new(),
            file: String::new(),
        }
    }

    #[test]
    fn mutation_note_names_only_the_understated_constituents() {
        let links = vec![
            link("entry", "F-1", "medium"),
            link("pivot", "F-2", "low"),
            link("impact", "F-3", "high"),
        ];
        let note = mutation_note(&links).unwrap();
        assert!(note.contains("F-1, F-2"), "{note}");
        assert!(!note.contains("F-3,"), "{note}");
        assert!(note.contains("advisory"), "{note}");
    }

    #[test]
    fn uniform_severity_chain_implies_no_mutation() {
        let links = vec![link("entry", "F-1", "high"), link("impact", "F-2", "high")];
        assert_eq!(mutation_note(&links), None);
    }
}
