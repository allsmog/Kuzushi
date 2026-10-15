//! Bounded model inputs and confirmation checks at publication.
use super::*;
use serde::Serialize;

pub(super) struct ChainHuntLimits {
    pub max_chains: usize,
    pub max_candidates: usize,
    pub max_prior: usize,
    pub max_context_bytes: usize,
    pub max_output_tokens: u32,
}

impl ChainHuntLimits {
    pub fn from_input(input: &Value) -> Result<Self> {
        Ok(Self {
            max_chains: bounded(input, "maxChains", 8, 1, 32)?,
            max_candidates: bounded(input, "maxCandidates", 100, 2, 200)?,
            max_prior: bounded(input, "maxPriorChains", 32, 0, 64)?,
            max_context_bytes: bounded(input, "maxContextBytes", 65536, 1024, 524288)?,
            max_output_tokens: bounded(input, "maxOutputTokens", 4096, 256, 16384)? as u32,
        })
    }
}

fn bounded(input: &Value, key: &str, default: u64, min: u64, max: u64) -> Result<usize> {
    let value = match input.get(key) {
        None => default,
        Some(value) => value
            .as_u64()
            .with_context(|| format!("triage:chain-hunt {key} must be an integer"))?,
    };
    anyhow::ensure!(
        (min..=max).contains(&value),
        "triage:chain-hunt {key} must be between {min} and {max}"
    );
    Ok(value as usize)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct InputCoverage {
    pub eligible_confirmed: usize,
    pub supplied_confirmed: usize,
    pub prior_hypotheses: usize,
    pub supplied_prior: usize,
}

impl InputCoverage {
    pub fn is_partial(&self) -> bool {
        self.eligible_confirmed != self.supplied_confirmed
            || self.prior_hypotheses != self.supplied_prior
    }
}

pub(super) struct RelationshipInputs {
    pub confirmed: Vec<Finding>,
    pub prior: Vec<Finding>,
    pub coverage: InputCoverage,
}

pub(super) fn relationship_inputs(
    store: &crate::findings::FindingStore,
    limits: &ChainHuntLimits,
) -> Result<RelationshipInputs> {
    let mut confirmed = super::super::chains::confirmed_findings(store)?;
    confirmed.retain(|finding| !is_hypothesis(finding));
    confirmed.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    let mut prior = store
        .list_all_findings()?
        .into_iter()
        .filter(is_hypothesis)
        .collect::<Vec<_>>();
    prior.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    let coverage = InputCoverage {
        eligible_confirmed: confirmed.len(),
        supplied_confirmed: confirmed.len().min(limits.max_candidates),
        prior_hypotheses: prior.len(),
        supplied_prior: prior.len().min(limits.max_prior),
    };
    confirmed.truncate(limits.max_candidates);
    prior.truncate(limits.max_prior);
    Ok(RelationshipInputs {
        confirmed,
        prior,
        coverage,
    })
}

fn is_hypothesis(finding: &Finding) -> bool {
    finding.tool.trim().eq_ignore_ascii_case("chains")
}

pub(super) fn ensure_members_still_confirmed(
    store: &crate::findings::FindingStore,
    chains: &[ModelChain],
) -> Result<()> {
    let current = super::super::chains::confirmed_findings(store)?;
    let by_fp = super::fingerprint_index(&current);
    for member in chains.iter().flat_map(|chain| chain.members.iter()) {
        let finding = by_fp
            .get(member.fingerprint.as_str())
            .context("Relationship member is no longer confirmed; nothing published")?;
        anyhow::ensure!(
            finding.id == member.finding_id && finding.scan_id == member.scan_id,
            "Relationship member observation changed; nothing published"
        );
    }
    Ok(())
}
