use serde::{Deserialize, Serialize};

use super::dedupe::DedupeCluster;
use super::votes::{ConfirmFinalVerdict, ConfirmVoteVerdict, VerifierPromptVariant, VoteTally};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnippetShown {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierVoteRecord {
    pub vote_index: u32,
    pub model: String,
    pub temperature: f32,
    pub prompt_variant: VerifierPromptVariant,
    pub verdict: ConfirmVoteVerdict,
    pub confidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_link: Option<String>,
    #[serde(default)]
    pub citations: Vec<String>,
    pub rationale: String,
    #[serde(default)]
    pub cost_usd: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerdictChainArtifact {
    pub schema_version: String,
    pub runbook_id: String,
    pub runbook_version: String,
    pub finding_id: String,
    pub candidate_fingerprint: String,
    #[serde(default)]
    pub snippets_shown: Vec<SnippetShown>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedupe_cluster: Option<DedupeCluster>,
    #[serde(default)]
    pub votes: Vec<VerifierVoteRecord>,
    pub tally: VoteTally,
    pub final_verdict: ConfirmFinalVerdict,
}

impl VerdictChainArtifact {
    pub fn new(
        runbook_id: impl Into<String>,
        runbook_version: impl Into<String>,
        finding_id: impl Into<String>,
        candidate_fingerprint: impl Into<String>,
        tally: VoteTally,
    ) -> Self {
        let final_verdict = tally.final_verdict;
        Self {
            schema_version: "confirm.verdict-chain.v1".to_string(),
            runbook_id: runbook_id.into(),
            runbook_version: runbook_version.into(),
            finding_id: finding_id.into(),
            candidate_fingerprint: candidate_fingerprint.into(),
            snippets_shown: Vec::new(),
            dedupe_cluster: None,
            votes: Vec::new(),
            tally,
            final_verdict,
        }
    }
}
