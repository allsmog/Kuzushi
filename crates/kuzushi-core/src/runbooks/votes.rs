use crate::runtime::ModelTier;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierPromptVariant {
    GuardFirst,
    ReachabilityFirst,
    SinkFirst,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifierVoteConfig {
    pub vote_index: u32,
    pub model_tier: ModelTier,
    pub temperature: f32,
    pub prompt_variant: VerifierPromptVariant,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VotePlan {
    pub finding_id: String,
    pub votes: Vec<VerifierVoteConfig>,
}

impl VotePlan {
    pub fn default_for(finding_id: impl Into<String>, requested_votes: u32) -> Self {
        let requested_votes = crate::runbooks::budget::normalize_odd_vote_count(requested_votes);
        let variants = [
            (VerifierPromptVariant::GuardFirst, 0.0, ModelTier::Mid),
            (VerifierPromptVariant::ReachabilityFirst, 0.2, ModelTier::Mid),
            (VerifierPromptVariant::SinkFirst, 0.1, ModelTier::Mid),
            (VerifierPromptVariant::GuardFirst, 0.3, ModelTier::Cheap),
            (VerifierPromptVariant::ReachabilityFirst, 0.0, ModelTier::Deep),
        ];
        let votes = variants
            .iter()
            .take(requested_votes as usize)
            .enumerate()
            .map(|(index, (prompt_variant, temperature, model_tier))| VerifierVoteConfig {
                vote_index: index as u32 + 1,
                model_tier: *model_tier,
                temperature: *temperature,
                prompt_variant: *prompt_variant,
            })
            .collect();
        Self {
            finding_id: finding_id.into(),
            votes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmVoteVerdict {
    TruePositive,
    FalsePositive,
    CannotVerify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoiseTolerance {
    Precision,
    Recall,
    NeedsReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoteTally {
    pub policy_version: String,
    pub true_positive: u32,
    pub false_positive: u32,
    pub cannot_verify: u32,
    pub final_verdict: ConfirmFinalVerdict,
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmFinalVerdict {
    TruePositive,
    FalsePositive,
    NeedsReview,
}

pub fn tally_votes(votes: &[ConfirmVoteVerdict], tolerance: NoiseTolerance) -> VoteTally {
    let true_positive = votes
        .iter()
        .filter(|vote| **vote == ConfirmVoteVerdict::TruePositive)
        .count() as u32;
    let false_positive = votes
        .iter()
        .filter(|vote| **vote == ConfirmVoteVerdict::FalsePositive)
        .count() as u32;
    let cannot_verify = votes
        .iter()
        .filter(|vote| **vote == ConfirmVoteVerdict::CannotVerify)
        .count() as u32;
    let max = true_positive.max(false_positive).max(cannot_verify);
    let winners = [true_positive, false_positive, cannot_verify]
        .into_iter()
        .filter(|count| *count == max)
        .count();
    let final_verdict = if winners == 1 && true_positive == max {
        ConfirmFinalVerdict::TruePositive
    } else if winners == 1 && false_positive == max {
        ConfirmFinalVerdict::FalsePositive
    } else if winners == 1 && cannot_verify == max {
        ConfirmFinalVerdict::NeedsReview
    } else {
        match tolerance {
            NoiseTolerance::Precision => ConfirmFinalVerdict::FalsePositive,
            NoiseTolerance::Recall | NoiseTolerance::NeedsReview => ConfirmFinalVerdict::NeedsReview,
        }
    };
    VoteTally {
        policy_version: "majority.v1".to_string(),
        true_positive,
        false_positive,
        cannot_verify,
        final_verdict,
        rationale: format!(
            "tp={true_positive} fp={false_positive} cannot_verify={cannot_verify}; policy=majority.v1"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vote_plan_decorrelates_prompt_variants() {
        let plan = VotePlan::default_for("F-1", 3);
        assert_eq!(plan.votes.len(), 3);
        assert_ne!(plan.votes[0].prompt_variant, plan.votes[1].prompt_variant);
    }

    #[test]
    fn cannot_verify_majority_becomes_needs_review() {
        let tally = tally_votes(
            &[
                ConfirmVoteVerdict::CannotVerify,
                ConfirmVoteVerdict::CannotVerify,
                ConfirmVoteVerdict::TruePositive,
            ],
            NoiseTolerance::Precision,
        );
        assert_eq!(tally.final_verdict, ConfirmFinalVerdict::NeedsReview);
    }
}
