//! Operator priorities are independent of finding truth and confidence.
use super::*;
use crate::capabilities::campaign::BriefReference;

pub(crate) const GOAL_RELEVANCE_SUBJECT: &str = "finding-goal-relevance-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoalRelevance {
    Direct,
    Related,
    Outside,
    Uncertain,
    Cleared,
}

impl GoalRelevance {
    pub fn label(self) -> &'static str {
        match self {
            Self::Direct => "Direct",
            Self::Related => "Related",
            Self::Outside => "Outside goal",
            Self::Uncertain => "Uncertain",
            Self::Cleared => "Cleared",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Related => "related",
            Self::Outside => "outside",
            Self::Uncertain => "uncertain",
            Self::Cleared => "cleared",
        }
    }

    pub(crate) fn order(self) -> u8 {
        match self {
            Self::Direct => 0,
            Self::Related => 1,
            Self::Uncertain => 3,
            Self::Outside => 4,
            Self::Cleared => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingGoalBasis {
    pub finding_id: i64,
    pub stable_key: String,
    pub fingerprint: String,
    pub observation_seq: u64,
    pub run_id: String,
    pub snapshot_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingGoalAssessment {
    pub schema_version: u32,
    pub id: String,
    pub revision: u64,
    pub brief_ref: BriefReference,
    pub brief_text: String,
    pub basis: FindingGoalBasis,
    pub relevance: GoalRelevance,
    pub reason: String,
    pub author: String,
    pub recorded_at: String,
}

impl FindingGoalAssessment {
    pub(crate) fn key(brief: &BriefReference, finding_id: i64) -> String {
        format!("goal_{}_{}_{}", brief.brief_id, brief.revision, finding_id)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.brief_ref.validate()?;
        anyhow::ensure!(
            self.schema_version == 1 && self.revision > 0,
            "Unsupported goal assessment revision"
        );
        anyhow::ensure!(
            self.id == Self::key(&self.brief_ref, self.basis.finding_id),
            "Goal assessment identity differs from its brief or finding"
        );
        anyhow::ensure!(
            self.basis.finding_id > 0 && self.basis.observation_seq > 0,
            "Goal assessment requires a recorded finding observation"
        );
        anyhow::ensure!(
            !self.reason.trim().is_empty() && self.reason.len() <= 4096,
            "Goal relevance reason must contain 1 to 4096 bytes"
        );
        self.validate_brief_text()?;
        anyhow::ensure!(
            self.author == "operator",
            "Goal relevance requires operator review"
        );
        Ok(())
    }
    fn validate_brief_text(&self) -> Result<()> {
        anyhow::ensure!(
            !self.brief_text.trim().is_empty() && self.brief_text.len() <= 8192,
            "Goal assessment brief text is invalid"
        );
        Ok(())
    }
}
