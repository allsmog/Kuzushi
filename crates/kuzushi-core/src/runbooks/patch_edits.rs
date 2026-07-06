use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchDecision {
    CandidateEdit,
    NoPatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuredPatchEdit {
    pub file: String,
    pub anchor_before: String,
    pub old: String,
    pub new: String,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchAuthorOutput {
    pub schema_version: String,
    pub decision: PatchDecision,
    #[serde(default)]
    pub edits: Vec<StructuredPatchEdit>,
    pub rationale: String,
    #[serde(default)]
    pub variants_checked: Vec<String>,
    pub bypass_considered: String,
    pub test_note: String,
}

impl PatchAuthorOutput {
    pub fn no_patch(rationale: impl Into<String>) -> Self {
        Self {
            schema_version: "fix.patch-author.v1".to_string(),
            decision: PatchDecision::NoPatch,
            edits: Vec::new(),
            rationale: rationale.into(),
            variants_checked: Vec::new(),
            bypass_considered: String::new(),
            test_note: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatchReviewDecision {
    Accept,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchReviewOutput {
    pub schema_version: String,
    pub review: PatchReviewDecision,
    pub style_score: u8,
    #[serde(default)]
    pub out_of_scope_hunks: Vec<String>,
    pub reason: String,
}

impl PatchReviewOutput {
    pub fn accepted(style_score: u8, reason: impl Into<String>) -> Self {
        Self {
            schema_version: "fix.patch-review.v1".to_string(),
            review: PatchReviewDecision::Accept,
            style_score,
            out_of_scope_hunks: Vec::new(),
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_patch_has_empty_edit_list() {
        let output = PatchAuthorOutput::no_patch("already fixed");
        assert_eq!(output.decision, PatchDecision::NoPatch);
        assert!(output.edits.is_empty());
    }
}
