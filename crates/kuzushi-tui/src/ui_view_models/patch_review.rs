use crate::{PendingPatch, ShellApp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PatchReviewModel {
    pub(crate) alias: String,
    pub(crate) patch_run_id: String,
    pub(crate) status: String,
    pub(crate) rationale: String,
    pub(crate) side_effect: Option<String>,
    pub(crate) diff: String,
    pub(crate) tests: Vec<PatchReviewTestRow>,
    pub(crate) guardrail: Option<String>,
    pub(crate) staged_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PatchReviewTestRow {
    pub(crate) name: String,
    pub(crate) blurb: String,
}

pub(crate) fn patch_review_model(app: &ShellApp, alias: &str) -> Option<PatchReviewModel> {
    app.engagement
        .pending_patch()
        .filter(|patch| patch.alias == alias)
        .map(PatchReviewModel::from_patch)
}

impl PatchReviewModel {
    fn from_patch(patch: &PendingPatch) -> Self {
        Self {
            alias: patch.alias.clone(),
            patch_run_id: patch.patch_run_id.clone(),
            status: patch.status.as_str().to_string(),
            rationale: patch.rationale.clone(),
            side_effect: patch.side_effect.clone(),
            diff: patch.diff.clone(),
            tests: patch
                .tests
                .iter()
                .map(|(name, blurb)| PatchReviewTestRow {
                    name: name.clone(),
                    blurb: blurb.clone(),
                })
                .collect(),
            guardrail: patch.guardrail.clone(),
            staged_at: patch.staged_at.clone(),
        }
    }
}

#[cfg(test)]
mod tests;
