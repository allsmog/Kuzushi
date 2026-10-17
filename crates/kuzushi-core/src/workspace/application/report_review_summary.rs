use super::*;
use crate::findings::{IdentityFoldPolicy, ReviewDecisionCounts};

/// Full workspace export membership, independent of shell filters and Scan scope.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkspaceReviewSummary {
    pub finding_count: usize,
    pub decisions: ReviewDecisionCounts,
    pub reassessment_required: usize,
}

pub fn load_workspace_review_summary(
    workspace: &WorkspaceTarget,
    minimum_watermark: Option<u64>,
) -> Result<WorkspaceReviewSummary> {
    let path = workspace.findings_db_path();
    if !path.try_exists()? {
        anyhow::ensure!(minimum_watermark.is_none(), "Previously loaded findings ledger is unavailable; restore it before refreshing the report");
        return Ok(WorkspaceReviewSummary::default());
    }
    let store = FindingStore::open_read_only(path)?;
    store.with_projection_snapshot(|store| {
        let watermark = store.projection_meta()?.applied_seq;
        anyhow::ensure!(minimum_watermark.is_none_or(|known| watermark >= known),
            "Findings projection is older than the loaded ledger; restore it or reselect the target");
        let findings = store
            .list_all_findings_with_identity_policy(IdentityFoldPolicy::UNRESOLVED_RUN_SCOPE)?;
        let completion = review_completion_for_findings(workspace, store, &findings)?;
        Ok(WorkspaceReviewSummary {
            finding_count: findings.len(),
            decisions: completion.decisions,
            reassessment_required: completion.reassessment_required,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_ledger_is_empty_without_creation_and_damaged_ledger_is_unavailable() {
        let root = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        assert_eq!(
            load_workspace_review_summary(&workspace, None).unwrap(),
            WorkspaceReviewSummary::default()
        );
        assert!(!workspace.findings_db_path().exists());
        fs::create_dir_all(workspace.findings_db_path().parent().unwrap()).unwrap();
        fs::write(workspace.findings_db_path(), "Owned invalid ledger").unwrap();
        assert!(load_workspace_review_summary(&workspace, None).is_err());
    }
    #[test]
    fn previously_loaded_ledger_must_exist_and_cannot_regress() {
        let root = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        assert!(load_workspace_review_summary(&workspace, Some(0)).is_err());
        assert!(!workspace.findings_db_path().exists());
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let watermark = store.projection_meta().unwrap().applied_seq;
        assert_eq!(
            load_workspace_review_summary(&workspace, Some(watermark)).unwrap(),
            WorkspaceReviewSummary::default()
        );
        assert!(load_workspace_review_summary(&workspace, Some(watermark + 1)).is_err());
        assert_eq!(store.projection_meta().unwrap().applied_seq, watermark);
    }
}
