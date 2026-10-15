//! A committed decision remains saved when its source receipt is unavailable.
use super::export_decision_basis::WorkspaceReviewDecisionBasis;
use crate::findings::{finding_stable_fp, Finding, FindingStore, ReviewDecision};
use crate::WorkspaceTarget;
use anyhow::{Context, Result};
use serde::Serialize;
mod presentation;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceReviewDecisionReceipt {
    pub schema_version: u32,
    pub decision_id: i64,
    pub source_basis: Option<WorkspaceReviewDecisionBasis>,
    pub source_read_error: Option<String>,
}

pub fn record_user_review_decision_with_receipt(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    decision: &ReviewDecision,
    read_watermark: Option<u64>,
    review_session_id: Option<String>,
) -> Result<WorkspaceReviewDecisionReceipt> {
    let decision_id =
        super::record_review_decision::record_user_review_decision_for_finding_with_session(
            workspace,
            finding,
            decision,
            read_watermark,
            review_session_id,
        )?;
    let source = read_review_decision_receipt(workspace, finding, decision_id);
    Ok(receipt_after_commit(decision_id, source))
}

fn receipt_after_commit(
    decision_id: i64,
    source: Result<Option<WorkspaceReviewDecisionBasis>>,
) -> WorkspaceReviewDecisionReceipt {
    let (source_basis, source_read_error) = match source {
        Ok(basis) => (basis, None),
        Err(error) => (None, Some(error.to_string())),
    };
    WorkspaceReviewDecisionReceipt {
        schema_version: 1,
        decision_id,
        source_basis,
        source_read_error,
    }
}

pub fn read_review_decision_receipt(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    decision_id: i64,
) -> Result<Option<WorkspaceReviewDecisionBasis>> {
    let store = FindingStore::open_read_only(workspace.findings_db_path())?;
    let record = store
        .review_decision_by_id(decision_id)?
        .context("The saved decision is not present in this ledger")?;
    anyhow::ensure!(
        record.finding_id == finding.id.context("Finding has no recorded id")?,
        "The saved decision belongs to another finding"
    );
    let Some(watermark) = record
        .provenance
        .and_then(|provenance| provenance.read_watermark)
    else {
        return Ok(None);
    };
    super::export_decision_basis::read_finding_review_source(
        workspace,
        &finding_stable_fp(finding),
        watermark,
        Some(watermark),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_read_failure_preserves_the_committed_decision_id() {
        let receipt = receipt_after_commit(42, Err(anyhow::anyhow!("source receipt unavailable")));
        assert_eq!(receipt.decision_id, 42);
        assert!(receipt.source_basis.is_none());
        assert_eq!(
            receipt.source_read_error.as_deref(),
            Some("source receipt unavailable")
        );
    }

    #[test]
    fn legacy_source_is_unavailable_without_a_fabricated_error_or_basis() {
        let receipt = receipt_after_commit(7, Ok(None));
        assert_eq!(receipt.decision_id, 7);
        assert!(receipt.source_basis.is_none());
        assert!(receipt.source_read_error.is_none());
    }

    fn observed_fixture() -> (tempfile::TempDir, WorkspaceTarget, FindingStore, Finding) {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("note.txt"),
            "Owned inert receipt fixture.\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let finding = Finding::new_tool(
            "native",
            "owned.rule",
            "note.txt",
            1,
            Some(1),
            crate::findings::Severity::Low,
            "Owned receipt fixture",
        );
        observe(&store, workspace.root(), "observed-a", &finding);
        let persisted = store
            .get_finding_by_fingerprint(&finding.fingerprint)
            .unwrap()
            .unwrap();
        (root, workspace, store, persisted)
    }

    fn observe(store: &FindingStore, root: &std::path::Path, run: &str, finding: &Finding) {
        store.record_run_started(run, root, "running").unwrap();
        store.insert_finding(run, finding).unwrap();
        store.record_run_finished(run, "completed", 1).unwrap();
    }

    fn human_decision() -> ReviewDecision {
        ReviewDecision::dismissal(
            crate::findings::DismissReason::FalsePositive,
            "Owned inert fixture is intentional",
            "operator",
        )
    }

    #[test]
    fn exact_receipt_does_not_drift_to_a_later_observation_or_decision() {
        let (_root, workspace, store, finding) = observed_fixture();
        let first = record_user_review_decision_with_receipt(
            &workspace,
            &finding,
            &human_decision(),
            None,
            None,
        )
        .unwrap();
        assert_eq!(first.source_basis.as_ref().unwrap().run_id, "observed-a");
        observe(&store, workspace.root(), "observed-b", &finding);
        let later = record_user_review_decision_with_receipt(
            &workspace,
            &finding,
            &human_decision(),
            None,
            None,
        )
        .unwrap();
        assert_eq!(later.source_basis.as_ref().unwrap().run_id, "observed-b");
        let reloaded = read_review_decision_receipt(&workspace, &finding, first.decision_id)
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.run_id, "observed-a");
        assert!(reloaded.later_observation.is_none());
        assert_eq!(
            store
                .list_review_decisions(finding.id.unwrap())
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn receipt_refuses_a_decision_for_another_finding() {
        let (_root, workspace, _store, finding) = observed_fixture();
        let receipt = record_user_review_decision_with_receipt(
            &workspace,
            &finding,
            &human_decision(),
            None,
            None,
        )
        .unwrap();
        let mut wrong = finding;
        wrong.id = Some(9_999);
        assert!(
            read_review_decision_receipt(&workspace, &wrong, receipt.decision_id)
                .unwrap_err()
                .to_string()
                .contains("another finding")
        );
    }
}
