use super::*;
use crate::findings::BatchOccurrenceReport;

pub(super) fn page_snapshot(
    page: FindingListPage,
    mut study: Option<BatchOccurrenceReport>,
    workspace: &WorkspaceTarget,
    store: &FindingStore,
) -> FindingPageSnapshot {
    // Gate metadata does not determine membership or invalidate its cursor.
    // Authenticate it separately so stale assessment cannot prevent triage.
    let study_gate_error = study
        .as_mut()
        .and_then(|report| {
            super::super::batch_occurrence::hydrate_report_gate(workspace.root(), store, report)
                .err()
        })
        .map(|error| format!("Study severity assessment unavailable: {error:#}"));
    FindingPageSnapshot {
        page,
        study,
        study_gate_error,
    }
}
