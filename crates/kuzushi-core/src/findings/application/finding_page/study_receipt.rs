use super::*;
use crate::findings::BatchOccurrenceReport;

pub(super) fn page_snapshot(
    page: FindingListPage,
    mut study: Option<BatchOccurrenceReport>,
    workspace: &WorkspaceTarget,
    store: &FindingStore,
) -> Result<FindingPageSnapshot> {
    // Gate metadata does not determine membership or invalidate its cursor.
    // Authenticate it separately so stale assessment cannot prevent triage.
    let study_gate_error = if let Some(report) = &mut study {
        gate_read_notice(super::super::batch_occurrence::hydrate_report_gate(
            workspace.root(),
            store,
            report,
        ))?
    } else {
        None
    };
    Ok(FindingPageSnapshot {
        page,
        study,
        study_gate_error,
    })
}

fn gate_read_notice(result: Result<()>) -> Result<Option<String>> {
    match result {
        Ok(()) => Ok(None),
        Err(error) if error.is::<crate::findings::BatchReceiptPending>() => Err(error),
        Err(error) => Ok(Some(format!(
            "Study severity assessment unavailable: {error:#}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changing_snapshot_reaches_the_existing_refresh_boundary() {
        let error = gate_read_notice(Err(crate::findings::BatchReceiptPending.into())).unwrap_err();
        assert!(error.is::<crate::findings::BatchReceiptPending>());
    }

    #[test]
    fn stable_assessment_failure_is_still_visible_without_blocking_triage() {
        let message = gate_read_notice(Err(anyhow::anyhow!("invalid assessment")))
            .unwrap()
            .unwrap();
        assert!(
            message.contains("assessment unavailable") && message.contains("invalid assessment")
        );
        assert!(gate_read_notice(Ok(())).unwrap().is_none());
    }
}
