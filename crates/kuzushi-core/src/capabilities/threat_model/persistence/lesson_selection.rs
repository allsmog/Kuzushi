use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

pub(crate) fn validate_reviewed_lessons(root: &Path, document: &Value) -> Result<()> {
    let Some(value) = document.get("reviewedLessons") else {
        return Ok(());
    };
    let records: Vec<crate::findings::FindingLesson> =
        serde_json::from_value(value.clone()).context("Reviewed lesson context is malformed")?;
    anyhow::ensure!(
        records.len() <= 8,
        "Context exceeds the reviewed lesson limit"
    );
    if records.is_empty() {
        return Ok(());
    }
    let workspace = crate::WorkspaceTarget::new(root)?;
    anyhow::ensure!(
        workspace.findings_db_path().exists(),
        "Lesson origin ledger is missing"
    );
    let store = crate::findings::FindingStore::open_read_only(workspace.findings_db_path())?;
    validate_records(root, &store, &records)
}

fn validate_records(
    root: &Path,
    store: &crate::findings::FindingStore,
    records: &[crate::findings::FindingLesson],
) -> Result<()> {
    let target = root.canonicalize()?.to_string_lossy().into_owned();
    let mut ids = std::collections::BTreeSet::new();
    for record in records {
        anyhow::ensure!(ids.insert(&record.id), "Context repeats a reviewed lesson");
        anyhow::ensure!(
            record.origin.target == target,
            "Lesson context belongs to another workspace"
        );
        let authentic = store.accepted_finding_lesson(&record.reference()?)?;
        anyhow::ensure!(
            authentic == *record,
            "Reviewed lesson snapshot does not match its ledger"
        );
    }
    Ok(())
}
