//! Immutable accounting context offered to a nested dispatch, not work approval.
use super::*;
use crate::allowance::{AllowanceReferenceV1, AllowanceWork, InvestigationWork};

const LEAF: &str = "inherited-allowance.json";
const MAX_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct InheritedAllowanceV1 {
    schema_version: u32,
    run_id: String,
    pub reference: AllowanceReferenceV1,
    pub accounting_run_id: String,
    pub work: InvestigationWork,
}

pub(crate) fn retain_inherited_allowance(
    target: &Path,
    run_id: &str,
    work: &AllowanceWork,
) -> Result<()> {
    let value = InheritedAllowanceV1 {
        schema_version: 1,
        run_id: run_id.into(),
        reference: AllowanceReferenceV1 {
            schema_version: 1,
            investigation_id: work.investigation_id.clone(),
            revision: work.revision,
            work_id: work.work_id.clone(),
        },
        accounting_run_id: work.run_id.clone(),
        work: work.work,
    };
    validate(&value, run_id)?;
    let _guard = super::run_ledger::acquire_run_terminal_lock(target, run_id)?;
    if let Some(existing) = load(target, run_id)? {
        anyhow::ensure!(
            existing == value,
            "Inherited accounting differs from this run's retained context"
        );
        return Ok(());
    }
    write_run_artifact_json_bounded(
        target,
        run_id,
        LEAF,
        "Inherited accounting context",
        &serde_json::to_value(value)?,
        MAX_BYTES,
    )?;
    Ok(())
}

pub(super) fn load(target: &Path, run_id: &str) -> Result<Option<InheritedAllowanceV1>> {
    let path = checked_run_artifact_path(target, run_id, LEAF)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::ensure!(
                !is_recorded(target, run_id)?,
                "Inherited accounting file is missing after retention"
            );
            return Ok(None);
        }
        other => {
            other?;
        }
    }
    let (_, text) = read_run_artifact_text_bounded(target, run_id, LEAF, MAX_BYTES as u64)?;
    authenticate(target, run_id, &text)?;
    let value: InheritedAllowanceV1 = serde_json::from_str(&text)?;
    validate(&value, run_id)?;
    Ok(Some(value))
}

fn validate(value: &InheritedAllowanceV1, run_id: &str) -> Result<()> {
    anyhow::ensure!(
        value.schema_version == 1 && value.run_id == run_id,
        "Inherited accounting identity does not match this run"
    );
    RunId::parse(&value.accounting_run_id)?;
    value.reference.validate()
}

fn authenticate(target: &Path, run_id: &str, text: &str) -> Result<()> {
    let reference = load_run_artifact_object_reference(target, run_id, LEAF)?;
    anyhow::ensure!(
        reference.size_bytes == text.len() as u64
            && reference.hash == crate::content_store::object_hash(reference.kind, text.as_bytes()),
        "Inherited accounting changed since retention"
    );
    Ok(())
}

fn is_recorded(target: &Path, run_id: &str) -> Result<bool> {
    Ok(load_run_artifacts(target, run_id)?
        .iter()
        .any(|artifact| artifact.path == LEAF))
}

#[cfg(test)]
mod tests;
