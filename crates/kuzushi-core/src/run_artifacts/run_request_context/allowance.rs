use super::*;
use crate::allowance::AllowanceReferenceV1;

struct Selection {
    reference: AllowanceReferenceV1,
    accounting_run_id: String,
    origin: RecordedAllowanceOrigin,
}

pub(super) fn read_allowance(
    workspace: &WorkspaceTarget,
    run_id: &str,
    input: &Value,
) -> (
    Result<Option<RunAllowanceContext>, String>,
    RecordedAllowanceOrigin,
) {
    let read = select(workspace.root(), run_id, input).and_then(|selected| {
        selected
            .map(|value| read_selected(workspace, value))
            .transpose()
    });
    match read {
        Ok(Some((context, origin))) => (Ok(Some(context)), origin),
        Ok(None) => (Ok(None), RecordedAllowanceOrigin::NotRecorded),
        Err(error) => (
            Err(format!("{error:#}")),
            RecordedAllowanceOrigin::Unavailable,
        ),
    }
}

fn select(target: &Path, run_id: &str, input: &Value) -> Result<Option<Selection>> {
    let inherited = super::super::inherited_allowance::load(target, run_id)?;
    if let Some(value) = input.get("allowanceRef").filter(|value| !value.is_null()) {
        let reference: AllowanceReferenceV1 = serde_json::from_value(value.clone())?;
        reference.validate()?;
        if let Some(inherited) = inherited {
            anyhow::ensure!(
                inherited.reference == reference && inherited.accounting_run_id == run_id,
                "Recorded explicit and inherited accounting differ"
            );
        }
        return Ok(Some(Selection {
            reference,
            accounting_run_id: run_id.into(),
            origin: RecordedAllowanceOrigin::Explicit,
        }));
    }
    Ok(inherited.map(|value| Selection {
        reference: value.reference,
        accounting_run_id: value.accounting_run_id.clone(),
        origin: RecordedAllowanceOrigin::Inherited {
            accounting_run_id: value.accounting_run_id,
            work: value.work,
        },
    }))
}

fn read_selected(
    workspace: &WorkspaceTarget,
    selected: Selection,
) -> Result<(RunAllowanceContext, RecordedAllowanceOrigin)> {
    let context = crate::SpendLimiter::read_run_allowance_context(
        &workspace.findings_db_path(),
        &selected.accounting_run_id,
        &selected.reference,
    )?;
    Ok((context, selected.origin))
}
