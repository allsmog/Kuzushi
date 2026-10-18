use crate::{app::ViewDataState, ShellApp};
use kuzushi_core::allowance::AllowanceSnapshot;
use kuzushi_core::run_lifecycle::SafeText;

pub(crate) struct InvestigationAllowanceModel {
    pub(crate) calls: String,
    pub(crate) rows: Vec<String>,
}

pub(crate) fn investigation_allowance_model(app: &ShellApp) -> Option<InvestigationAllowanceModel> {
    let key = app.investigation_allowance_key()?;
    let target = app.target()?;
    let state = app
        .workbench_cache()
        .borrow()
        .cached_investigation_allowance(target, &key);
    match state {
        ViewDataState::Ready(Ok(Some(snapshot))) => Some(present(&snapshot)),
        ViewDataState::Ready(Ok(None)) => None,
        ViewDataState::Ready(Err(error)) => Some(InvestigationAllowanceModel {
            calls: "calls unavailable".into(),
            rows: vec![
                "Ledger unavailable".into(),
                safe(error),
                "Retrying this read".into(),
                "report · full limits".into(),
            ],
        }),
        _ => Some(InvestigationAllowanceModel {
            calls: "calls loading".into(),
            rows: vec!["Shared allowance loading".into()],
        }),
    }
}

fn present(snapshot: &AllowanceSnapshot) -> InvestigationAllowanceModel {
    let calls = calls_label(snapshot);
    InvestigationAllowanceModel {
        calls: calls.clone(),
        rows: vec![
            calls,
            format!("{} Review protected", snapshot.protected_review_remaining()),
            format!("{} other calls left", snapshot.non_review_remaining()),
            format!("{} unsettled", snapshot.unresolved_calls),
            kuzushi_core::run_lifecycle::cost_label(snapshot.cost),
            safe(format!(
                "{} r{}",
                snapshot.investigation_id, snapshot.revision
            )),
            "Ledger at last read".into(),
            "report · full limits".into(),
        ],
    }
}

pub(super) fn calls_label(snapshot: &AllowanceSnapshot) -> String {
    format!(
        "calls {}/{}",
        snapshot.committed_calls, snapshot.limits.max_provider_calls
    )
}

fn safe(value: String) -> String {
    SafeText::condensed_line(value).to_string()
}

#[cfg(test)]
mod tests;
