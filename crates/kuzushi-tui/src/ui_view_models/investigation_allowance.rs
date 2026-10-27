use crate::{app::ViewDataState, ShellApp};
use kuzushi_core::allowance::AllowanceSnapshot;
use kuzushi_core::run_lifecycle::SafeText;

pub(crate) struct InvestigationAllowanceModel {
    pub(crate) calls: String,
    pub(crate) rows: Vec<String>,
    pub(crate) summary: String,
}

pub(crate) fn investigation_allowance_model(app: &ShellApp) -> Option<InvestigationAllowanceModel> {
    let study = app.study_allowance_selection();
    let Some(state) = allowance_state(app) else {
        return study.map(|study| unavailable_plan_model(app, study.campaign_id));
    };
    let mut model = present_state(state, study.is_some())?;
    if let Some(id) = study {
        model
            .rows
            .insert(0, safe(format!("Study: {}", id.campaign_id)));
    }
    Some(model)
}

fn unavailable_plan_model(app: &ShellApp, id: &str) -> InvestigationAllowanceModel {
    let loading = app.campaign_history_loading();
    InvestigationAllowanceModel {
        calls: if loading {
            "calls loading"
        } else {
            "calls unavailable"
        }
        .into(),
        rows: vec![
            safe(format!("Study: {id}")),
            "Selected plan identity is not available. r refreshes history.".into(),
        ],
        summary: "Spending unknown · read plan first".into(),
    }
}

fn present_state(
    state: ViewDataState<crate::InvestigationAllowanceRead>,
    study_bound: bool,
) -> Option<InvestigationAllowanceModel> {
    match state {
        ViewDataState::Ready(Ok(Some(snapshot))) => Some(present(&snapshot)),
        ViewDataState::Ready(Ok(None)) => unapproved_study_model(study_bound),
        ViewDataState::Ready(Err(error)) => Some(InvestigationAllowanceModel {
            calls: "calls unavailable".into(),
            summary: "Allowance unavailable · cost unknown".into(),
            rows: vec![
                "Ledger unavailable".into(),
                safe(error),
                "Retrying this read".into(),
                "report · full limits".into(),
            ],
        }),
        _ => Some(InvestigationAllowanceModel {
            calls: "calls loading".into(),
            summary: "Reading shared allowance".into(),
            rows: vec!["Shared allowance loading".into()],
        }),
    }
}

fn unapproved_study_model(study_bound: bool) -> Option<InvestigationAllowanceModel> {
    study_bound.then(|| InvestigationAllowanceModel {
        calls: "calls unapproved".into(),
        summary: "No allowance recorded · cost unknown".into(),
        rows: vec!["No allowance recorded".into(), "Cost unknown".into()],
    })
}

pub(super) fn allowance_state(
    app: &ShellApp,
) -> Option<ViewDataState<crate::InvestigationAllowanceRead>> {
    let key = app.investigation_allowance_key()?;
    let target = app.target()?;
    let state = app
        .workbench_cache()
        .borrow()
        .cached_investigation_allowance(target, &key);
    Some(state)
}

fn present(snapshot: &AllowanceSnapshot) -> InvestigationAllowanceModel {
    let calls = calls_label(snapshot);
    InvestigationAllowanceModel {
        calls: calls.clone(),
        summary: protected_cost_summary(snapshot),
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

fn protected_cost_summary(snapshot: &AllowanceSnapshot) -> String {
    let review = format!("{} Review protected", snapshot.protected_review_remaining());
    let complete = format!(
        "{review} · {}",
        kuzushi_core::run_lifecycle::cost_label(snapshot.cost)
    );
    if unicode_width::UnicodeWidthStr::width(complete.as_str()) <= 40 {
        return complete;
    }
    format!("{review} · {}", cost_state(snapshot.cost))
}

fn cost_state(cost: kuzushi_core::runtime::RuntimeCostReport) -> &'static str {
    if cost.is_unavailable() {
        return "cost unknown";
    }
    if cost.is_complete() {
        return "exact cost";
    }
    if cost.is_estimated() {
        return "estimated";
    }
    "partial cost"
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
