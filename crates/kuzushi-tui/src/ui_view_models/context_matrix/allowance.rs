//! Compact current accounting stays outside the independently paged evidence.
use crate::app::{ShellApp, ViewDataState};
use kuzushi_core::{allowance::AllowanceSnapshot, runtime::RuntimeCostReport};

pub(crate) fn lines(app: &ShellApp, width: usize) -> Vec<String> {
    use super::super::investigation_allowance::allowance_state;
    match allowance_state(app) {
        Some(ViewDataState::Ready(Ok(Some(snapshot)))) => present(&snapshot, width),
        Some(ViewDataState::Ready(Ok(None))) => {
            vec!["Allowance not approved".into(), "Cost unknown".into()]
        }
        Some(ViewDataState::Ready(Err(_))) => vec![
            "Allowance unavailable".into(),
            "Retrying read · cost unknown".into(),
        ],
        Some(_) => vec!["Allowance loading".into(), "Reading saved ledger".into()],
        None => vec![
            "Plan not prepared".into(),
            "Cost unknown · no new work approved".into(),
        ],
    }
}

fn present(snapshot: &AllowanceSnapshot, width: usize) -> Vec<String> {
    let calls = format!(
        "Calls {}/{}",
        snapshot.committed_calls, snapshot.limits.max_provider_calls,
    );
    let review = format!("Review {} protected", snapshot.protected_review_remaining());
    if width < 72 {
        return vec![
            calls,
            review,
            format!(
                "{} unsettled · {}",
                snapshot.unresolved_calls,
                compact_cost(snapshot.cost)
            ),
        ];
    }
    vec![
        format!(
            "{calls} · {review} · {} other calls left",
            snapshot.non_review_remaining()
        ),
        format!(
            "Ledger at last read · {} unsettled · {}",
            snapshot.unresolved_calls,
            kuzushi_core::run_lifecycle::cost_label(snapshot.cost)
        ),
    ]
}

fn compact_cost(cost: RuntimeCostReport) -> String {
    if cost.is_unavailable() {
        return "cost unknown".into();
    }
    if cost.is_complete() {
        return kuzushi_core::run_lifecycle::cost_label(cost);
    }
    if cost.is_estimated() {
        return "cost estimated".into();
    }
    "cost incomplete".into()
}

#[cfg(test)]
mod tests;
