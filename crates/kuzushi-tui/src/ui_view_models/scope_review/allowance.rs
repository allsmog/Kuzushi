//! Recorded generation links scope reading to its current shared ledger.
use crate::app::ViewDataState;
use crate::ui_view_models::investigation_allowance::{
    allowance_state, investigation_allowance_model, InvestigationAllowanceModel,
};
use crate::ShellApp;
use kuzushi_core::allowance::AllowanceSnapshot;
use kuzushi_core::run_lifecycle::SafeText;
use std::sync::Arc;

pub(super) fn summary(app: &ShellApp) -> Vec<String> {
    let Some(model) = scope_model(app) else {
        return Vec::new();
    };
    let mut lines = vec![format!("Shared allowance: {}", model.calls), model.summary];
    if let Some(snapshot) = snapshot(app) {
        lines.insert(
            1,
            format!(
                "{} calls left · {} unsettled",
                snapshot.remaining_calls(),
                snapshot.unresolved_calls
            ),
        );
    }
    lines
}

pub(super) fn detail(app: &ShellApp) -> Vec<String> {
    if scope_model(app).is_none() {
        return Vec::new();
    }
    let Some(snapshot) = snapshot(app) else {
        return read_error(app);
    };
    vec![
        safe(format!(
            "Shared investigation: {} r{}",
            snapshot.investigation_id, snapshot.revision
        )),
        safe(format!("Allowance model: {}", snapshot.model)),
        format!(
            "{} total calls approved",
            snapshot.limits.max_provider_calls
        ),
        format!("{} other calls left", snapshot.non_review_remaining()),
        kuzushi_core::run_lifecycle::cost_label(snapshot.cost),
        "Totals cover all work sharing this investigation. Ledger at last read.".into(),
        "Dollar ceiling: not enforced. Later work needs separate approval.".into(),
    ]
}

fn scope_model(app: &ShellApp) -> Option<InvestigationAllowanceModel> {
    app.scope_generation_run_id()?;
    investigation_allowance_model(app)
}

fn snapshot(app: &ShellApp) -> Option<Arc<AllowanceSnapshot>> {
    match allowance_state(app)? {
        ViewDataState::Ready(Ok(Some(snapshot))) => Some(snapshot),
        _ => None,
    }
}

fn read_error(app: &ShellApp) -> Vec<String> {
    match allowance_state(app) {
        Some(ViewDataState::Ready(Err(error))) => {
            vec![safe(format!("Shared allowance read failed: {error}"))]
        }
        _ => Vec::new(),
    }
}

fn safe(text: String) -> String {
    SafeText::condensed_line(text).to_string()
}
