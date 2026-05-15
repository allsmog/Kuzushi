use crate::{PlanProposal, ShellApp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlanCardModel {
    pub(crate) goal: String,
    pub(crate) summary: String,
    pub(crate) active_count: usize,
    pub(crate) total_count: usize,
    pub(crate) changes: Vec<PlanChangeRow>,
    pub(crate) unsupported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PlanChangeRow {
    pub(crate) label: String,
    pub(crate) selected: bool,
    pub(crate) skipped: bool,
}

pub(crate) fn plan_card_model(app: &ShellApp) -> Option<PlanCardModel> {
    let plan = app.pending_plan.as_ref()?;
    Some(PlanCardModel::from_app(app, plan))
}

impl PlanCardModel {
    fn from_app(app: &ShellApp, plan: &PlanProposal) -> Self {
        let cursor = app.plan_cursor_clamped();
        let changes = plan
            .changes
            .iter()
            .enumerate()
            .map(|(index, change)| PlanChangeRow {
                label: change.label(),
                selected: index == cursor,
                skipped: app.plan_change_skipped(index),
            })
            .collect::<Vec<_>>();
        let active_count = changes.iter().filter(|change| !change.skipped).count();
        Self {
            goal: plan.goal.clone(),
            summary: plan.summary.clone(),
            active_count,
            total_count: changes.len(),
            changes,
            unsupported: plan.unsupported.clone(),
        }
    }
}

#[cfg(test)]
mod tests;
