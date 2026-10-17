use crate::{Notice, NoticeSeverity, ShellApp, ThrottleAdvisory};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ThrottleBannerModel {
    pub(crate) source: String,
    pub(crate) message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NoticeBannerModel {
    pub(crate) source: String,
    pub(crate) message: String,
    pub(crate) severity: NoticeSeverity,
    pub(crate) dismiss_on_escape: bool,
}

pub(crate) fn notice_banner_model(app: &ShellApp) -> Option<NoticeBannerModel> {
    let advisory = app.advisory();
    let notice = advisory.notice.as_ref()?;
    let behind_confirmation = advisory.pending_confirm.is_some()
        && advisory
            .pending_confirm_since
            .is_some_and(|since| notice.since < since);
    if behind_confirmation {
        return None;
    }
    Some(NoticeBannerModel::from_notice(
        notice,
        app.notice_captures_escape(),
    ))
}

impl NoticeBannerModel {
    fn from_notice(notice: &Notice, dismiss_on_escape: bool) -> Self {
        Self {
            source: notice.source.clone(),
            message: notice.message.clone(),
            severity: notice.severity,
            dismiss_on_escape,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CostCapHaltModel {
    pub(crate) header: String,
    pub(crate) compact: &'static str,
    pub(crate) actions: &'static str,
}

pub(crate) fn throttle_banner_model(app: &ShellApp) -> Option<ThrottleBannerModel> {
    app.advisory()
        .throttle
        .as_ref()
        .map(ThrottleBannerModel::from_advisory)
}

pub(crate) fn cost_cap_halt_model(app: &ShellApp) -> Option<CostCapHaltModel> {
    if app.budget_editor_open() || app.shell_view() == crate::ShellView::QuitConfirm {
        return None;
    }
    let halt = app.advisory().budget_halt.as_ref()?;
    let spent = super::format_runtime_cost(
        app.session().session_cost_report(),
        app.session().cost_accounting_error(),
    );
    let (compact, actions) = budget_halt_actions(app.advisory().budget_halt_acknowledged);
    Some(CostCapHaltModel {
        header: format!("■ COST CAP HALT · {spent} / cap ${:.4}", halt.limit_usd),
        compact,
        actions,
    })
}

fn budget_halt_actions(acknowledged: bool) -> (&'static str, &'static str) {
    if acknowledged {
        (
            "SPENDING HALTED · cost / report",
            "Spending stays halted. Type cost or report to inspect.",
        )
    } else {
        (
            "COST CAP · Esc inspect · c cap · a abort",
            "Esc inspect/report   c review cap   a abort work",
        )
    }
}

impl ThrottleBannerModel {
    fn from_advisory(throttle: &ThrottleAdvisory) -> Self {
        Self {
            source: throttle.source.clone(),
            message: throttle.message.clone(),
        }
    }
}

#[cfg(test)]
mod tests;
