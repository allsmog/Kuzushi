use crate::app::StudyAllowance;
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
    let owned_study = app.runtime_state.owned_study_allowance();
    let (compact, actions) =
        budget_halt_actions(app.advisory().budget_halt_acknowledged, owned_study);
    let label = budget_halt_label(owned_study.is_some());
    Some(CostCapHaltModel {
        header: format!("■ {label} · {spent} / cap ${:.4}", halt.limit_usd),
        compact,
        actions,
    })
}

fn budget_halt_label(owned_study: bool) -> &'static str {
    if owned_study {
        "SESSION COST CAP HALT"
    } else {
        "COST CAP HALT"
    }
}

fn budget_halt_actions(
    acknowledged: bool,
    owned_study: Option<StudyAllowance>,
) -> (&'static str, &'static str) {
    if let Some(allowance) = owned_study {
        return owned_study_budget_actions(acknowledged, allowance);
    }
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

fn owned_study_budget_actions(
    acknowledged: bool,
    allowance: StudyAllowance,
) -> (&'static str, &'static str) {
    if acknowledged {
        (
            "SESSION HALT · cost / report",
            acknowledged_study_actions(allowance),
        )
    } else {
        (
            "SESSION CAP · a local · Ctrl+C study",
            halted_study_actions(allowance),
        )
    }
}

fn acknowledged_study_actions(allowance: StudyAllowance) -> &'static str {
    match allowance {
        StudyAllowance::Set => {
            "Type cost or report. Session spending is halted; the study uses its own allowance."
        }
        StudyAllowance::NotSet => {
            "Type cost or report. Session spending is halted; the study has no allowance set and is not bounded by the session cap."
        }
        StudyAllowance::Unknown => {
            "Type cost or report. Session spending is halted; the study's allowance could not be determined."
        }
    }
}

fn halted_study_actions(allowance: StudyAllowance) -> &'static str {
    match allowance {
        StudyAllowance::Set => {
            "Study allowance is separate. Esc inspect · c cap · a stop session work · Ctrl+C study"
        }
        StudyAllowance::NotSet => {
            "Study has no allowance set and is not bounded by the session cap. Esc inspect · c cap · a stop session work · Ctrl+C study"
        }
        StudyAllowance::Unknown => {
            "Study allowance could not be determined. Esc inspect · c cap · a stop session work · Ctrl+C study"
        }
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
