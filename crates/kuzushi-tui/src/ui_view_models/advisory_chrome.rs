use crate::{BudgetHalt, Notice, NoticeSeverity, ShellApp, ThrottleAdvisory};

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
}

pub(crate) fn notice_banner_model(app: &ShellApp) -> Option<NoticeBannerModel> {
    app.advisory.notice.as_ref().map(NoticeBannerModel::from_notice)
}

impl NoticeBannerModel {
    fn from_notice(notice: &Notice) -> Self {
        Self {
            source: notice.source.clone(),
            message: notice.message.clone(),
            severity: notice.severity,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CostCapHaltModel {
    pub(crate) header: String,
}

pub(crate) fn throttle_banner_model(app: &ShellApp) -> Option<ThrottleBannerModel> {
    app.advisory
        .throttle
        .as_ref()
        .map(ThrottleBannerModel::from_advisory)
}

pub(crate) fn cost_cap_halt_model(app: &ShellApp) -> Option<CostCapHaltModel> {
    app.advisory
        .budget_halt
        .as_ref()
        .map(CostCapHaltModel::from_halt)
}

impl ThrottleBannerModel {
    fn from_advisory(throttle: &ThrottleAdvisory) -> Self {
        Self {
            source: throttle.source.clone(),
            message: throttle.message.clone(),
        }
    }
}

impl CostCapHaltModel {
    fn from_halt(halt: &BudgetHalt) -> Self {
        Self {
            header: format!(
                "■ COST CAP HALT · spent ${:.4} / cap ${:.4}",
                halt.spent_usd, halt.limit_usd
            ),
        }
    }
}

#[cfg(test)]
mod tests;
