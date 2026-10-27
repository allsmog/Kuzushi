use super::*;

impl ShellApp {
    pub(crate) fn reject_runtime_launch_while_budget_halted(
        &mut self,
        runtime_backed: bool,
        label: &str,
    ) -> bool {
        if !runtime_backed || !self.is_budget_halted() {
            return false;
        }
        self.log(
            "budget",
            format!(
                "{label} blocked by the session spending halt; inspect cost or report, or review the stop in setup"
            ),
        );
        self.set_error_notice(
            "cost",
            "runtime-backed launch blocked by the session spending halt. Review accounting and the stop in setup before starting model work.",
        );
        true
    }

    pub(super) fn maybe_trigger_budget_halt(&mut self) {
        if self.advisory().budget_halt.is_some() {
            return;
        }
        let Some(limit) = self
            .session()
            .session_budget_usd()
            .filter(|limit| *limit > 0.0)
        else {
            return;
        };
        match self.session().budget_spend_usd() {
            None => self.halt_for_unreliable_cost(limit),
            Some(spent) if spent >= limit => self.halt_at_cost_limit(limit, spent),
            Some(_) => {}
        }
    }

    fn halt_for_unreliable_cost(&mut self, limit: f64) {
        self.set_budget_halt(limit, self.session().session_cost_usd());
        self.log(
            "budget",
            "session spend is incomplete or invalid; budget is halted until accounting is resolved",
        );
    }

    fn halt_at_cost_limit(&mut self, limit: f64, spent: f64) {
        self.set_budget_halt(limit, spent);
        let estimated = if self.session().session_cost_report().is_estimated() {
            "~"
        } else {
            ""
        };
        self.log(
            "budget",
            format!(
                "session cost {estimated}${spent:.4} reached cap ${limit:.4}; c=review cap · a=abort"
            ),
        );
    }

    fn set_budget_halt(&mut self, limit_usd: f64, spent_usd: f64) {
        self.advisory_mut().budget_halt_acknowledged = false;
        self.advisory_mut().budget_halt = Some(BudgetHalt {
            limit_usd,
            spent_usd,
        });
        self.runtime_state.refresh_owned_study_allowance();
    }

    pub(crate) fn budget_halt_owns_input(&self) -> bool {
        self.is_budget_halted()
            && !self.advisory().budget_halt_acknowledged
            && !self.budget_editor_open()
            && self.shell_view() != ShellView::QuitConfirm
    }

    pub(crate) fn continue_past_budget(&mut self) {
        if self.session().budget_spend_usd().is_none() {
            self.set_error_notice(
                "cost",
                "cannot continue past the budget while runtime spend is incomplete or invalid",
            );
            return;
        }
        if !self.is_budget_halted() {
            return;
        }
        let origin = self.shell_view();
        let current = self.session().session_budget_usd();
        self.set_shell_view(ShellView::Setup);
        self.router
            .setup_mut()
            .begin_budget_revision(current, origin);
        self.log(
            "budget",
            "review and approve a new cap; work remains halted while editing",
        );
    }

    pub(crate) fn abort_for_budget(&mut self) {
        let requested = self.request_active_abort_with_reason(AbortReason::Budget);
        self.runtime_state.refresh_owned_study_allowance();
        let study = owned_study_abort_note(self.runtime_state.owned_study_allowance());
        self.log(
            "budget",
            format!(
                "session work abort requested: {requested}; session budget remains halted.{study}",
            ),
        );
    }
}

/// Discloses whether a still-running owned study is bounded at all.
fn owned_study_abort_note(allowance: Option<StudyAllowance>) -> &'static str {
    match allowance {
        None => "",
        Some(StudyAllowance::Set) => " The owned study has its own allowance; Ctrl+C requests Stop.",
        Some(StudyAllowance::NotSet) => {
            " The owned study has no allowance set and is not bounded by the session cap; Ctrl+C requests Stop."
        }
        Some(StudyAllowance::Unknown) => {
            " The owned study's allowance could not be determined; Ctrl+C requests Stop."
        }
    }
}

#[cfg(all(test, unix))]
mod held_study_tests;
