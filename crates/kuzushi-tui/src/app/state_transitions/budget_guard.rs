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
                "{label} blocked by the session cost halt; c raises the cap, a aborts active work"
            ),
        );
        self.set_error_notice(
            "cost",
            "runtime-backed launch blocked until the budget cap is explicitly raised or reset",
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
        if !self.session().cost_accounting_is_complete() {
            self.halt_for_unreliable_cost(limit);
        } else if self.session().session_cost_usd() >= limit {
            self.halt_at_cost_limit(limit);
        }
    }

    fn halt_for_unreliable_cost(&mut self, limit: f64) {
        self.set_budget_halt(limit);
        self.log(
            "budget",
            "session spend is incomplete or invalid; budget is halted until accounting is resolved",
        );
    }

    fn halt_at_cost_limit(&mut self, limit: f64) {
        self.set_budget_halt(limit);
        self.log(
            "budget",
            format!(
                "session cost ${:.4} reached cap ${limit:.4}; c=continue · a=abort",
                self.session().session_cost_usd()
            ),
        );
    }

    fn set_budget_halt(&mut self, limit_usd: f64) {
        let spent_usd = self.session().session_cost_usd();
        self.advisory_mut().budget_halt = Some(BudgetHalt {
            limit_usd,
            spent_usd,
        });
    }

    pub(crate) fn continue_past_budget(&mut self) {
        if !self.session().cost_accounting_is_complete() {
            self.set_error_notice(
                "cost",
                "cannot continue past the budget while runtime spend is incomplete or invalid",
            );
            return;
        }
        let Some(halt) = self.advisory().budget_halt.clone() else {
            return;
        };
        let doubled = match doubled_budget_cap(halt.limit_usd, halt.spent_usd) {
            Ok(cost) => cost,
            Err(error) => {
                self.report_cost_accounting_error(error);
                return;
            }
        };
        self.session_mut().set_session_budget_usd(Some(doubled));
        self.advisory_mut().budget_halt = None;
        self.log(
            "budget",
            format!(
                "continuing past ${:.4}; new soft cap ${doubled:.4}",
                halt.spent_usd
            ),
        );
    }

    pub(crate) fn abort_for_budget(&mut self) {
        let requested = self.request_active_abort_with_reason(AbortReason::Budget);
        self.log(
            "budget",
            format!(
                "aborting due to cost cap (abort requested: {requested}); budget halt remains armed",
            ),
        );
    }
}

fn doubled_budget_cap(limit_usd: f64, spent_usd: f64) -> anyhow::Result<f64> {
    let base = kuzushi_core::runtime::RuntimeCost::from_usd(
        limit_usd.max(spent_usd),
        "budget continuation spend",
    )?;
    base.checked_add(base, "budget continuation cap")
        .map(kuzushi_core::runtime::RuntimeCost::usd)
}
