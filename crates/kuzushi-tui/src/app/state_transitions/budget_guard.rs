use super::*;

impl ShellApp {
    pub(super) fn maybe_trigger_budget_halt(&mut self) {
        if self.advisory().budget_halt.is_some() {
            return;
        }
        if let Some(limit) = self.session().session_budget_usd() {
            if limit > 0.0 && self.session().session_cost_usd() >= limit {
                self.advisory_mut().budget_halt = Some(BudgetHalt {
                    limit_usd: limit,
                    spent_usd: self.session().session_cost_usd(),
                });
                self.log(
                    "budget",
                    format!(
                        "session cost ${:.4} reached cap ${:.4}; c=continue · a=abort",
                        self.session().session_cost_usd(),
                        limit
                    ),
                );
            }
        }
    }

    pub(crate) fn continue_past_budget(&mut self) {
        if let Some(halt) = self.advisory_mut().budget_halt.take() {
            self.session_mut()
                .set_session_budget_usd(Some(halt.spent_usd * 2.0));
            self.log(
                "budget",
                format!(
                    "continuing past ${:.4}; new soft cap ${:.4}",
                    halt.spent_usd,
                    self.session().session_cost_usd() * 2.0
                ),
            );
        }
    }

    pub(crate) fn abort_for_budget(&mut self) {
        self.advisory_mut().budget_halt = None;
        let requested = self.request_active_abort();
        self.log(
            "budget",
            format!(
                "aborting due to cost cap (abort requested: {requested}). Next: /cost or /scan",
            ),
        );
    }
}
