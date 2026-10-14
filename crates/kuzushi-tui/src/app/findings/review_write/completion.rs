use super::*;

impl ShellApp {
    pub(crate) fn apply_review_decision_write_result(&mut self) -> bool {
        let Some((apply, context, result)) = self.runtime_state.review_write.take_completed()
        else {
            return false;
        };
        if apply.target.as_deref() != self.target() {
            self.notice_review_write_for_other_target(&apply, result);
            return true;
        }
        let unchanged = context.origin == self.shell_view()
            && context.interaction == self.ui().operator_interaction_stamp();
        let effects = self.apply_review_write_result(apply, result, unchanged);
        EffectRuntime::execute(self, effects);
        true
    }

    pub(super) fn apply_review_write_result(
        &mut self,
        apply: ReviewDecisionApply,
        result: ReviewWriteResult,
        unchanged: bool,
    ) -> Vec<ShellEffect> {
        match result {
            Ok(id) => self.finish_saved_review_decision(&apply, id, unchanged),
            Err(ReviewWriteFailure::Workspace(error)) => {
                self.set_error_notice(
                    "review",
                    with_next_step(error.to_string(), "target <path> then findings"),
                );
                Vec::new()
            }
            Err(ReviewWriteFailure::Commit(error)) => {
                self.finish_failed_review_decision(&apply, error, unchanged)
            }
        }
    }

    fn finish_saved_review_decision(
        &mut self,
        apply: &ReviewDecisionApply,
        id: i64,
        unchanged: bool,
    ) -> Vec<ShellEffect> {
        if self.open_review_session_id(&apply.finding) == apply.review_session_id {
            self.close_review_session(&apply.finding);
        }
        if unchanged {
            self.clear_review_decision_conflict();
        }
        let label = review_decision_finding_label(apply.alias.as_deref(), &apply.finding);
        self.log_saved_review_decision(id, apply.decision.verdict, &label);
        if unchanged {
            return self.review_decision_refresh_effects(&apply.finding);
        }
        self.passive_review_write_refresh(&apply.finding)
    }

    fn finish_failed_review_decision(
        &mut self,
        apply: &ReviewDecisionApply,
        error: anyhow::Error,
        unchanged: bool,
    ) -> Vec<ShellEffect> {
        if !unchanged {
            let label = review_decision_finding_label(apply.alias.as_deref(), &apply.finding);
            self.set_error_notice("review", format!("Decision save for {label} failed: {error}. Inspect the ledger and command history before retrying."));
            return self.passive_review_write_refresh(&apply.finding);
        }
        if self.log_review_decision_write_error(&apply.finding, error) {
            return self.review_decision_conflict_refresh_effects();
        }
        Vec::new()
    }

    fn passive_review_write_refresh(&mut self, finding: &Finding) -> Vec<ShellEffect> {
        let selected = crate::ui_view_models::current_finding_for_detail(self);
        if selected.is_some_and(|(_, current)| current.id == finding.id)
            && self.active_findings_filter().is_some()
        {
            self.reset_findings_page_request();
        }
        self.review_decision_conflict_refresh_effects()
    }

    fn notice_review_write_for_other_target(
        &mut self,
        apply: &ReviewDecisionApply,
        result: ReviewWriteResult,
    ) {
        let label = review_decision_finding_label(apply.alias.as_deref(), &apply.finding);
        let target = apply
            .target
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "no target".into());
        match result {
            Ok(id) => self.set_success_notice("review", format!("Decision #{id} saved for {label} in {target}")),
            Err(error) => self.set_error_notice("review", format!("Decision save for {label} in {target} failed: {}. Inspect that ledger before retrying.", review_write_error_message(error))),
        }
    }
}

fn review_write_error_message(error: ReviewWriteFailure) -> String {
    match error {
        ReviewWriteFailure::Workspace(error) | ReviewWriteFailure::Commit(error) => {
            error.to_string()
        }
    }
}
