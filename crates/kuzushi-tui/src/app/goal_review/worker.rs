use super::*;
use serde_json::json;

impl ShellApp {
    pub(super) fn read_goal_review(&mut self, newer_brief: bool) {
        if self.runtime_state.goal_review_worker.is_some() {
            return;
        }
        let state = &self.runtime_state.goal_review;
        let mut input = json!({"briefId":state.brief_id,"offset":state.offset,"filter":GOAL_FILTERS[state.filter]});
        let brief = state
            .page
            .as_ref()
            .and_then(|page| page.as_ref().ok())
            .and_then(|page| page.brief.as_ref());
        if let Some(brief) = brief.filter(|_| !newer_brief) {
            input["briefRef"] = json!(brief.reference);
        }
        self.spawn_goal_action(false, input);
    }

    pub(super) fn read_goal_history(&mut self) {
        if self.runtime_state.goal_review_worker.is_some() {
            return;
        }
        let state = &mut self.runtime_state.goal_review;
        let Some(id) = state.selected().map(|row| row.basis.finding_id) else {
            return;
        };
        state.history_id = Some(id);
        state.history = None;
        state.show_history = true;
        state.scroll = 0;
        self.spawn_goal_action(false, json!({"findingId":id}));
    }

    pub(super) fn save_goal_review(&mut self) {
        if self.runtime_state.goal_review_worker.is_some() {
            return;
        }
        let Some(form) = &self.runtime_state.goal_review.form else {
            return;
        };
        let input = json!({"briefRef":form.brief.reference,"basis":form.row.basis,
            "expectedRevision":form.row.assessment.as_ref().map_or(0,|record| record.revision),
            "relevance":form.relevance,"reason":form.reason.text()});
        self.spawn_goal_action(true, input);
    }

    fn spawn_goal_action(&mut self, writing: bool, input: serde_json::Value) {
        let Some(target) = self.target_owned() else {
            return;
        };
        if self.runtime_state.goal_review.target.as_ref() != Some(&target) {
            return;
        }
        let worker_target = target.clone();
        let config = self.config().clone();
        let history_id = input["findingId"].as_i64();
        let handle = std::thread::spawn(move || {
            let workspace = WorkspaceTarget::new(worker_target).map_err(|e| e.to_string())?;
            kuzushi_core::workspace::execute_goal_review(
                &workspace,
                &config,
                if writing {
                    "findings:goal-assess"
                } else {
                    "findings:goals"
                },
                input,
            )
            .map_err(|e| format!("{e:#}"))
        });
        self.runtime_state.goal_review_worker = Some(GoalReviewWorker {
            target,
            writing,
            history_id,
            handle,
        });
        self.runtime_state.goal_review.notice = Some(
            if writing {
                "Saving reviewed relevance. Waiting for its receipt."
            } else {
                "Reading recorded goal data..."
            }
            .into(),
        );
    }

    pub(crate) fn poll_goal_review(&mut self) -> bool {
        let Some(worker) = &self.runtime_state.goal_review_worker else {
            return false;
        };
        if !worker.handle.is_finished() {
            return false;
        }
        let worker = self.runtime_state.goal_review_worker.take().unwrap();
        let result = worker
            .handle
            .join()
            .unwrap_or_else(|_| Err("Goal review worker stopped unexpectedly".into()));
        if self.target() != Some(worker.target.as_path()) {
            self.set_info_notice(
                "goals",
                "Goal review finished for the earlier target. Its receipt can be inspected there.",
            );
            return true;
        }
        if worker.history_id.is_some() {
            self.runtime_state.goal_review.history = Some(result.and_then(|value| {
                serde_json::from_value(value["data"]["history"].clone())
                    .map_err(|error| error.to_string())
            }));
            self.runtime_state.goal_review.notice = None;
        } else {
            self.finish_goal_action(worker.writing, result);
        }
        true
    }

    fn finish_goal_action(&mut self, writing: bool, result: Result<serde_json::Value, String>) {
        if !writing {
            let state = &mut self.runtime_state.goal_review;
            state.page = Some(result.and_then(|value| {
                serde_json::from_value(value["data"].clone()).map_err(|e| e.to_string())
            }));
            state.notice = state.pending_receipt.take().or_else(|| read_receipt(state));
            return;
        }
        match result.and_then(|output| self.accept_saved_goal(output)) {
            Ok(()) => self.read_goal_review(false),
            Err(error) => self.runtime_state.goal_review.notice = Some(format!("Action not confirmed. {error}\nEsc edits the retained reason. Esc again returns to the list; r there refreshes before reassessment.")),
        }
    }

    fn accept_saved_goal(&mut self, output: serde_json::Value) -> Result<(), String> {
        let record: kuzushi_core::findings::FindingGoalAssessment =
            serde_json::from_value(output["data"].clone())
                .map_err(|error| format!("Saved receipt is unreadable: {error}"))?;
        let state = &mut self.runtime_state.goal_review;
        state.pinned = Some(record.basis.finding_id);
        state.pending_receipt = Some(format!(
            "Saved assessment v{} · {} v{}",
            record.revision, record.brief_ref.brief_id, record.brief_ref.revision
        ));
        state.form = None;
        state.editing = false;
        state.scroll = 0;
        Ok(())
    }
}

fn read_receipt(state: &GoalReviewState) -> Option<String> {
    let page = state.page.as_ref()?.as_ref().ok()?;
    let brief = page.brief.as_ref()?;
    Some(format!(
        "Showing saved brief {} v{} · ledger {}",
        brief.reference.brief_id, brief.reference.revision, page.watermark
    ))
}
