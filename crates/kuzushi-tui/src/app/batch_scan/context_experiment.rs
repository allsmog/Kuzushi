use super::*;
use crate::app::state_transitions::InputUpdate;
use crate::app::ShellApp;
use serde_json::Value;
const BASELINE_ALLOWANCE_LOADING: &str =
    "Reading the baseline allowance; wait before preparing work";
#[cfg(test)]
mod tests;

impl ShellApp {
    pub(super) fn toggle_context_experiment(&mut self) -> InputUpdate {
        if self.scope_context_action_unavailable(crossterm::event::KeyCode::Char('+')) {
            return InputUpdate::handled();
        }
        if self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .is_some_and(|config| !config.study.matrix.cases.is_empty())
        {
            self.set_batch_config_notice("This draft has fresh context cases. Clear Context cases to use one historical comparison; spending stays recorded.");
            return InputUpdate::handled();
        }
        if self.has_running_work() {
            self.set_batch_config_notice(
                "Wait for active work; the context comparison draft is kept.",
            );
            return InputUpdate::handled();
        }
        if self.open_context_result_choices() {
            return InputUpdate::handled();
        }
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            toggle_baseline(config);
        }
        self.retry_context_baseline_allowance()
            .unwrap_or_else(InputUpdate::handled)
    }

    pub(super) fn retry_context_baseline_allowance(&mut self) -> Option<InputUpdate> {
        let config = self.router.campaign_mut().batch_scan_config.as_mut()?;
        if !config.study.baseline_allowance_pending {
            return None;
        }
        config.study.accounting_error = Some(BASELINE_ALLOWANCE_LOADING.into());
        let input = serde_json::json!({"investigationId":config.study.investigation_id});
        Some(InputUpdate::handled_with_effects(self.reduce_run_tool(
            Some("campaign:allowance".into()),
            Some(input.to_string()),
        )))
    }

    pub(crate) fn context_baseline_allowance_failed(&mut self, tool: &str, message: &str) {
        if tool != "campaign:allowance" {
            return;
        }
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        if !config.study.baseline_allowance_pending {
            return;
        }
        config.study.accounting_error = Some(format!("Baseline allowance unavailable: {message}"));
        config.notice = Some("Baseline allowance could not be read. r retries the read. Your draft and spending account are kept; no work starts.".into());
    }
}

impl ShellApp {
    fn open_context_result_choices(&mut self) -> bool {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return false;
        };
        if config.study.context_experiment.is_none() {
            return false;
        }
        config.context_result_cursor = Some(0);
        config.notice = None;
        true
    }

    pub(super) fn handle_context_result_key(
        &mut self,
        code: crossterm::event::KeyCode,
    ) -> Option<InputUpdate> {
        use crossterm::event::KeyCode;
        let cursor = self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()?
            .context_result_cursor?;
        if code == KeyCode::Char('r') {
            self.refresh_campaign_deck();
            return Some(InputUpdate::handled());
        }
        if code == KeyCode::Enter {
            return Some(self.compare_selected_context_result(cursor));
        }
        let count = crate::ui_view_models::study_config::context_result_jobs(self).len();
        if let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() {
            update_result_cursor(config, code, count);
        }
        Some(InputUpdate::handled())
    }

    fn compare_selected_context_result(&mut self, cursor: usize) -> InputUpdate {
        let jobs = crate::ui_view_models::study_config::context_result_jobs(self);
        let Some(run) = jobs.get(cursor).and_then(|job| job.run_id.clone()) else {
            self.set_batch_config_notice("This pass has no recorded run yet. Refresh the campaign; comparison starts no work.");
            return InputUpdate::handled();
        };
        let baseline = self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .context_baseline_run_id
            .clone()
            .unwrap();
        self.open_run_diff_view(baseline, run);
        self.set_input_mode(crate::app::InputMode::Navigate);
        InputUpdate::handled()
    }
}

fn update_result_cursor(
    config: &mut BatchScanConfig,
    code: crossterm::event::KeyCode,
    count: usize,
) {
    use crossterm::event::KeyCode;
    match code {
        KeyCode::Esc | KeyCode::Char('q') => config.context_result_cursor = None,
        KeyCode::Up => {
            config.context_result_cursor =
                Some(config.context_result_cursor.unwrap().saturating_sub(1))
        }
        KeyCode::Down => {
            config.context_result_cursor =
                Some((config.context_result_cursor.unwrap() + 1).min(count.saturating_sub(1)))
        }
        KeyCode::Char('x') => clear_result_comparison(config),
        _ => {}
    }
}

fn clear_result_comparison(config: &mut BatchScanConfig) {
    config.context_result_cursor = None;
    config.study.context_baseline_run_id = None;
    config.study.invalidate_plan();
    config.notice = Some(
        "Comparison cleared. Spending remains recorded; prepare and approve a new plan.".into(),
    );
}

fn toggle_baseline(config: &mut BatchScanConfig) {
    if config.study.context_baseline_run_id.take().is_some() {
        config.study.invalidate_plan();
        config.notice = Some("Context comparison cleared. This draft repeats one context; spending is retained and a new plan needs approval.".into());
        return;
    }
    let Some(run) = config.prior_run_id.clone() else {
        config.notice = Some("Select a completed run in Usage evidence first, then enable Context comparison. No work starts.".into());
        return;
    };
    let Some(investigation) = baseline_investigation(config, &run) else {
        return;
    };
    if config
        .study
        .allowance
        .as_ref()
        .is_some_and(|allowance| allowance.investigation_id != investigation)
    {
        config.notice=Some("This baseline belongs to another investigation. Keep its spending history separate; open a study from that baseline instead.".into());
        return;
    }
    config.study.invalidate_plan();
    config.study.context_baseline_run_id = Some(run);
    config.study.investigation_id = investigation;
    config.study.baseline_allowance_pending = true;
    config.study.accounting_error = Some(BASELINE_ALLOWANCE_LOADING.into());
    config.notice = Some("Context comparison selected. Choose a different exact context in Source and context. Other conditions must match the baseline; planning and approval check them. No work starts.".into());
}

fn baseline_investigation(config: &mut BatchScanConfig, run: &str) -> Option<String> {
    let prior = config.prior_runs.iter().find(|prior| prior.run_id == run);
    let Some(crate::app::ViewDataState::Ready(Ok(evidence))) = prior.map(|prior| &prior.evidence)
    else {
        config.notice=Some("Baseline evidence is loading or unavailable. r refreshes it before context comparison.".into());
        return None;
    };
    let Some(usage) = &evidence.provider_usage else {
        config.notice=Some("Baseline has no durable investigation accounting. Inspect historical results; choose an admitted run for a new experiment.".into());
        return None;
    };
    Some(usage.investigation_id.clone())
}

pub(super) fn read_context_experiment(
    data: &Value,
) -> anyhow::Result<Option<kuzushi_core::capabilities::campaign::ContextExperimentReceipt>> {
    Ok(
        data.get("contextExperiment")
            .filter(|value| !value.is_null())
            .map(|value| {
                serde_json::from_value::<
                    kuzushi_core::capabilities::campaign::ContextExperimentReceipt,
                >(value.clone())
            })
            .transpose()?,
    )
}
