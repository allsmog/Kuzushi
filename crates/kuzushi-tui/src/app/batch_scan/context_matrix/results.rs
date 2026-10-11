use super::*;
use crate::app::{view_hydration::ViewHydrationKey, ViewDataState};
use kuzushi_core::findings::{BatchTrialReport, ContextMatrixOccurrenceReport};

impl ShellApp {
    pub(crate) fn cached_context_matrix_report(
        &self,
    ) -> ViewDataState<Result<ContextMatrixOccurrenceReport, String>> {
        let Some(target) = self.target() else {
            return crate::app::ViewDataState::NotRequested;
        };
        let Some(receipt) = self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .and_then(|config| config.study.matrix.receipt.as_ref())
        else {
            return crate::app::ViewDataState::NotRequested;
        };
        let key = ViewHydrationKey::ContextMatrixReport {
            campaign_id: receipt.campaign_id.clone(),
            plan_sha256: receipt.plan_sha256.clone(),
        };
        self.workbench_cache()
            .borrow()
            .cached_matrix_report(target, &key)
    }

    pub(super) fn open_matrix_results(&mut self) -> InputUpdate {
        let config = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        if config.study.matrix.receipt.is_none() {
            config.notice = Some(
                "Prepare the finite matrix before reading its recorded results. No work starts."
                    .into(),
            );
            return InputUpdate::handled();
        }
        config.study.matrix.results = true;
        config.study.matrix.pass_selection = None;
        config.notice = None;
        self.refresh_matrix_results()
    }

    pub(in crate::app::batch_scan) fn handle_matrix_result_key(
        &mut self,
        code: KeyCode,
    ) -> Option<InputUpdate> {
        if !self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()?
            .study
            .matrix
            .results
        {
            return None;
        };
        if let Some(update) = self.matrix_report_read_key(code) {
            return Some(update);
        }
        if matches!(code, KeyCode::Enter | KeyCode::Char('b')) {
            return Some(self.activate_matrix_result(code));
        };
        let config = self.router.campaign_mut().batch_scan_config.as_mut()?;
        navigate_results(config, code);
        Some(InputUpdate::handled())
    }

    fn matrix_report_read_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        match code {
            KeyCode::Char('r') => Some(self.refresh_matrix_results()),
            KeyCode::Char('R') => Some(self.open_matrix_report()),
            _ => None,
        }
    }

    fn open_matrix_report(&mut self) -> InputUpdate {
        let Some(receipt) = self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .and_then(|config| config.study.matrix.receipt.as_ref())
        else {
            return InputUpdate::handled();
        };
        let study = crate::app::view_state::ReportStudyRef {
            campaign_id: receipt.campaign_id.clone(),
            plan_sha256: receipt.plan_sha256.clone(),
        };
        self.open_report_from_current_origin();
        self.router.report_mut().set_study(Some(study));
        self.scroll_to_top();
        self.invalidate_view_hydration();
        if let Some(target) = self.target() {
            self.workbench_cache()
                .borrow_mut()
                .invalidate_investigation_report(target);
        }
        self.schedule_active_view_hydration();
        InputUpdate::handled()
    }

    fn refresh_matrix_results(&mut self) -> InputUpdate {
        let Some(target) = self.target_owned() else {
            return InputUpdate::handled();
        };
        self.invalidate_view_hydration();
        self.workbench_cache()
            .borrow_mut()
            .invalidate_study_usage(&target);
        self.schedule_active_view_hydration();
        InputUpdate::handled()
    }

    fn activate_matrix_result(&mut self, code: KeyCode) -> InputUpdate {
        let Some(config) = self.router.campaign().batch_scan_config.as_ref() else {
            return InputUpdate::handled();
        };
        if config.study.matrix.pass_selection.is_none() {
            let config = self
                .router
                .campaign_mut()
                .batch_scan_config
                .as_mut()
                .unwrap();
            config.study.matrix.pass_selection = Some(code == KeyCode::Char('b'));
            config.study.matrix.pass_cursor = 0;
            return InputUpdate::handled();
        }
        self.choose_matrix_pass()
    }

    fn choose_matrix_pass(&mut self) -> InputUpdate {
        let state = crate::ui_view_models::matrix_result_state(self);
        let ViewDataState::Ready(Ok(report)) = state else {
            self.set_batch_config_notice(
                "Recorded results are loading or unavailable. r retries the read; no work starts.",
            );
            return InputUpdate::handled();
        };
        let config = self.router.campaign().batch_scan_config.as_ref().unwrap();
        let matrix = &config.study.matrix;
        let Some(trial) = selected_trial(&report, config) else {
            return InputUpdate::handled();
        };
        let Some(run) = trial.run_id.clone() else {
            self.set_batch_config_notice(
                "This pass has no recorded run. Select another pass or refresh results.",
            );
            return InputUpdate::handled();
        };
        if matrix.pass_selection == Some(true) {
            return self.select_matrix_baseline(trial, run);
        }
        let Some(baseline) = matrix.baseline_run_id.clone() else {
            self.set_batch_config_notice(
                "b chooses a completed baseline pass before comparison. Comparison starts no work.",
            );
            return InputUpdate::handled();
        };
        self.open_run_diff_view(baseline, run);
        self.set_input_mode(crate::app::InputMode::Navigate);
        InputUpdate::handled()
    }

    fn select_matrix_baseline(&mut self, trial: &BatchTrialReport, run: String) -> InputUpdate {
        if trial.state != "completed" {
            self.set_batch_config_notice(
                "Choose a completed baseline pass. Partial results remain readable as candidates.",
            );
            return InputUpdate::handled();
        }
        let config = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        config.study.matrix.baseline_run_id = Some(run);
        config.study.matrix.pass_selection = None;
        config.notice = Some("Baseline pass selected.".into());
        InputUpdate::handled()
    }
}

pub(crate) fn selected_trial<'a>(
    report: &'a ContextMatrixOccurrenceReport,
    config: &BatchScanConfig,
) -> Option<&'a BatchTrialReport> {
    let matrix = &config.study.matrix;
    let case = if matrix.pass_selection == Some(true) {
        report
            .cases
            .iter()
            .find(|case| case.id == report.baseline_case_id)?
    } else {
        report.cases.get(matrix.cursor)?
    };
    case.occurrence.trials.get(matrix.pass_cursor)
}

fn navigate_results(config: &mut BatchScanConfig, code: KeyCode) {
    if matches!(code, KeyCode::Esc | KeyCode::Char('q')) {
        if config.study.matrix.pass_selection.take().is_none() {
            config.study.matrix.results = false
        };
        return;
    }
    let matrix = &mut config.study.matrix;
    if matrix.pass_selection.is_some() {
        let index = if matrix.pass_selection == Some(true) {
            matrix
                .cases
                .iter()
                .position(|case| Some(&case.id) == matrix.baseline_case_id.as_ref())
                .unwrap_or(0)
        } else {
            matrix.cursor
        };
        let count = matrix.cases.get(index).map_or(0, |case| case.passes);
        matrix.pass_cursor = move_cursor(matrix.pass_cursor, code, count);
    } else {
        navigate_case_results(matrix, code)
    };
}

fn navigate_case_results(matrix: &mut StudyContextMatrix, code: KeyCode) {
    let cursor = move_cursor(matrix.cursor, code, matrix.cases.len());
    if cursor != matrix.cursor {
        matrix.cursor = cursor;
        matrix.detail_scroll = 0;
        return;
    }
    match code {
        KeyCode::PageUp => matrix.detail_scroll = matrix.detail_scroll.saturating_sub(5),
        KeyCode::PageDown => matrix.detail_scroll = matrix.detail_scroll.saturating_add(5),
        KeyCode::Home => matrix.detail_scroll = 0,
        KeyCode::End => matrix.detail_scroll = usize::MAX,
        _ => {}
    }
}

fn move_cursor(index: usize, code: KeyCode, count: usize) -> usize {
    match code {
        KeyCode::Up => index.saturating_sub(1),
        KeyCode::Down => (index + 1).min(count.saturating_sub(1)),
        _ => index,
    }
}
