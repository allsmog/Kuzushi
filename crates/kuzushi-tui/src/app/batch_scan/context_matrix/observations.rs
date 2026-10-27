//! Read exact case observations through the existing Review and return boundary.
use super::*;
use crate::app::{FindingsRefresh, InputMode, OpenFindingReference, ShellEffect, ShellView};
use kuzushi_core::findings::ContextMatrixOccurrenceReport;

impl ShellApp {
    pub(super) fn matrix_observation_key(&mut self, code: KeyCode) -> Option<InputUpdate> {
        let matrix = &self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()?
            .study
            .matrix;
        if matrix.observation_key.is_some() {
            if code == KeyCode::Char('r') {
                return None;
            }
            return Some(self.navigate_matrix_observation(code));
        }
        (matrix.pass_selection.is_none() && code == KeyCode::Char('f'))
            .then(|| self.open_matrix_observations())
    }

    fn open_matrix_observations(&mut self) -> InputUpdate {
        let report = match self.matrix_observation_report() {
            Ok(report) => report,
            Err(error) => return self.matrix_observation_notice(error),
        };
        let config = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        let Some(row) = report
            .cases
            .get(config.study.matrix.cursor)
            .and_then(|case| case.occurrence.rows.first())
        else {
            return self.matrix_observation_notice(
                "No recorded observations in this case. Decisions stay unchanged.",
            );
        };
        config.study.matrix.observation_key = Some(row.fold_key.clone());
        config.study.matrix.observation_scroll = 0;
        config.study.matrix.observation_notice = None;
        InputUpdate::handled()
    }

    fn navigate_matrix_observation(&mut self, code: KeyCode) -> InputUpdate {
        if matches!(code, KeyCode::Esc | KeyCode::Char('q')) {
            self.router
                .campaign_mut()
                .batch_scan_config
                .as_mut()
                .unwrap()
                .study
                .matrix
                .observation_key = None;
            return InputUpdate::handled();
        }
        if code == KeyCode::Enter {
            return self.review_matrix_observation();
        }
        let report = match self.matrix_observation_report() {
            Ok(report) => report,
            Err(error) => return self.matrix_observation_notice(error),
        };
        let limits = crate::ui_view_models::matrix_result_read_limits(self).unwrap_or_default();
        let config = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        move_selection(&mut config.study.matrix, &report, code, limits);
        InputUpdate::handled()
    }

    fn matrix_observation_report(&self) -> Result<ContextMatrixOccurrenceReport, String> {
        let report = ready_report(self.cached_context_matrix_report())?;
        let receipt = self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .and_then(|config| config.study.matrix.receipt.as_ref())
            .ok_or("Read this exact saved study before opening its observations.")?;
        if report.campaign_id != receipt.campaign_id || report.plan_sha256 != receipt.plan_sha256 {
            return Err(
                "Recorded results do not match this study. r retries; no work starts.".into(),
            );
        }
        Ok(report)
    }

    fn review_matrix_observation(&mut self) -> InputUpdate {
        let reference = match self.selected_matrix_observation_reference() {
            Ok(reference) => reference,
            Err(error) => return self.matrix_observation_notice(error),
        };
        let Some(target) = self.target_owned() else {
            return self.matrix_observation_notice(
                "Select the original target before reading its observations.",
            );
        };
        self.router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap()
            .study
            .matrix
            .observation_notice = None;
        let query = self.active_findings_filter().clone().unwrap_or_default();
        let origin = self.capture_linked_findings_origin(target, query);
        self.router.campaign_mut().clear_active_batch();
        self.router.campaign_mut().matrix_observation_origin = Some(origin);
        self.set_active_findings_filter(None);
        *self.selected_finding_mut() = None;
        self.set_shell_view(ShellView::Workbench);
        self.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Review));
        self.set_input_mode(InputMode::Navigate);
        self.set_info_notice("Recorded case finding", "Review opens the recorded observation. Evidence confidence and decisions stay separate from recurrence. Back returns to the context results.");
        InputUpdate::handled_with_effects(vec![
            ShellEffect::RefreshFindings(FindingsRefresh {
                announce: false,
                filter: None,
            }),
            ShellEffect::OpenFinding(OpenFindingReference { reference }),
        ])
    }

    fn selected_matrix_observation_reference(&self) -> Result<String, String> {
        let report = self.matrix_observation_report()?;
        let matrix = &self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .unwrap()
            .study
            .matrix;
        let row = report
            .cases
            .get(matrix.cursor)
            .and_then(|case| {
                case.occurrence
                    .rows
                    .iter()
                    .find(|row| Some(&row.fold_key) == matrix.observation_key.as_ref())
            })
            .ok_or("The selected observation is no longer available. Choose another or refresh.")?;
        let reference = row.representative_observation_ref.as_ref()
            .ok_or("This result has no exact observation reference. Refresh the recorded results before opening Review.")?;
        let id = reference
            .strip_prefix("generation:")
            .and_then(|id| id.parse::<i64>().ok());
        if !id.is_some_and(|id| id > 0) {
            return Err(
                "This observation reference is invalid. Refresh the recorded results.".into(),
            );
        }
        Ok(reference.clone())
    }

    fn matrix_observation_notice(&mut self, message: impl Into<String>) -> InputUpdate {
        let message = message.into();
        let matrix = &mut self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap()
            .study
            .matrix;
        if matrix.observation_key.is_some() {
            matrix.observation_notice = Some(message);
            matrix.observation_scroll = 0;
        } else {
            self.set_batch_config_notice(message);
        }
        InputUpdate::handled()
    }

    pub(crate) fn reviewed_context_matrix_receipt(&self) -> Option<&ContextMatrixReceipt> {
        if self.shell_view() != ShellView::Workbench {
            return None;
        }
        let origin = self.router.campaign().matrix_observation_origin.as_ref()?;
        if !self.linked_findings_origin_matches(origin) {
            return None;
        }
        origin.context_matrix_receipt()
    }

    pub(crate) fn matrix_observation_return_is_available(&self) -> bool {
        self.router
            .campaign()
            .matrix_observation_origin
            .as_ref()
            .is_some_and(|origin| self.linked_findings_origin_matches(origin))
    }

    pub(crate) fn restore_matrix_observation_origin(&mut self) -> bool {
        if self.shell_view() != ShellView::Workbench
            || !self.matrix_observation_return_is_available()
        {
            return false;
        }
        let origin = self
            .router
            .campaign_mut()
            .matrix_observation_origin
            .take()
            .unwrap();
        self.restore_linked_findings_origin(origin);
        true
    }
}

fn ready_report(
    state: crate::app::ViewDataState<Result<ContextMatrixOccurrenceReport, String>>,
) -> Result<ContextMatrixOccurrenceReport, String> {
    match state {
        crate::app::ViewDataState::Ready(Ok(report)) => Ok(report),
        crate::app::ViewDataState::Ready(Err(error)) => Err(format!(
            "Recorded observations unavailable: {error}. r retries; no work starts."
        )),
        _ => Err("Recorded observations are loading. r retries; no work starts.".into()),
    }
}

fn move_selection(
    matrix: &mut StudyContextMatrix,
    report: &ContextMatrixOccurrenceReport,
    code: KeyCode,
    limits: crate::ui_view_models::MatrixResultReadLimits,
) {
    let Some(case) = report.cases.get(matrix.cursor) else {
        return;
    };
    let rows = &case.occurrence.rows;
    let index = rows
        .iter()
        .position(|row| Some(&row.fold_key) == matrix.observation_key.as_ref())
        .unwrap_or(0);
    let next = finding_index(code, index, rows.len());
    if let Some(row) = next.and_then(|next| rows.get(next)) {
        matrix.observation_key = Some(row.fold_key.clone());
        matrix.observation_scroll = 0;
        matrix.observation_notice = None;
        return;
    }
    matrix.observation_scroll = read_offset(matrix.observation_scroll, code, limits);
}

fn read_offset(
    current: usize,
    code: KeyCode,
    limits: crate::ui_view_models::MatrixResultReadLimits,
) -> usize {
    let current = current.min(limits.max_scroll);
    match code {
        KeyCode::Home => 0,
        KeyCode::End => limits.max_scroll,
        _ => page_offset(current, code, limits),
    }
}

fn page_offset(
    current: usize,
    code: KeyCode,
    limits: crate::ui_view_models::MatrixResultReadLimits,
) -> usize {
    match code {
        KeyCode::PageUp => current.saturating_sub(limits.page.max(1)),
        KeyCode::PageDown => current
            .saturating_add(limits.page.max(1))
            .min(limits.max_scroll),
        _ => current,
    }
}

fn finding_index(code: KeyCode, index: usize, count: usize) -> Option<usize> {
    match code {
        KeyCode::Up | KeyCode::Char('k') => Some(index.saturating_sub(1)),
        KeyCode::Down | KeyCode::Char('j') => Some((index + 1).min(count.saturating_sub(1))),
        _ => None,
    }
}
