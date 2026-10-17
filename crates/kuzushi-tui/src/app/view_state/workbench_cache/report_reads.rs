//! Retain one previous read for presentation, separately from current export readiness.
use super::{InvestigationReportRead, ViewDataState, ViewHydrationKey, WorkbenchCache};
use std::path::{Path, PathBuf};
use std::sync::Arc;

impl WorkbenchCache {
    pub(crate) fn cached_workspace_report_review(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> ViewDataState<Result<Arc<kuzushi_core::workspace::WorkspaceReviewSummary>, String>> {
        self.workspace_report_review
            .current(target, key)
            .cloned()
            .map(ViewDataState::Ready)
            .unwrap_or_else(|| self.loading_state(target, key))
    }

    pub(crate) fn invalidate_investigation_report(&mut self, target: &Path) {
        self.workspace_report_review.invalidate_target(target);
        self.investigation_report.invalidate_target(target);
    }

    pub(crate) fn cached_selected_report(
        &self,
        target: Option<&Path>,
        key: &ViewHydrationKey,
    ) -> ViewDataState<InvestigationReportRead> {
        let Some(target) = target else {
            return ViewDataState::Ready(Ok(None));
        };
        self.investigation_report
            .current(target, key)
            .cloned()
            .map(ViewDataState::Ready)
            .unwrap_or_else(|| self.loading_state(target, key))
    }

    pub(crate) fn cached_previous_selected_report(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> Option<Arc<kuzushi_core::workspace::InvestigationReportDocument>> {
        self.investigation_report
            .previous(target, key)
            .cloned()
            .flatten()
    }

    pub(crate) fn cached_previous_workspace_report_review(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> Option<Arc<kuzushi_core::workspace::WorkspaceReviewSummary>> {
        self.workspace_report_review.previous(target, key).cloned()
    }

    /// Screen context uses current run identities, never previous refresh content.
    pub(crate) fn cached_report_run_refs(
        &self,
        target: Option<&Path>,
        key: &ViewHydrationKey,
    ) -> Option<Vec<String>> {
        let document = self
            .investigation_report
            .current(target?, key)?
            .as_ref()
            .ok()?
            .as_ref()?;
        Some(
            document
                .summary()
                .attempts
                .iter()
                .map(|attempt| attempt.run_id.clone())
                .collect(),
        )
    }
}

#[derive(Debug)]
struct ReportReadEntry<T> {
    target: PathBuf,
    key: ViewHydrationKey,
    value: Result<T, String>,
}

#[derive(Debug)]
pub(super) struct ReportReadCache<T> {
    current: Option<ReportReadEntry<T>>,
    previous: Option<ReportReadEntry<T>>,
}

impl<T> Default for ReportReadCache<T> {
    fn default() -> Self {
        Self {
            current: None,
            previous: None,
        }
    }
}

impl<T> ReportReadCache<T> {
    pub(super) fn store(
        &mut self,
        target: PathBuf,
        key: ViewHydrationKey,
        value: Result<T, String>,
    ) {
        self.current = Some(ReportReadEntry { target, key, value });
        self.previous = None;
    }

    pub(super) fn current(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
    ) -> Option<&Result<T, String>> {
        self.current
            .as_ref()
            .filter(|entry| entry.target == target && entry.key == *key)
            .map(|entry| &entry.value)
    }

    pub(super) fn previous(&self, target: &Path, key: &ViewHydrationKey) -> Option<&T> {
        self.current
            .iter()
            .chain(self.previous.iter())
            .find(|entry| {
                entry.target == target
                    && same_report_selection(&entry.key, key)
                    && watermark_did_not_regress(
                        report_watermark(&entry.key),
                        report_watermark(key),
                    )
            })
            .and_then(|entry| entry.value.as_ref().ok())
    }

    pub(super) fn invalidate_target(&mut self, target: &Path) {
        if self
            .current
            .as_ref()
            .is_some_and(|entry| entry.target == target)
        {
            self.invalidate();
        }
    }

    pub(super) fn invalidate(&mut self) {
        if let Some(current) = self.current.take() {
            self.previous = Some(current);
        }
    }
}

fn same_report_selection(left: &ViewHydrationKey, right: &ViewHydrationKey) -> bool {
    use ViewHydrationKey::*;
    match (left, right) {
        (InvestigationReport { run_refs: a, .. }, InvestigationReport { run_refs: b, .. }) => {
            a == b
        }
        (
            InvestigationStudyReport {
                campaign_id: a,
                plan_sha256: x,
                ..
            },
            InvestigationStudyReport {
                campaign_id: b,
                plan_sha256: y,
                ..
            },
        ) => a == b && x == y,
        (WorkspaceReportReview { .. }, WorkspaceReportReview { .. }) => true,
        _ => false,
    }
}

fn report_watermark(key: &ViewHydrationKey) -> Option<u64> {
    use ViewHydrationKey::*;
    match key {
        InvestigationReport {
            findings_watermark, ..
        }
        | InvestigationStudyReport {
            findings_watermark, ..
        }
        | WorkspaceReportReview { findings_watermark } => *findings_watermark,
        _ => None,
    }
}

fn watermark_did_not_regress(previous: Option<u64>, current: Option<u64>) -> bool {
    match (previous, current) {
        (Some(previous), Some(current)) => current >= previous,
        (None, _) => true,
        (Some(_), None) => false,
    }
}

#[cfg(test)]
mod tests;
