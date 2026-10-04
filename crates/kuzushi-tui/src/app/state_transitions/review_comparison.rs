use super::*;

impl ShellApp {
    /// Uses the same visible row as Review, never an out-of-filter pinned finding.
    pub(crate) fn review_observation_run_pair(&self) -> Option<(String, String)> {
        if crate::ui_view_models::active_workbench_page(self) != WorkbenchPage::Review {
            return None;
        }
        let (_, finding) = crate::ui_view_models::visible_finding_at_cursor(self)?;
        let gap = finding.observation_gap.as_ref()?;
        let left = gap.last_seen_run_id.as_ref()?.trim();
        let right = gap.compared_run_id.as_ref()?.trim();
        if left.is_empty() || right.is_empty() {
            return None;
        }
        Some((left.to_string(), right.to_string()))
    }

    pub(super) fn open_review_observation_comparison(&mut self) {
        let Some((left, right)) = self.review_observation_run_pair() else {
            self.log(
                "review",
                "This finding has no recorded scan pair to compare.",
            );
            return;
        };
        self.open_run_diff_view(left, right);
        self.router.run_diff_mut().toggle_sources(0);
        self.set_input_mode(InputMode::Navigate);
    }
}
