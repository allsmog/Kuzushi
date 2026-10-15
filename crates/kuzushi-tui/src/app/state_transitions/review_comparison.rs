use super::*;

impl ShellApp {
    pub(super) fn draft_current_source_review(&mut self) -> InputUpdate {
        if !self.input().is_empty() {
            self.set_warn_notice(
                "review",
                "Keep or clear the current draft before preparing source review.",
            );
            return InputUpdate::handled();
        }
        self.open_current_source_review();
        InputUpdate::handled()
    }
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

#[cfg(test)]
mod current_source_tests {
    use super::*;

    fn fixture() -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_findings(vec![Finding::new_tool(
            "fixture",
            "owned",
            "note.txt",
            1,
            None,
            kuzushi_core::Severity::Low,
            "Owned source fixture",
        )]);
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Review));
        app
    }

    #[test]
    fn targetless_source_action_starts_no_work_and_keeps_the_composer() {
        let mut app = fixture();
        app.draft_current_source_review();
        assert!(app.source_review_form().is_none());
        assert!(app.input().is_empty());
        assert!(!app.has_running_work());
    }

    #[test]
    fn source_action_preserves_existing_draft_and_cursor() {
        let mut app = fixture();
        app.set_input("unsent\nreview draft");
        app.set_cursor(3);
        app.draft_current_source_review();
        assert_eq!(app.input(), "unsent\nreview draft");
        assert_eq!(app.cursor(), 3);
        assert!(!app.has_running_work());
    }
}
