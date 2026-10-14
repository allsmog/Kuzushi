use super::*;

impl ShellApp {
    /// Enter on the review queue. This is a substantive open — it selects the
    /// finding and moves focus to its detail — so it starts a review session.
    /// Moving the cursor does not come through here.
    pub(crate) fn open_finding_at_cursor(&mut self) -> Vec<ShellEffect> {
        let Some((alias, finding)) = self.selected_visible_finding_at_cursor() else {
            return Vec::new();
        };
        self.open_captured_finding(alias, finding)
    }

    /// Capture the row before changing pages because Review and Prove can
    /// project different finding sets at the same cursor index.
    pub(crate) fn open_finding_at_cursor_on_page(
        &mut self,
        page: WorkbenchPage,
    ) -> Vec<ShellEffect> {
        let Some((alias, finding)) = self.selected_visible_finding_at_cursor() else {
            return Vec::new();
        };
        self.set_workbench_page(page);
        self.open_captured_finding(alias, finding)
    }

    fn open_captured_finding(&mut self, alias: String, finding: Finding) -> Vec<ShellEffect> {
        *self.selected_finding_mut() = Some(finding.clone());
        self.bind_selected_finding_reference(alias.clone());
        self.focus_workbench_details_for_opened_finding();
        let effects = self.review_session_start_effects(&finding);
        self.log_cursor_finding_opened(&alias, finding);
        effects
    }

    fn selected_visible_finding_at_cursor(&mut self) -> Option<(String, Finding)> {
        let visible_len = crate::ui_view_models::visible_findings_len(self);
        if visible_len == 0 {
            return None;
        }
        let cursor = self.router.findings().cursor().min(visible_len - 1);
        self.router.findings_mut().set_cursor(cursor);
        crate::ui_view_models::visible_finding_at_cursor(self)
    }

    pub(super) fn focus_workbench_details_for_opened_finding(&mut self) {
        self.set_shell_view(ShellView::Workbench);
        let detail = crate::ui_view_models::active_workbench_page(self).detail_surface();
        self.router.workbench_mut().set_focus(detail);
        self.router.workbench_mut().scroll_mut().set(detail, 0);
        let viewport = self.viewport();
        let area = ratatui::layout::Rect::new(0, 0, viewport.columns, viewport.rows);
        let hidden = crate::renderer::workbench_phase_plan_for_app(self, area)
            .is_some_and(|plan| plan.surface(detail).is_none());
        if hidden {
            self.router.workbench_mut().show_zoomed_focus(detail);
        }
    }

    fn log_cursor_finding_opened(&mut self, alias: &str, finding: Finding) {
        self.log(
            "open",
            format!(
                "{alias} {} {}:{} {}",
                finding.severity.as_str(),
                finding.file_path,
                finding.start_line,
                finding.fingerprint
            ),
        );
        self.log("title", finding.title);
        if let Some(triage) = &finding.triage {
            self.log(
                "triage",
                format!(
                    "{} {:.2} {}",
                    triage.verdict.as_str(),
                    triage.confidence,
                    triage.rationale
                ),
            );
        }
    }
}
