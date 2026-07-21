use super::*;

impl ShellApp {
    pub(crate) fn open_finding_at_cursor(&mut self) {
        let Some((alias, finding)) = self.selected_visible_finding_at_cursor() else {
            return;
        };
        *self.selected_finding_mut() = Some(finding.clone());
        self.focus_workbench_details_for_opened_finding();
        self.log_cursor_finding_opened(&alias, finding);
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

    fn focus_workbench_details_for_opened_finding(&mut self) {
        self.set_shell_view(ShellView::Workbench);
        let detail = crate::ui_view_models::active_workbench_page(self).detail_surface();
        self.router.workbench_mut().set_focus(detail);
        self.router.workbench_mut().scroll_mut().set(detail, 0);
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
