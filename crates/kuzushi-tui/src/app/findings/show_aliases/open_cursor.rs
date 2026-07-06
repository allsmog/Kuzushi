use super::*;

impl ShellApp {
    pub(crate) fn open_finding_at_cursor(&mut self) {
        let visible_len = crate::ui_view_models::visible_findings_len(self);
        if visible_len == 0 {
            return;
        }
        let cursor = self.findings_route.cursor().min(visible_len - 1);
        self.findings_route.set_cursor(cursor);
        let Some((alias, finding)) = crate::ui_view_models::visible_finding_at_cursor(self) else {
            return;
        };
        self.selected_finding = Some(finding.clone());
        // The Workbench DETAILS pane is where a selected finding now reads;
        // put focus there so j/k scrolls evidence immediately after Enter.
        self.shell_view = ShellView::Workbench;
        self.workbench_focus = crate::app::WorkbenchPane::Details;
        self.workbench_center_mode = crate::app::WorkbenchCenterMode::Code;
        self.workbench_scroll
            .set(crate::app::WorkbenchPane::Details, 0);
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
