use super::*;

impl ShellApp {
    pub(crate) fn open_finding_at_cursor(&mut self) {
        let aliases = sorted_finding_aliases(&self.findings);
        if aliases.is_empty() {
            return;
        }
        let cursor = self.findings_cursor.min(aliases.len() - 1);
        let (alias, finding) = aliases[cursor].clone();
        self.findings_cursor = cursor;
        self.selected_finding = Some(finding.clone());
        // The Workbench DETAILS pane is where a selected finding now reads;
        // put focus there so j/k scrolls evidence immediately after Enter.
        self.shell_view = ShellView::Workbench;
        self.workbench_focus = crate::app::WorkbenchPane::Details;
        self.scroll_offset = 0;
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
