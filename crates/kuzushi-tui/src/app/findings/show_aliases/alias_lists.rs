use super::*;

impl ShellApp {
    pub fn show_aliases(&mut self, prefix: Option<&str>) {
        self.shell_view = ShellView::Workbench;
        self.workbench_focus = crate::app::WorkbenchPane::Findings;
        let filter = prefix.map(|raw| raw.trim().to_ascii_uppercase());
        let table = format_alias_table(&self.findings, &self.chains, filter.as_deref());
        for line in table.lines() {
            self.log("aliases", line.to_string());
        }
    }

    pub(crate) fn show_findings(&mut self) {
        self.open_workbench(crate::app::WorkbenchPane::Findings);
    }

    /// Open the Workbench command center with `pane` focused, refreshing the
    /// findings store so the FINDINGS/DETAILS panes reflect the latest scan.
    /// The `findings` verb and the `workbench` verb both land here.
    pub(crate) fn open_workbench(&mut self, pane: crate::app::WorkbenchPane) {
        self.shell_view = ShellView::Workbench;
        self.workbench_focus = pane;
        if pane == crate::app::WorkbenchPane::Center {
            self.selected_finding = None;
        }
        self.refresh_findings(true);
        self.clamp_findings_cursor();
        if self.findings.is_empty() {
            self.log("findings", "no findings yet. Next: scan or scan <target>");
        }
    }

    pub(crate) fn clamp_findings_cursor(&mut self) {
        if self.findings.is_empty() {
            self.findings_cursor = 0;
        } else {
            self.findings_cursor = self.findings_cursor.min(self.findings.len() - 1);
        }
    }

    pub(crate) fn sync_findings_cursor_to_selected(&mut self) {
        let Some(fingerprint) = self
            .selected_finding
            .as_ref()
            .map(|finding| finding.fingerprint.as_str())
        else {
            self.clamp_findings_cursor();
            return;
        };
        if let Some(index) = sorted_finding_aliases(&self.findings)
            .into_iter()
            .position(|(_, finding)| finding.fingerprint == fingerprint)
        {
            self.findings_cursor = index;
        } else {
            self.clamp_findings_cursor();
        }
    }
}
