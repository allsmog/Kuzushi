use super::*;

impl ShellApp {
    pub fn show_aliases(&mut self, prefix: Option<&str>) {
        self.shell_view = ShellView::Workbench;
        self.workbench_focus = crate::app::WorkbenchPane::Findings;
        self.workbench_center_mode = crate::app::WorkbenchCenterMode::Code;
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
        self.workbench_center_mode = self.default_workbench_center_mode(pane);
        if self.findings.is_empty() {
            self.log("findings", "no findings yet. Next: scan or scan <target>");
        }
    }

    pub(crate) fn default_workbench_center_mode(
        &self,
        pane: crate::app::WorkbenchPane,
    ) -> crate::app::WorkbenchCenterMode {
        if pane == crate::app::WorkbenchPane::Center || self.should_open_workbench_on_dfd() {
            return crate::app::WorkbenchCenterMode::Dfd;
        }
        crate::app::WorkbenchCenterMode::Code
    }

    fn should_open_workbench_on_dfd(&self) -> bool {
        self.findings.is_empty()
            && crate::ui_view_models::journey_model(self)
                .as_ref()
                .map_or(false, |journey| {
                    journey.current == crate::app::WorkflowPhase::Map
                })
    }

    pub(crate) fn clamp_findings_cursor(&mut self) {
        let len = crate::ui_view_models::visible_findings_len(self);
        if len == 0 {
            self.findings_cursor = 0;
        } else {
            self.findings_cursor = self.findings_cursor.min(len - 1);
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
        if let Some(index) = crate::ui_view_models::visible_sorted_finding_alias_indices(self)
            .into_iter()
            .position(|(_, index)| {
                self.findings
                    .get(index)
                    .is_some_and(|finding| finding.fingerprint == fingerprint)
            })
        {
            self.findings_cursor = index;
        } else {
            self.clamp_findings_cursor();
        }
    }
}
