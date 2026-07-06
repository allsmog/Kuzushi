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
        self.findings_route.clamp(len);
    }

    pub(crate) fn sync_findings_cursor_to_selected(&mut self) {
        let Some(selected) = self.selected_finding.as_ref() else {
            self.clamp_findings_cursor();
            return;
        };
        if let Some(index) = crate::ui_view_models::visible_finding_position_for(self, selected) {
            self.findings_route.set_cursor(index);
        } else {
            self.clamp_findings_cursor();
        }
    }
}
