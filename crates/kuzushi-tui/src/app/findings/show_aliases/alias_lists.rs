use super::*;

impl ShellApp {
    pub fn show_aliases(&mut self, prefix: Option<&str>) {
        self.shell_view = ShellView::Workbench;
        self.router
            .workbench_mut()
            .set_focus(crate::app::WorkbenchPane::Findings);
        self.router
            .workbench_mut()
            .set_center_mode(crate::app::WorkbenchCenterMode::Code);
        let filter = prefix.map(|raw| raw.trim().to_ascii_uppercase());
        let table = format_alias_table(self.findings(), self.chain_aliases(), filter.as_deref());
        for line in table.lines() {
            self.log("aliases", line.to_string());
        }
    }

    pub(crate) fn open_workbench_effects(
        &mut self,
        pane: crate::app::WorkbenchPane,
    ) -> Vec<ShellEffect> {
        self.begin_workbench_open(pane);
        vec![
            ShellEffect::RefreshFindings(FindingsRefresh {
                announce: true,
                filter: None,
            }),
            ShellEffect::FinalizeWorkbenchOpen(WorkbenchOpenFinalize { pane }),
        ]
    }

    /// Open the Workbench command center with `pane` focused.
    /// Command reducers should prefer `open_workbench_effects` so the findings
    /// store read happens in the effect runtime.
    pub(crate) fn open_workbench(&mut self, pane: crate::app::WorkbenchPane) {
        self.begin_workbench_open(pane);
        self.refresh_findings(true);
        self.finalize_workbench_open_effect(WorkbenchOpenFinalize { pane });
    }

    fn begin_workbench_open(&mut self, pane: crate::app::WorkbenchPane) {
        self.shell_view = ShellView::Workbench;
        self.router.workbench_mut().set_focus(pane);
        if pane == crate::app::WorkbenchPane::Center {
            *self.selected_finding_mut() = None;
        }
    }

    pub(crate) fn finalize_workbench_open_effect(&mut self, open: WorkbenchOpenFinalize) {
        self.clamp_findings_cursor();
        let center_mode = self.default_workbench_center_mode(open.pane);
        self.router.workbench_mut().set_center_mode(center_mode);
        if self.findings().is_empty() {
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
        self.findings().is_empty()
            && crate::ui_view_models::journey_model(self)
                .as_ref()
                .map_or(false, |journey| {
                    journey.current == crate::app::WorkflowPhase::Map
                })
    }

    pub(crate) fn clamp_findings_cursor(&mut self) {
        let len = crate::ui_view_models::visible_findings_len(self);
        self.router.findings_mut().clamp(len);
    }

    pub(crate) fn sync_findings_cursor_to_selected(&mut self) {
        let Some(selected) = self.selected_finding().as_ref() else {
            self.clamp_findings_cursor();
            return;
        };
        if let Some(index) = crate::ui_view_models::visible_finding_position_for(self, selected) {
            self.router.findings_mut().set_cursor(index);
        } else {
            self.clamp_findings_cursor();
        }
    }
}
