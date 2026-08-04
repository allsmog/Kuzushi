use super::*;

impl ShellApp {
    pub(crate) fn prepare_findings_list_view(&mut self) {
        *self.selected_finding_mut() = None;
        self.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Review));
        self.set_shell_view(ShellView::Workbench);
        self.router
            .workbench_mut()
            .set_focus(crate::ui_view_models::PhaseSurfaceId::ReviewQueue);
    }

    pub fn show_aliases(&mut self, prefix: Option<&str>) {
        self.set_shell_view(ShellView::Workbench);
        self.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Review));
        self.router
            .workbench_mut()
            .set_focus(crate::ui_view_models::PhaseSurfaceId::ReviewQueue);
        let filter = prefix.map(|raw| raw.trim().to_ascii_uppercase());
        let table = format_alias_table(self.findings(), self.chain_aliases(), filter.as_deref());
        for line in table.lines() {
            self.log("aliases", line.to_string());
        }
    }

    /// Every workbench entry point opens onto the active page's finding-list
    /// surface; the page itself is either set by the caller or reality-derived.
    pub(crate) fn open_workbench_effects(&mut self) -> Vec<ShellEffect> {
        let focus = self.begin_workbench_open();
        vec![
            ShellEffect::RefreshFindings(FindingsRefresh {
                announce: true,
                filter: None,
            }),
            ShellEffect::FinalizeWorkbenchOpen(WorkbenchOpenFinalize { focus }),
        ]
    }

    pub(crate) fn open_reality_derived_workbench_effects(&mut self) -> Vec<ShellEffect> {
        self.router.workbench_mut().set_page(None);
        self.open_workbench_effects()
    }

    /// Open the Review workflow with the finding-list surface focused.
    /// Command reducers should prefer `open_workbench_effects` so the findings
    /// store read happens in the effect runtime.
    pub(crate) fn open_workbench(&mut self) {
        let focus = self.begin_workbench_open();
        self.refresh_findings_preserving_active_filter(true);
        self.finalize_workbench_open_effect(WorkbenchOpenFinalize { focus });
    }

    pub(crate) fn open_cached_workbench(&mut self) {
        let focus = self.begin_workbench_open();
        self.finalize_workbench_open_effect(WorkbenchOpenFinalize { focus });
    }

    fn begin_workbench_open(&mut self) -> crate::ui_view_models::PhaseSurfaceId {
        self.set_shell_view(ShellView::Workbench);
        let focus = crate::ui_view_models::active_workbench_page(self).findings_surface();
        self.router.workbench_mut().set_focus(focus);
        focus
    }

    /// The findings refresh can change the reality-derived page, so re-anchor
    /// focus onto the (possibly new) page's finding-list surface before the
    /// cursor clamp runs.
    pub(crate) fn finalize_workbench_open_effect(&mut self, open: WorkbenchOpenFinalize) {
        let page = crate::ui_view_models::active_workbench_page(self);
        if open.focus.page() != page {
            self.router
                .workbench_mut()
                .set_focus(page.findings_surface());
        }
        self.clamp_findings_cursor();
        if self.findings().is_empty() {
            self.log("findings", "no findings yet. Next: scan, or full <target>");
        }
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
