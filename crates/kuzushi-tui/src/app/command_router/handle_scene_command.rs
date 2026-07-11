use super::*;
use crate::scene3d::VizPage;

const AUTO_OPEN_INTERACTION_GRACE: std::time::Duration = std::time::Duration::from_secs(4);

/// Map a completed tool to the gallery page that visualizes its artifact, if
/// any. Pure so the auto-open hooks stay testable. Matched exactly on the verbs
/// that actually *emit* the structured artifact the page draws — prereq steps
/// (`taint-iris-next:catalog`), read/info verbs (`threat-model:read`), and tools
/// that don't emit structured flows (`taint-iris-next:hunt` flattens its taint
/// path into finding text, unlike `taint-iris:hunt`) are intentionally absent so
/// auto-open never lands on an empty page.
pub(crate) fn viz_page_for_tool(tool_name: &str) -> Option<VizPage> {
    match tool_name {
        "taint-iris:hunt" => Some(VizPage::AttackPath),
        "exploit-chain:scan" => Some(VizPage::ExploitChain),
        _ => None,
    }
}

impl ShellApp {
    /// Open the gallery, keeping whatever page was last shown.
    pub fn open_scene(&mut self) {
        self.open_scene_to_page(self.router.scene().page());
    }

    /// Open the gallery focused on a specific page (manual nav and auto-open).
    pub fn open_scene_to_page(&mut self, page: VizPage) {
        if !matches!(self.shell_view(), ShellView::Scene) {
            self.push_nav_history(self.shell_view());
        }
        self.router.scene_mut().set_page(page);
        self.set_shell_view(ShellView::Scene);
        self.log(
            "scene",
            format!(
                "security-viz — {} · Tab cycles pages · Esc/q returns",
                page.label()
            ),
        );
    }

    /// Auto-switch to a gallery page when its artifact lands, unless the
    /// operator opted out via `setg ui.auto_open_viz false`. Mirrors
    /// `auto_open_activity`.
    pub(crate) fn auto_open_viz_page(&mut self, page: VizPage) {
        if !self.ui().auto_open_viz() {
            return;
        }
        if self.activity_deck_is_pinned() {
            self.log_scene_ready(page, "output page unchanged");
            return;
        }
        self.sync_activity_deck_to_scene_page(page);
        self.open_or_log_scene_ready(page);
    }

    pub(crate) fn auto_open_workbench_dfd(&mut self) {
        if !self.ui().auto_open_viz() {
            return;
        }
        self.hydrate_latest_threat_model_for_dfd();
        if crate::ui_view_models::dfd_model(self).empty_hint.is_some() {
            return;
        }
        if self.can_auto_open_viz_now() {
            self.open_workbench(crate::app::WorkbenchPane::Center);
            self.router
                .workbench_mut()
                .set_page(Some(crate::app::WorkbenchPage::Review));
            self.router
                .workbench_mut()
                .set_center_mode(crate::app::WorkbenchCenterMode::Dfd);
            self.log(
                "workbench",
                "data-flow model ready — showing Workbench DFD center pane",
            );
        } else {
            self.log_workbench_ready("use `workbench` to view");
        }
    }

    fn hydrate_latest_threat_model_for_dfd(&mut self) {
        let Some(target) = self.target_owned() else {
            return;
        };
        let path = kuzushi_core::capabilities::persistent_threat_model_path(&target);
        self.invalidate_view_hydration();
        self.workbench_cache()
            .borrow_mut()
            .invalidate_json_file(&path);
        self.hydrate_view_keys_blocking(
            &target,
            vec![crate::app::ViewHydrationKey::JsonFile { path }],
        );
    }

    fn activity_deck_is_pinned(&self) -> bool {
        self.activity().is_some() && !self.router.activity().can_auto_switch_deck()
    }

    fn sync_activity_deck_to_scene_page(&mut self, page: VizPage) {
        if self.activity().is_some() {
            self.router.activity_mut().set_deck_scene_page(page);
        }
    }

    fn open_or_log_scene_ready(&mut self, page: VizPage) {
        if matches!(self.shell_view(), ShellView::Activity) {
            self.log_scene_ready(page, "showing in Activity output");
            return;
        }
        if self.can_auto_open_viz_now() {
            self.open_scene_to_page(page);
        } else {
            self.log_scene_ready(page, "use `scene` to view");
        }
    }

    fn log_scene_ready(&mut self, page: VizPage, message: &str) {
        self.log(
            "scene",
            format!(
                "{} ready — {message}; setg ui.auto_open_viz false disables auto-open",
                page.label()
            ),
        );
    }

    fn log_workbench_ready(&mut self, message: &str) {
        self.log(
            "workbench",
            format!(
                "data-flow model ready — {message}; setg ui.auto_open_viz false disables auto-open"
            ),
        );
    }

    fn can_auto_open_viz_now(&self) -> bool {
        if self
            .ui()
            .recent_operator_interaction(AUTO_OPEN_INTERACTION_GRACE)
        {
            return false;
        }
        !matches!(
            self.shell_view(),
            ShellView::Workbench
                | ShellView::TargetPicker
                | ShellView::PlanningPicker
                | ShellView::ModelPicker
                | ShellView::AuthMethodPicker
                | ShellView::PromptsEditor
                | ShellView::ThreatEditor
                | ShellView::AgentChat
                | ShellView::Story
                | ShellView::FailureHandoff
                | ShellView::Trace
                | ShellView::Replay
        )
    }

    /// Whether `page` has a backing artifact worth showing. Guards auto-open so
    /// a tool run that produced nothing (clean scan, zero-flow hunt) doesn't
    /// yank the operator to an empty page that reads "run the tool".
    pub(crate) fn viz_page_has_content(&self, page: VizPage) -> bool {
        match page {
            VizPage::AttackPath => self.domain().taint_flow().is_some(),
            VizPage::ExploitChain => self.domain().has_exploit_chains(),
            VizPage::Dfd => crate::ui_view_models::dfd_model(self).empty_hint.is_none(),
            VizPage::Heatmap | VizPage::AttackSurface => !self.findings().is_empty(),
        }
    }

    /// Switch to a specific gallery page and reflect it in the open view.
    pub fn set_scene_page(&mut self, page: VizPage) {
        self.router.scene_mut().set_page(page);
    }
}
