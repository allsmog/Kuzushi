use super::*;
use crate::scene3d::VizPage;

/// `/scene` (`/viz`, `/diagram`) opens the security-viz gallery, keeping
/// whatever page was last shown. Pages are fed real Kuzushi data and show an
/// empty-state hint until the backing artifact (findings, threat model, exploit
/// chains, taint flow) has been generated.
pub(crate) fn handle_scene_command(app: &mut ShellApp, command: &ShellCommand) -> bool {
    let ShellCommand::Scene = command else {
        return false;
    };
    app.open_scene();
    true
}

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
        "threat-model:build" => Some(VizPage::Dfd),
        _ => None,
    }
}

impl ShellApp {
    /// Open the gallery, keeping whatever page was last shown.
    pub fn open_scene(&mut self) {
        self.open_scene_to_page(self.scene_page);
    }

    /// Open the gallery focused on a specific page (manual nav and auto-open).
    pub fn open_scene_to_page(&mut self, page: VizPage) {
        self.scene_page = page;
        self.shell_view = ShellView::Scene(page);
        self.log(
            "scene",
            format!("security-viz — {} · Tab cycles pages · esc back", page.label()),
        );
    }

    /// Auto-switch to a gallery page when its artifact lands, unless the
    /// operator opted out via `KUZUSHI_AUTO_OPEN_VIZ=false`. Mirrors
    /// `auto_open_activity`.
    pub(crate) fn auto_open_viz_page(&mut self, page: VizPage) {
        if self.auto_open_viz {
            self.open_scene_to_page(page);
        }
    }

    /// Whether `page` has a backing artifact worth showing. Guards auto-open so
    /// a tool run that produced nothing (clean scan, zero-flow hunt) doesn't
    /// yank the operator to an empty page that reads "run the tool".
    pub(crate) fn viz_page_has_content(&self, page: VizPage) -> bool {
        match page {
            VizPage::AttackPath => self.taint_flow.is_some(),
            VizPage::ExploitChain => !self.exploit_chains.is_empty(),
            VizPage::Dfd => crate::ui_view_models::dfd_model(self).empty_hint.is_none(),
            VizPage::Heatmap | VizPage::AttackSurface => !self.findings.is_empty(),
        }
    }

    /// Switch to a specific gallery page and reflect it in the open view.
    pub fn set_scene_page(&mut self, page: VizPage) {
        self.scene_page = page;
        if matches!(self.shell_view, ShellView::Scene(_)) {
            self.shell_view = ShellView::Scene(page);
        }
    }
}
