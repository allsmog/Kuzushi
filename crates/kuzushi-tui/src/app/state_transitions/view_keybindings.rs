use super::view_keybinding_groups::{
    activity_keybindings, actor_detail_keybindings, campaign_keybindings, catalog_keybindings, home_keybindings,
    prompts_editor_keybindings, recommend_keybindings, threat_keybindings, tune_keybindings,
    workbench_keybindings,
};
use super::view_keybinding_helpers::{
    back_keybinding, bind, pause_scan_keybindings, resume_scan_keybindings, scroll_keybindings,
};
use super::*;

impl ShellApp {
    /// Compose the active view's keybindings from three layers: per-view
    /// extras, the shared scroll base (for generically-scrollable views), and
    /// the universal `Esc back` affordance. Per-view extras come first so a
    /// view that rebinds a base key (e.g. Findings `j`) wins via first-match.
    pub(crate) fn view_keybindings(&self) -> Vec<ViewKeybinding> {
        self.view_keybindings_for_view(self.shell_view())
    }

    pub(crate) fn view_keybindings_for_view(&self, view: ShellView) -> Vec<ViewKeybinding> {
        let mut binds = self.view_specific_keybindings(view);
        if self.view_uses_scroll_base(view) {
            binds.extend(scroll_keybindings());
        }
        if self.view_offers_back(view) {
            binds.push(back_keybinding());
        }
        self.ui.apply_keymap_overrides(view, binds)
    }

    pub(crate) fn workbench_view_keybindings_for_plan(
        &self,
        plan: Option<&crate::ui_view_models::PhasePresentationPlan>,
    ) -> Vec<ViewKeybinding> {
        let bindings = workbench_keybindings_for_plan(self, plan);
        self.ui
            .apply_keymap_overrides(ShellView::Workbench, bindings)
    }

    fn view_specific_keybindings(&self, view: ShellView) -> Vec<ViewKeybinding> {
        match view {
            ShellView::Campaign => campaign_keybindings(),
            ShellView::Catalog => catalog_keybindings(),
            ShellView::Home => home_keybindings(),
            ShellView::Workbench => workbench_keybindings(self),
            ShellView::Recommend => recommend_keybindings(),
            ShellView::Threat => threat_keybindings(),
            ShellView::ModuleRun => self.module_run_keybindings(),
            ShellView::ActorDetail => actor_detail_keybindings(),
            ShellView::PromptsEditor => prompts_editor_keybindings(),
            ShellView::Tune => tune_keybindings(),
            ShellView::Activity => self.activity_view_keybindings(),
            _ => Vec::new(),
        }
    }

    fn activity_view_keybindings(&self) -> Vec<ViewKeybinding> {
        let mut bindings = activity_keybindings();
        if self.can_pause_scan_hotkey() {
            bindings.extend(pause_scan_keybindings());
        }
        if self.can_resume_scan_hotkey() {
            bindings.extend(resume_scan_keybindings());
        }
        bindings
    }

    /// Generic `j/k/g/G` scrolling applies to scrollable views except those
    /// that drive a bespoke cursor (Catalog and the Workbench's pane-aware
    /// focus own their keys).
    fn view_uses_scroll_base(&self, view: ShellView) -> bool {
        self.is_view_scrollable(view) && !matches!(view, ShellView::Catalog | ShellView::Workbench)
    }

    /// Esc goes back everywhere except views that already own Esc
    /// (pickers/modals intercept Esc earlier). Cleared prompt drafts are
    /// restored explicitly with Ctrl+_ / Ctrl+/ so Esc stays navigation.
    fn view_offers_back(&self, view: ShellView) -> bool {
        !self.view_owns_esc(view)
    }

    fn view_owns_esc(&self, view: ShellView) -> bool {
        matches!(
            view,
            ShellView::CommandPalette
                | ShellView::PlanningPicker
                | ShellView::TargetPicker
                | ShellView::Setup
        )
    }

    pub(super) fn module_run_keybindings(&self) -> Vec<ViewKeybinding> {
        let mut bindings = (1..=4)
            .map(|index| {
                bind(
                    HotkeyTrigger::Char(char::from_digit(index as u32, 10).unwrap()),
                    "1..4",
                    "actor",
                    ViewHotkeyAction::ActorDetail(index),
                )
            })
            .collect::<Vec<_>>();
        if self.can_pause_scan_hotkey() {
            bindings.extend(pause_scan_keybindings());
        }
        if self.can_resume_scan_hotkey() {
            bindings.extend(resume_scan_keybindings());
        }
        bindings
    }

    pub(super) fn can_pause_scan_hotkey(&self) -> bool {
        self.scan().is_some_and(|scan| scan.running)
            && self.scan_cancel_token().is_some()
            && !self.is_scan_paused()
    }

    pub(super) fn can_resume_scan_hotkey(&self) -> bool {
        self.scan().is_some_and(|scan| scan.running)
            && self.scan_cancel_token().is_some()
            && self.is_scan_paused()
    }
}
