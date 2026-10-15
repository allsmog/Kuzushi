use super::view_keybinding_groups::{
    activity_keybindings, actor_detail_keybindings, campaign_keybindings, catalog_keybindings,
    home_keybindings, prompts_editor_keybindings, recommend_keybindings, threat_keybindings,
    tune_keybindings, workbench_keybindings,
};
use super::view_keybinding_helpers::{
    back_keybinding, bind, bind_char, pause_scan_keybindings, resume_scan_keybindings,
    scroll_keybindings,
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

    /// The key the composed keymap dispatches `Back` from in `view` — the same
    /// list `handle_view_hotkey` searches — so a footer can advertise the real
    /// binding instead of a hardcoded literal. `None` when the view owns Esc
    /// itself and therefore offers no back affordance.
    pub(crate) fn view_back_key(&self, view: ShellView) -> Option<String> {
        self.view_keybindings_for_view(view)
            .into_iter()
            .find(|binding| binding.action == ViewHotkeyAction::Back)
            .map(|binding| binding.hint)
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
            ShellView::Relationships => relationship_keybindings(),
            ShellView::Campaign => self.campaign_view_keybindings(),
            ShellView::RunDiff => vec![
                bind(
                    HotkeyTrigger::Tab,
                    "Tab",
                    "findings / sources",
                    ViewHotkeyAction::RunDiffToggleSources,
                ),
                bind(
                    HotkeyTrigger::BackTab,
                    "Shift+Tab",
                    "findings / sources",
                    ViewHotkeyAction::RunDiffToggleSources,
                ),
            ],
            ShellView::Catalog => catalog_keybindings(self.router.catalog().is_expanded()),
            ShellView::Home => home_keybindings(),
            ShellView::Workbench => workbench_keybindings(self),
            ShellView::Recommend => recommend_keybindings(
                !crate::ui_view_models::recommendation_components(self).is_empty(),
            ),
            ShellView::Threat => threat_keybindings(),
            ShellView::ModuleRun => self.module_run_keybindings(),
            ShellView::ActorDetail => actor_detail_keybindings(),
            ShellView::PromptsEditor => prompts_editor_keybindings(),
            ShellView::Tune => tune_keybindings(),
            ShellView::Activity => self.activity_view_keybindings(),
            ShellView::Auth => vec![bind_char('q', "q", "back", ViewHotkeyAction::Back)],
            ShellView::Logs => logs_keybindings(),
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

    fn campaign_view_keybindings(&self) -> Vec<ViewKeybinding> {
        let mut bindings = campaign_keybindings();
        if self.selected_fixed_study_has_ended() {
            if let Some(binding) = bindings
                .iter_mut()
                .find(|binding| binding.action == ViewHotkeyAction::CampaignLaunch)
            {
                binding.label = "new plan required".into();
            }
        }
        bindings
    }

    /// Generic line/edge scrolling applies to scrollable views except those
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

#[cfg(test)]
mod keymap_collision_tests {
    use super::super::view_keybinding_groups::activity_keybindings;
    use super::super::view_keybinding_helpers::{
        pause_scan_keybindings, resume_scan_keybindings, scroll_keybindings,
    };
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn empty_campaign_keeps_the_existing_launch_binding() {
        let app = ShellApp::new(V2Config::default(), None);
        let binding = app
            .view_keybindings_for_view(ShellView::Campaign)
            .into_iter()
            .find(|binding| binding.action == ViewHotkeyAction::CampaignLaunch)
            .unwrap();
        assert_eq!(binding.label, "launch");
    }

    /// Dispatch is first-match over the composed list, so a duplicate trigger
    /// silently shadows everything after it. Shadowing the shared scroll base
    /// or the universal Esc-back is the documented rebind pattern; any other
    /// duplicate is an accidental collision the operator cannot discover.
    fn assert_no_accidental_collisions(context: &str, binds: &[ViewKeybinding]) {
        for (index, binding) in binds.iter().enumerate() {
            for shadowed in binds[index + 1..]
                .iter()
                .filter(|later| later.trigger == binding.trigger)
                .filter(|later| later.action != binding.action)
            {
                assert!(
                    matches!(
                        shadowed.action,
                        ViewHotkeyAction::ViewScrollUp
                            | ViewHotkeyAction::ViewScrollDown
                            | ViewHotkeyAction::ViewScrollTop
                            | ViewHotkeyAction::ViewScrollBottom
                            | ViewHotkeyAction::ViewPageUp
                            | ViewHotkeyAction::ViewPageDown
                            | ViewHotkeyAction::Back
                    ),
                    "{context}: {:?} binds {:?} but silently shadows {:?}; \
                     only the shared scroll base / Esc-back may be rebound",
                    binding.trigger,
                    binding.action,
                    shadowed.action,
                );
            }
        }
    }

    #[test]
    fn every_view_keymap_is_free_of_accidental_collisions() {
        let app = ShellApp::new(V2Config::default(), None);
        let views = [
            ShellView::Home,
            ShellView::Catalog,
            ShellView::Recommend,
            ShellView::ModuleRun,
            ShellView::Workbench,
            ShellView::Tune,
            ShellView::Threat,
            ShellView::PromptsEditor,
            ShellView::ActorDetail,
            ShellView::Activity,
            ShellView::Campaign,
            ShellView::Coverage,
            ShellView::Runs,
            ShellView::Jobs,
            ShellView::Replay,
            ShellView::Trace,
            ShellView::Logs,
            ShellView::Help,
        ];
        for view in views {
            let binds = app.view_keybindings_for_view(view);
            assert_no_accidental_collisions(&format!("{view:?}"), &binds);
        }
    }

    #[test]
    fn map_and_threat_views_bind_model_head_cycling() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Map));

        for view in [ShellView::Workbench, ShellView::Threat] {
            let binds = app.view_keybindings_for_view(view);
            assert!(binds.iter().any(|binding| {
                binding.trigger == HotkeyTrigger::Char('m')
                    && binding.action == ViewHotkeyAction::ThreatModelNext
            }));
            assert!(binds.iter().any(|binding| {
                binding.trigger == HotkeyTrigger::Char('M')
                    && binding.action == ViewHotkeyAction::ThreatModelPrevious
            }));
        }
    }

    /// The backlog preset arms eight extra one-key decisions on the Review
    /// page — the densest keymap in the shell and the one where a collision
    /// would record a wrong review decision.
    #[test]
    fn review_backlog_keymap_is_free_of_accidental_collisions() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Review));
        app.router.workbench_mut().review_mut().backlog = true;

        let binds = app.view_keybindings_for_view(ShellView::Workbench);

        assert_no_accidental_collisions("Workbench/Review+backlog", &binds);
        assert_eq!(
            binds
                .iter()
                .find(|binding| binding.trigger == HotkeyTrigger::Char('t'))
                .unwrap()
                .action,
            ViewHotkeyAction::WorkbenchBacklogToolCycle
        );
        assert_eq!(
            binds
                .iter()
                .find(|binding| binding.trigger == HotkeyTrigger::Char('T'))
                .unwrap()
                .action,
            ViewHotkeyAction::WorkbenchTraceView
        );
        // The decisions the preset advertises must actually be armed.
        for key in ['c', 'f', 'd', 'w', 'u'] {
            assert!(
                binds
                    .iter()
                    .any(|binding| binding.trigger == HotkeyTrigger::Char(key)),
                "backlog decision key {key:?} missing from the composed keymap"
            );
        }
    }

    /// The pause/resume overlays join Activity's extras conditionally at
    /// runtime; compose the maximal union statically so a future extra can
    /// never collide with `p`/`P`/`r`/`R` unnoticed.
    #[test]
    fn scan_pause_resume_overlays_never_collide_with_activity_extras() {
        let mut binds = activity_keybindings();
        binds.extend(pause_scan_keybindings());
        binds.extend(resume_scan_keybindings());
        binds.extend(scroll_keybindings());

        assert_no_accidental_collisions("Activity+pause+resume", &binds);
    }
}
