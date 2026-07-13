use super::*;
use crate::scene3d::VizPage;
use std::path::{Component, Path};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusedWorkbenchVisualization {
    Scene(VizPage),
    ProofReplay,
}

impl ShellApp {
    pub(super) fn handle_view_hotkey(&mut self, key: KeyEvent) -> InputUpdate {
        if let Some(handled) = self.handle_workbench_depth_key(key) {
            return InputUpdate::handled_if(handled);
        }
        let Some(binding) = self
            .view_keybindings()
            .into_iter()
            .find(|binding| binding.matches(key))
        else {
            return InputUpdate::handled_if(self.handle_generic_scroll_hotkey(key));
        };
        let char_trigger = binding.trigger.is_char();
        let update = self.apply_view_hotkey(binding.action);
        if update.handled && char_trigger {
            self.ui_mut().record_operator_interaction(Instant::now());
        }
        update
    }

    pub(super) fn apply_view_hotkey(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        if let Some(update) = self.apply_workbench_hotkey(action) {
            return update;
        }
        self.apply_focused_view_hotkey(action)
    }

    /// The `bool`-returning handlers, tried in order; each mutates and reports
    /// whether it claimed the action (short-circuit, like the `if` chain).
    fn apply_focused_view_hotkey(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        for handler in FOCUSED_HOTKEY_HANDLERS {
            let update = handler(self, action);
            if update.handled {
                return update;
            }
        }
        self.apply_shell_hotkey(action)
    }

    /// Pane-aware Workbench navigation: `Tab` cycles focus, `j/k` or arrows
    /// move within the focused pane (FINDINGS cursor, or other pane scroll),
    /// `g/G` jump, and `Enter` selects the cursored finding.
    fn apply_workbench_hotkey(&mut self, action: ViewHotkeyAction) -> Option<InputUpdate> {
        match action {
            ViewHotkeyAction::WorkbenchCyclePane => self.cycle_workbench_pane(false),
            ViewHotkeyAction::WorkbenchCyclePanePrev => self.cycle_workbench_pane(true),
            ViewHotkeyAction::WorkbenchScrollNext => self.workbench_move(1),
            ViewHotkeyAction::WorkbenchScrollPrev => self.workbench_move(-1),
            ViewHotkeyAction::WorkbenchScrollFirst => self.workbench_jump(true),
            ViewHotkeyAction::WorkbenchScrollLast => self.workbench_jump(false),
            ViewHotkeyAction::WorkbenchToggleCenter => self.toggle_workbench_center_mode(),
            ViewHotkeyAction::WorkbenchCenterNext => self.cycle_workbench_center_mode(1),
            ViewHotkeyAction::WorkbenchCenterPrev => self.cycle_workbench_center_mode(-1),
            ViewHotkeyAction::WorkbenchOpenFocusedVisualization => {
                self.open_workbench_focused_viz()
            }
            ViewHotkeyAction::WorkbenchTogglePaneZoom => self.toggle_workbench_pane_zoom(),
            ViewHotkeyAction::WorkbenchOpen => self.workbench_open_focused(),
            ViewHotkeyAction::WorkbenchPageNext => {
                self.set_workbench_page(crate::ui_view_models::active_workbench_page(self).next())
            }
            ViewHotkeyAction::WorkbenchPagePrev => {
                self.set_workbench_page(crate::ui_view_models::active_workbench_page(self).prev())
            }
            ViewHotkeyAction::WorkbenchPage(page) => self.set_workbench_page(page),
            ViewHotkeyAction::WorkbenchValidate => return Some(self.draft_workbench_validation()),
            ViewHotkeyAction::WorkbenchSuppress => return Some(self.draft_workbench_suppression()),
            ViewHotkeyAction::WorkbenchOrderChain => return Some(self.draft_workbench_chain()),
            ViewHotkeyAction::WorkbenchCluster => self.open_workbench_coverage_clusters(),
            ViewHotkeyAction::Back if self.focus_workbench_findings_before_back() => {}
            _ => return None,
        }
        Some(InputUpdate::handled())
    }

    /// Depth-stack review keys (opt-in `ui.workbench_depth_stack`). Returns
    /// `Some(true)` when the depth stack consumed the key, `None` to fall
    /// through to the standard view keybindings — so `Esc` at the list root
    /// still leaves the view, while inner depths unwind first.
    fn handle_workbench_depth_key(&mut self, key: KeyEvent) -> Option<bool> {
        if !self.workbench_depth_stack_active() {
            return None;
        }
        let bounds =
            crate::ui_view_models::workbench_depth_bounds(self, self.router.workbench().nav());
        match self.router.workbench_mut().nav_mut().apply_key(key, bounds) {
            NavEffect::Ignored | NavEffect::Leave => None,
            NavEffect::Handled => Some(true),
            NavEffect::SelectStep(delta) => {
                self.step_findings_cursor(delta);
                Some(true)
            }
            NavEffect::SelectJump(to_start) => {
                self.jump_findings_selection(to_start);
                Some(true)
            }
            NavEffect::Yank => {
                self.log("workbench", "record zoom (z) holds the full text");
                Some(true)
            }
        }
    }

    fn workbench_depth_stack_active(&self) -> bool {
        self.router.workbench().depth_stack()
            && self.shell_view() == ShellView::Workbench
            && self.workbench_is_review_page()
    }

    fn jump_findings_selection(&mut self, to_start: bool) {
        let len = crate::ui_view_models::visible_findings_len(self);
        self.router.findings_mut().jump(to_start, len);
        self.reset_workbench_detail_scroll();
    }

    fn set_workbench_page(&mut self, page: WorkbenchPage) {
        let viewport = self.viewport();
        let workbench = self.router.workbench_mut();
        workbench.set_page(Some(page));
        workbench.scroll_mut().set(WorkbenchPane::Center, 0);
        workbench.set_focus(page.primary_pane_for_viewport(viewport.columns, viewport.rows));
        self.set_shell_view(ShellView::Workbench);
        self.log(
            "workbench",
            format!(
                "page {} · {}",
                page.position(),
                page.title().to_ascii_lowercase()
            ),
        );
    }

    fn cycle_workbench_pane(&mut self, reverse: bool) {
        let page = crate::ui_view_models::active_workbench_page(self);
        let current = self.router.workbench().focus();
        let viewport = self.viewport();
        let next = page.next_interactive_pane_for_viewport(
            self.router.workbench().center_mode(),
            current,
            reverse,
            viewport.columns,
            viewport.rows,
        );
        self.router.workbench_mut().set_focus(next);
    }

    fn toggle_workbench_center_mode(&mut self) {
        self.router.workbench_mut().toggle_center_mode();
        self.normalize_workbench_focus();
    }

    fn cycle_workbench_center_mode(&mut self, direction: i32) {
        self.router.workbench_mut().cycle_center_mode(direction);
    }

    fn open_workbench_focused_viz(&mut self) {
        let page = crate::ui_view_models::active_workbench_page(self);
        let pane = self.normalize_workbench_focus();
        match focused_workbench_visualization(page, pane) {
            FocusedWorkbenchVisualization::Scene(scene) => self.open_scene_to_page(scene),
            FocusedWorkbenchVisualization::ProofReplay => self.open_confirm_proof_replay(),
        }
    }

    fn open_confirm_proof_replay(&mut self) {
        let model = crate::ui_view_models::phase_cockpit_model_for_phase(
            self,
            kuzushi_core::WorkflowPhase::Confirm,
        );
        let crate::ui_view_models::PhaseCockpitBody::Confirm(confirm) = model.body else {
            return;
        };
        let Some(run_id) = confirm.proof.and_then(|proof| proof.replay_run_id) else {
            self.log(
                "workbench",
                "proof replay unavailable — run `verify <finding>` to record replayable proof",
            );
            return;
        };
        self.push_nav_history(self.shell_view());
        self.router.replay_mut().open(run_id.clone());
        self.set_shell_view(ShellView::Replay);
        self.log("replay", run_id);
    }

    fn toggle_workbench_pane_zoom(&mut self) {
        self.normalize_workbench_focus();
        self.router.workbench_mut().toggle_zoom();
    }

    fn normalize_workbench_focus(&mut self) -> WorkbenchPane {
        let page = crate::ui_view_models::active_workbench_page(self);
        let current = self.router.workbench().focus();
        let viewport = self.viewport();
        let pane_order = page.interactive_panes_for_viewport(
            self.router.workbench().center_mode(),
            viewport.columns,
            viewport.rows,
        );
        if pane_order.contains(&current) {
            return current;
        }
        let primary = page.primary_pane_for_viewport(viewport.columns, viewport.rows);
        self.router.workbench_mut().set_focus(primary);
        primary
    }

    fn focus_workbench_findings_before_back(&mut self) -> bool {
        if self.shell_view() != ShellView::Workbench
            || self.router.workbench().focus() != WorkbenchPane::Details
        {
            return false;
        }
        let page = crate::ui_view_models::active_workbench_page(self);
        let focus = page.primary_pane();
        self.router.workbench_mut().set_focus(focus);
        self.log(
            "workbench",
            format!(
                "returned to {} — Esc again to leave",
                page.title().to_ascii_lowercase()
            ),
        );
        true
    }

    fn workbench_move(&mut self, delta: isize) {
        match self.normalize_workbench_focus() {
            WorkbenchPane::Findings => self.step_findings_cursor(delta),
            WorkbenchPane::Source | WorkbenchPane::Center | WorkbenchPane::Details => {
                self.scroll_by_delta(delta)
            }
        }
    }

    fn scroll_by_delta(&mut self, delta: isize) {
        if delta >= 0 {
            self.scroll_down(1);
        } else {
            self.scroll_up(1);
        }
    }

    fn step_findings_cursor(&mut self, delta: isize) {
        let len = crate::ui_view_models::visible_findings_len(self);
        self.router.findings_mut().step_direction(delta, len);
        self.reset_workbench_detail_scroll();
    }

    fn workbench_jump(&mut self, to_start: bool) {
        match self.normalize_workbench_focus() {
            WorkbenchPane::Findings => {
                let len = crate::ui_view_models::visible_findings_len(self);
                self.router.findings_mut().jump(to_start, len);
                self.reset_workbench_detail_scroll();
            }
            WorkbenchPane::Source | WorkbenchPane::Center | WorkbenchPane::Details => {
                self.jump_scroll_region(to_start);
            }
        }
    }

    fn jump_scroll_region(&mut self, to_start: bool) {
        if to_start {
            self.scroll_to_top();
        } else {
            self.scroll_to_bottom();
        }
    }

    fn workbench_open_focused(&mut self) {
        let page = crate::ui_view_models::active_workbench_page(self);
        match self.normalize_workbench_focus() {
            WorkbenchPane::Center => self.open_workbench_focused_viz(),
            WorkbenchPane::Findings if page == WorkbenchPage::Coverage => {
                let can_open = crate::ui_view_models::visible_finding_at_cursor(self).is_some();
                if can_open {
                    self.set_workbench_page(WorkbenchPage::Review);
                }
                // Open after the page transition so finding detail remains
                // focused; otherwise `set_workbench_page` resets focus to the
                // Confirm composition's primary CENTER pane.
                self.open_workbench_finding_or_log();
            }
            WorkbenchPane::Findings => self.open_workbench_finding_or_log(),
            WorkbenchPane::Source | WorkbenchPane::Details => {}
        }
    }

    fn workbench_is_review_page(&self) -> bool {
        crate::ui_view_models::active_workbench_page(self) == WorkbenchPage::Review
    }

    fn open_workbench_finding_or_log(&mut self) {
        if self.findings().is_empty() {
            self.log("findings", "no findings yet — run `scan` first");
            return;
        }
        self.open_finding_at_cursor();
    }

    fn draft_workbench_validation(&mut self) -> InputUpdate {
        let Some(finding) = self.current_workbench_finding() else {
            self.log(
                "verify",
                "no finding selected — open REVIEW and choose a finding first",
            );
            return InputUpdate::handled();
        };
        let input = serde_json::json!({ "fingerprint": finding.fingerprint }).to_string();
        self.set_input(format!("run verify:exploit {input}"));
        self.set_input_mode(InputMode::Prompt);
        self.log("verify", "draft loaded — press Enter to start verification");
        InputUpdate::handled()
    }

    fn draft_workbench_suppression(&mut self) -> InputUpdate {
        let Some((alias, finding)) = crate::ui_view_models::current_finding_for_detail(self) else {
            self.log("suppress", "no finding selected — choose a finding first");
            return InputUpdate::handled();
        };
        let reference = alias.unwrap_or(finding.fingerprint);
        self.set_input(format!("suppress {reference} --reason "));
        self.set_input_mode(InputMode::Prompt);
        self.log("suppress", "draft loaded — enter a reason and submit");
        InputUpdate::handled()
    }

    fn reset_workbench_detail_scroll(&mut self) {
        self.router
            .workbench_mut()
            .scroll_mut()
            .set(WorkbenchPane::Details, 0);
    }

    fn draft_workbench_chain(&mut self) -> InputUpdate {
        self.set_input("run exploit-chain:scan {}".to_string());
        self.set_input_mode(InputMode::Prompt);
        self.log(
            "chain",
            "draft loaded — press Enter to start exploit-chain analysis",
        );
        InputUpdate::handled()
    }

    fn reduce_hotkey_command(&mut self, command: ShellCommand) -> InputUpdate {
        let update = self.reduce_command_message(command);
        if update.handled {
            InputUpdate::handled_with_effects(update.effects)
        } else {
            InputUpdate::ignored()
        }
    }

    fn open_workbench_coverage_clusters(&mut self) {
        self.set_workbench_page(WorkbenchPage::Coverage);
        self.log(
            "cluster",
            "coverage groups duplicates and root-cause clusters without hiding distinct sinks",
        );
    }

    fn current_workbench_finding(&self) -> Option<Finding> {
        crate::ui_view_models::current_finding_for_detail(self).map(|(_, finding)| finding)
    }

    fn apply_scroll_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        match action {
            ViewHotkeyAction::ViewScrollUp => self.scroll_current_view_up(1),
            ViewHotkeyAction::ViewScrollDown => self.scroll_current_view_down(1),
            ViewHotkeyAction::ViewScrollTop => self.scroll_current_view_to_top(),
            ViewHotkeyAction::ViewScrollBottom => self.scroll_current_view_to_bottom(),
            ViewHotkeyAction::ViewPageUp => self.page_up_current_view(),
            ViewHotkeyAction::ViewPageDown => self.page_down_current_view(),
            _ => return false,
        }
        true
    }

    fn apply_scroll_hotkey_update(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        if self.apply_scroll_hotkey(action) {
            InputUpdate::handled()
        } else {
            InputUpdate::ignored()
        }
    }

    fn apply_recommend_hotkey(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        match action {
            ViewHotkeyAction::RecommendCursorPrevious => {
                self.move_recommend_cursor(-1);
                InputUpdate::handled()
            }
            ViewHotkeyAction::RecommendCursorNext => {
                self.move_recommend_cursor(1);
                InputUpdate::handled()
            }
            ViewHotkeyAction::RecommendScanComponent => self.scan_recommend_component(),
            ViewHotkeyAction::RecommendPromoteComponent => self.promote_recommend_component(),
            _ => InputUpdate::ignored(),
        }
    }

    fn move_recommend_cursor(&mut self, delta: isize) {
        let count = crate::ui_view_models::recommendation_components(self).len();
        if count == 0 {
            self.router.catalog_mut().reset_recommend_cursor();
            self.log(
                "component",
                "no component recommendations yet — run `recommend` first",
            );
            return;
        }
        self.router
            .catalog_mut()
            .move_recommend_cursor(delta, count);
    }

    fn scan_recommend_component(&mut self) -> InputUpdate {
        let Some(component) = self.selected_recommend_component() else {
            self.log(
                "component",
                "no component selected — run `recommend` to rank components first",
            );
            return InputUpdate::handled();
        };
        self.log(
            "component",
            format!(
                "scanning {} as {} within the current target",
                component.rel_path, component.class_label
            ),
        );
        self.reduce_hotkey_command(ShellCommand::RunTool {
            tool: Some("sast:scan".to_string()),
            input: component.scan_input.clone(),
        })
    }

    fn promote_recommend_component(&mut self) -> InputUpdate {
        let Some(component) = self.selected_recommend_component() else {
            self.log(
                "component",
                "no component selected — run `recommend` to rank components first",
            );
            return InputUpdate::handled();
        };
        if component.promote_command.is_none() {
            self.log(
                "component",
                format!(
                    "{} is best scanned inside the current target",
                    component.rel_path
                ),
            );
            return InputUpdate::handled();
        }
        let Some(target_path) = self.recommend_component_target_path(&component.rel_path) else {
            self.log(
                "component",
                "promotion needs an active target and target-relative component path",
            );
            return InputUpdate::handled();
        };
        let effects = self.request_target_activation(TargetActivation {
            path: target_path,
            selected_scope: None,
            source: TargetActivationSource::Command,
        });
        if effects.is_empty() {
            return InputUpdate::handled();
        }
        self.log(
            "component",
            format!("promoted {} to its own target", component.rel_path),
        );
        InputUpdate::handled_with_effects(effects)
    }

    fn selected_recommend_component(
        &mut self,
    ) -> Option<crate::ui_view_models::ComponentRecommendationRow> {
        let components = crate::ui_view_models::recommendation_components(self);
        let selected = self
            .router
            .catalog_mut()
            .selected_recommend_cursor(components.len());
        components.get(selected).cloned()
    }

    fn recommend_component_target_path(&self, rel_path: &str) -> Option<PathBuf> {
        let target = self.target_path_buf()?;
        let rel = Self::target_relative_component_path(rel_path)?;
        Some(target.join(rel))
    }

    fn target_relative_component_path(rel_path: &str) -> Option<PathBuf> {
        let trimmed = rel_path.trim_matches('/');
        let path = Path::new(trimmed);
        let relative = !trimmed.is_empty()
            && path
                .components()
                .all(|component| matches!(component, Component::Normal(_)));
        relative.then(|| path.to_path_buf())
    }

    fn apply_prompt_or_tune_hotkey(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        match action {
            ViewHotkeyAction::TuneCursorPrevious => {
                self.move_tune_cursor(-1);
                InputUpdate::handled()
            }
            ViewHotkeyAction::TuneCursorNext => {
                self.move_tune_cursor(1);
                InputUpdate::handled()
            }
            ViewHotkeyAction::TuneActivate => {
                InputUpdate::handled_with_effects(self.activate_tune_action())
            }
            ViewHotkeyAction::PromptsCursorPrevious => {
                self.move_prompts_cursor(-1);
                InputUpdate::handled()
            }
            ViewHotkeyAction::PromptsCursorNext => {
                self.move_prompts_cursor(1);
                InputUpdate::handled()
            }
            ViewHotkeyAction::PromptsAction(action) => {
                InputUpdate::handled_with_effects(self.activate_prompts_action(action))
            }
            _ => InputUpdate::ignored(),
        }
    }

    fn apply_actor_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        match action {
            ViewHotkeyAction::ActorDetail(index) => {
                self.router.actor_detail_mut().open(index);
                self.set_shell_view(ShellView::ActorDetail);
            }
            ViewHotkeyAction::ActorDetailFilterCycle => {
                self.router.actor_detail_mut().cycle_filter();
            }
            ViewHotkeyAction::ActorDetailFilterReset => {
                self.router.actor_detail_mut().reset_filter();
            }
            _ => return false,
        }
        true
    }

    fn apply_actor_hotkey_update(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        if self.apply_actor_hotkey(action) {
            InputUpdate::handled()
        } else {
            InputUpdate::ignored()
        }
    }

    fn apply_shell_hotkey(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        if self.apply_activity_hotkey(action) {
            return InputUpdate::handled();
        }
        match action {
            ViewHotkeyAction::CatalogActivate => self.load_catalog_action(),
            ViewHotkeyAction::CatalogToggleExpert => self.toggle_catalog_expert(),
            ViewHotkeyAction::ThreatView(view) => {
                self.router.threat_mut().open(view);
                self.set_shell_view(ShellView::Threat);
                InputUpdate::handled()
            }
            ViewHotkeyAction::PauseScan => self.reduce_hotkey_command(ShellCommand::Pause),
            ViewHotkeyAction::ResumeScan => self.reduce_hotkey_command(ShellCommand::Resume(None)),
            ViewHotkeyAction::OpenNextPhase => self.reduce_hotkey_command(ShellCommand::Next),
            ViewHotkeyAction::Back => {
                self.go_back();
                InputUpdate::handled()
            }
            _ => InputUpdate::ignored(),
        }
    }

    fn load_catalog_action(&mut self) -> InputUpdate {
        if self.target().is_none() {
            self.open_target_picker();
            return InputUpdate::handled();
        }
        let Some(command) = self.catalog_cursor_command() else {
            self.log("capability", "no capability action is available");
            return InputUpdate::handled();
        };
        self.set_input(command.clone());
        self.set_input_mode(InputMode::Prompt);
        self.log(
            "capability",
            format!("loaded `{}` — edit if needed, then submit", command.trim()),
        );
        InputUpdate::handled()
    }

    fn toggle_catalog_expert(&mut self) -> InputUpdate {
        self.router.catalog_mut().toggle_expanded();
        let message = if self.router.catalog().is_expanded() {
            "showing expert engines and installed integrations"
        } else {
            "showing phase-native actions"
        };
        self.log("capability", message);
        InputUpdate::handled()
    }

    fn apply_activity_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        if self.apply_activity_session_hotkey(action) {
            return true;
        }
        match action {
            ViewHotkeyAction::ActivityReset => self.reset_activity_view(),
            ViewHotkeyAction::ActivityFocusSelected => self.open_or_focus_activity_task(),
            ViewHotkeyAction::ActivityOpenDeckArtifact => self.open_activity_deck_artifact(),
            ViewHotkeyAction::ActivityOpenFindings => self.open_activity_findings_review(),
            ViewHotkeyAction::ActivityBackground => self.background_handoff(),
            _ => return false,
        }
        true
    }

    fn apply_activity_session_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        if matches!(action, ViewHotkeyAction::ActivityTabPaneFocus)
            && self
                .activity()
                .is_some_and(|session| session.tasks.is_empty())
        {
            self.log(
                "activity",
                "no task rows to focus; output is already full width",
            );
            return true;
        }
        let Some(session) = self.activity() else {
            return false;
        };
        let event_count = session.events.len();
        let route = self.router.activity_mut();
        match action {
            ViewHotkeyAction::ActivityTabPaneFocus => route.toggle_pane_focus(),
            ViewHotkeyAction::ActivityToggleVerbose => route.toggle_verbose_subsystems(),
            ViewHotkeyAction::ActivityTogglePause => route.toggle_paused(event_count),
            ViewHotkeyAction::ActivityDeckNext => route.next_deck_page(),
            ViewHotkeyAction::ActivityDeckPrev => route.prev_deck_page(),
            _ => return false,
        };
        true
    }

    fn reset_activity_view(&mut self) {
        if self.activity().is_none() {
            self.log("activity", "no Activity view state to reset");
            return;
        }
        self.router.activity_mut().reset_presentation_state();
        self.log("activity", "reset Activity view state; run preserved");
    }

    fn open_activity_deck_artifact(&mut self) {
        if self.activity().is_none() {
            self.log("activity", "no active run output to open");
            return;
        }
        let page = self.router.activity().deck_page;
        match page {
            ActivityDeckPage::Findings => self.open_activity_findings_review(),
            ActivityDeckPage::Recon => self.open_activity_recon_detail(),
            page => match page.scene_page() {
                Some(scene_page) => self.open_scene_to_page(scene_page),
                None => self.log("activity", "this output view has no full visualization"),
            },
        }
    }

    fn open_activity_recon_detail(&mut self) {
        if !matches!(self.shell_view(), ShellView::Module) {
            self.push_nav_history(self.shell_view());
        }
        self.set_focused_module(Some("recon".to_string()));
        self.set_shell_view(ShellView::Module);
        self.log(
            "activity",
            "opened full recon detail; use back to return to the run",
        );
    }

    fn open_activity_findings_review(&mut self) {
        self.select_activity_deck_finding();
        self.open_workbench(WorkbenchPane::Findings);
        self.log(
            "activity",
            "opened findings review from Activity; use back to return to the run",
        );
    }

    fn select_activity_deck_finding(&mut self) {
        if self.activity().is_none()
            || self.router.activity().deck_page != ActivityDeckPage::Findings
        {
            return;
        }
        let cursor = self.router.activity().deck_cursor;
        let visible_len = crate::ui_view_models::visible_findings_len(self);
        if visible_len == 0 {
            return;
        }
        let index = cursor.min(visible_len - 1);
        let Some((_, finding)) = crate::ui_view_models::visible_finding_at_index(self, index)
        else {
            return;
        };
        self.router.findings_mut().set_cursor(index);
        *self.selected_finding_mut() = Some(finding);
    }

    fn open_or_focus_activity_task(&mut self) {
        let Some(task_id) = self.focus_activity_task_at_cursor() else {
            self.log_activity_focus_unavailable();
            return;
        };
        let Some(page) = activity_task_deck_page(&task_id) else {
            self.log(
                "activity",
                format!("focused {task_id}; no generated output view yet"),
            );
            return;
        };
        let route = self.router.activity_mut();
        route.set_deck_page_by_user(page);
        route.pane_focus = PaneFocus::Right;
        self.log(
            "activity",
            format!("showing {task_id} output in the {} view", page.label()),
        );
    }

    fn log_activity_focus_unavailable(&mut self) {
        let message = match self.activity() {
            None => "no active run to focus",
            Some(session) if session.tasks.is_empty() => {
                "no task rows to focus; output is already full width"
            }
            Some(_) => "no visible task at the current cursor",
        };
        self.log("activity", message);
    }

    fn focus_activity_task_at_cursor(&mut self) -> Option<String> {
        let session = self.activity()?;
        if session.tasks.is_empty() {
            return None;
        }
        let task_id = self
            .router
            .activity()
            .task_id_at_cursor(session)?
            .to_string();
        self.router.activity_mut().focus_task = Some(task_id.clone());
        Some(task_id)
    }
}

fn focused_workbench_visualization(
    page: WorkbenchPage,
    pane: WorkbenchPane,
) -> FocusedWorkbenchVisualization {
    match page {
        WorkbenchPage::Terrain => FocusedWorkbenchVisualization::Scene(VizPage::AttackSurface),
        WorkbenchPage::Coverage => FocusedWorkbenchVisualization::Scene(VizPage::Heatmap),
        WorkbenchPage::Review => confirm_visualization(pane),
        WorkbenchPage::Ship => fix_visualization(pane),
    }
}

fn confirm_visualization(pane: WorkbenchPane) -> FocusedWorkbenchVisualization {
    if pane == WorkbenchPane::Details {
        FocusedWorkbenchVisualization::ProofReplay
    } else {
        FocusedWorkbenchVisualization::Scene(VizPage::AttackPath)
    }
}

fn fix_visualization(pane: WorkbenchPane) -> FocusedWorkbenchVisualization {
    if matches!(pane, WorkbenchPane::Source | WorkbenchPane::Center) {
        FocusedWorkbenchVisualization::Scene(VizPage::ExploitChain)
    } else {
        FocusedWorkbenchVisualization::Scene(VizPage::Dfd)
    }
}

#[cfg(test)]
mod phase_visualization_tests {
    use super::*;

    fn assert_visualization(
        page: WorkbenchPage,
        pane: WorkbenchPane,
        expected: FocusedWorkbenchVisualization,
    ) {
        assert_eq!(focused_workbench_visualization(page, pane), expected);
    }

    #[test]
    fn map_and_hunt_panes_open_phase_native_scenes() {
        assert_visualization(
            WorkbenchPage::Terrain,
            WorkbenchPane::Center,
            FocusedWorkbenchVisualization::Scene(VizPage::AttackSurface),
        );
        for pane in [WorkbenchPane::Source, WorkbenchPane::Details] {
            assert_visualization(
                WorkbenchPage::Coverage,
                pane,
                FocusedWorkbenchVisualization::Scene(VizPage::Heatmap),
            );
        }
    }

    #[test]
    fn confirm_flow_and_proof_panes_have_distinct_destinations() {
        for pane in [
            WorkbenchPane::Source,
            WorkbenchPane::Center,
            WorkbenchPane::Findings,
        ] {
            assert_visualization(
                WorkbenchPage::Review,
                pane,
                FocusedWorkbenchVisualization::Scene(VizPage::AttackPath),
            );
        }
        assert_visualization(
            WorkbenchPage::Review,
            WorkbenchPane::Details,
            FocusedWorkbenchVisualization::ProofReplay,
        );
    }

    #[test]
    fn fix_tree_and_dfd_panes_open_matching_scenes() {
        for pane in [WorkbenchPane::Source, WorkbenchPane::Center] {
            assert_visualization(
                WorkbenchPage::Ship,
                pane,
                FocusedWorkbenchVisualization::Scene(VizPage::ExploitChain),
            );
        }
        for pane in [WorkbenchPane::Findings, WorkbenchPane::Details] {
            assert_visualization(
                WorkbenchPage::Ship,
                pane,
                FocusedWorkbenchVisualization::Scene(VizPage::Dfd),
            );
        }
    }
}

type FocusedHotkeyHandler = fn(&mut ShellApp, ViewHotkeyAction) -> InputUpdate;

const FOCUSED_HOTKEY_HANDLERS: &[FocusedHotkeyHandler] = &[
    ShellApp::apply_scroll_hotkey_update,
    ShellApp::apply_recommend_hotkey,
    ShellApp::apply_prompt_or_tune_hotkey,
    ShellApp::apply_actor_hotkey_update,
];

fn activity_task_deck_page(task_id: &str) -> Option<ActivityDeckPage> {
    activity_nonfinding_deck_page(task_id)
        .or_else(|| task_produces_findings(task_id).then_some(ActivityDeckPage::Findings))
}

fn activity_nonfinding_deck_page(task_id: &str) -> Option<ActivityDeckPage> {
    if task_id.starts_with("recon:") {
        return Some(ActivityDeckPage::Recon);
    }
    if task_id == "threat-model:build" {
        return Some(ActivityDeckPage::Dfd);
    }
    if let Some(page) = viz_page_for_tool(task_id) {
        return Some(ActivityDeckPage::from_scene_page(page));
    }
    None
}

fn task_produces_findings(task_id: &str) -> bool {
    let normalized = task_id.to_ascii_lowercase();
    normalized == "sast:scan"
        || normalized == "agentic-sast:scan"
        || normalized.ends_with(":scan")
        || normalized.contains("triage")
        || normalized.contains("verify")
        || normalized.contains("finding")
}
