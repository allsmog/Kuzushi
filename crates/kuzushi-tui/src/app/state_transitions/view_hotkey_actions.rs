use super::*;
use std::path::{Component, Path};

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

    /// Pane-aware Workbench navigation: `Tab` cycles focus, `j/k/g/G` move
    /// within the focused pane (FINDINGS cursor, or SOURCE/CENTER/DETAILS scroll),
    /// and `Enter` selects the cursored finding when the FINDINGS pane is focused.
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
            ViewHotkeyAction::WorkbenchZoomCenter => self.open_workbench_center_viz(),
            ViewHotkeyAction::WorkbenchOpen => self.workbench_open_focused(),
            ViewHotkeyAction::WorkbenchPageNext => {
                self.set_workbench_page(crate::ui_view_models::active_workbench_page(self).next())
            }
            ViewHotkeyAction::WorkbenchPagePrev => {
                self.set_workbench_page(crate::ui_view_models::active_workbench_page(self).prev())
            }
            ViewHotkeyAction::WorkbenchPage(page) => self.set_workbench_page(page),
            ViewHotkeyAction::WorkbenchValidate => return Some(self.validate_workbench_finding()),
            ViewHotkeyAction::WorkbenchOrderChain => return Some(self.order_workbench_chain()),
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
            && self.shell_view == ShellView::Workbench
            && self.workbench_is_review_page()
    }

    fn jump_findings_selection(&mut self, to_start: bool) {
        let len = crate::ui_view_models::visible_findings_len(self);
        self.router.findings_mut().jump(to_start, len);
    }

    fn set_workbench_page(&mut self, page: WorkbenchPage) {
        let workbench = self.router.workbench_mut();
        workbench.set_page(Some(page));
        workbench.scroll_mut().set(WorkbenchPane::Center, 0);
        if page == WorkbenchPage::Review {
            workbench.set_focus(WorkbenchPane::Findings);
        } else {
            workbench.set_focus(WorkbenchPane::Center);
        }
        self.shell_view = ShellView::Workbench;
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
        if !self.workbench_is_review_page() {
            self.router.workbench_mut().set_focus(WorkbenchPane::Center);
            return;
        }
        let current = self.router.workbench().focus();
        let next = if reverse {
            current.prev()
        } else {
            current.next()
        };
        self.router.workbench_mut().set_focus(next);
    }

    fn toggle_workbench_center_mode(&mut self) {
        self.router.workbench_mut().toggle_center_mode();
    }

    fn cycle_workbench_center_mode(&mut self, direction: i32) {
        self.router.workbench_mut().cycle_center_mode(direction);
    }

    fn open_workbench_center_viz(&mut self) {
        let Some(page) = self.router.workbench().center_mode().scene_page() else {
            self.log(
                "workbench",
                "CODE has no full visualization; choose DFD/CHAIN/FLOW/RISK",
            );
            return;
        };
        self.open_scene_to_page(page);
    }

    fn focus_workbench_findings_before_back(&mut self) -> bool {
        if self.shell_view != ShellView::Workbench
            || self.router.workbench().focus() != WorkbenchPane::Details
        {
            return false;
        }
        self.router
            .workbench_mut()
            .set_focus(WorkbenchPane::Findings);
        self.log("workbench", "returned to findings — Esc again to leave");
        true
    }

    fn workbench_move(&mut self, delta: isize) {
        if !self.workbench_is_review_page() {
            self.move_workbench_page_body(delta);
            return;
        }
        match self.router.workbench().focus() {
            WorkbenchPane::Findings => self.step_findings_cursor(delta),
            WorkbenchPane::Source | WorkbenchPane::Center | WorkbenchPane::Details => {
                self.scroll_by_delta(delta)
            }
        }
    }

    fn move_workbench_page_body(&mut self, delta: isize) {
        self.router.workbench_mut().set_focus(WorkbenchPane::Center);
        self.scroll_by_delta(delta);
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
    }

    fn workbench_jump(&mut self, to_start: bool) {
        if !self.workbench_is_review_page() {
            self.jump_workbench_page_body(to_start);
            return;
        }
        match self.router.workbench().focus() {
            WorkbenchPane::Findings => {
                let len = crate::ui_view_models::visible_findings_len(self);
                self.router.findings_mut().jump(to_start, len);
            }
            WorkbenchPane::Source | WorkbenchPane::Center | WorkbenchPane::Details => {
                self.jump_scroll_region(to_start);
            }
        }
    }

    fn jump_workbench_page_body(&mut self, to_start: bool) {
        self.router.workbench_mut().set_focus(WorkbenchPane::Center);
        self.jump_scroll_region(to_start);
    }

    fn jump_scroll_region(&mut self, to_start: bool) {
        if to_start {
            self.scroll_to_top();
        } else {
            self.scroll_to_bottom();
        }
    }

    fn workbench_open_focused(&mut self) {
        if !self.workbench_is_review_page() {
            return;
        }
        match self.router.workbench().focus() {
            WorkbenchPane::Center => self.open_workbench_center_viz(),
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

    fn validate_workbench_finding(&mut self) -> InputUpdate {
        let Some(finding) = self.current_workbench_finding() else {
            self.log(
                "verify",
                "no finding selected — open REVIEW and choose a finding first",
            );
            return InputUpdate::handled();
        };
        let input = serde_json::json!({ "fingerprint": finding.fingerprint }).to_string();
        self.reduce_hotkey_command(ShellCommand::RunTool {
            tool: Some("verify:exploit".to_string()),
            input: Some(input),
        })
    }

    fn order_workbench_chain(&mut self) -> InputUpdate {
        self.reduce_hotkey_command(ShellCommand::RunTool {
            tool: Some("exploit-chain:scan".to_string()),
            input: None,
        })
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
            ViewHotkeyAction::ViewScrollUp => self.scroll_up(1),
            ViewHotkeyAction::ViewScrollDown => self.scroll_down(1),
            ViewHotkeyAction::ViewScrollTop => self.scroll_to_top(),
            ViewHotkeyAction::ViewScrollBottom => self.scroll_to_bottom(),
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
        self.log(
            "component",
            format!("promoted {} to its own target", component.rel_path),
        );
        InputUpdate::handled_with_effects(vec![ShellEffect::ActivateTarget(TargetActivation {
            path: target_path,
            selected_scope: None,
            source: TargetActivationSource::Command,
        })])
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
                self.shell_view = ShellView::ActorDetail;
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
            ViewHotkeyAction::ThreatView(view) => {
                self.router.threat_mut().open(view);
                self.shell_view = ShellView::Threat;
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

    fn apply_activity_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        if self.apply_activity_session_hotkey(action) {
            return true;
        }
        match action {
            ViewHotkeyAction::ActivityReset => self.reset_activity_view(),
            ViewHotkeyAction::ActivityFocusSelected => self.open_or_focus_activity_task(),
            ViewHotkeyAction::ActivityOpenDeckArtifact => self.open_activity_deck_artifact(),
            ViewHotkeyAction::ActivityOpenFindings => self.open_activity_findings_review(),
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
            page => match page.scene_page() {
                Some(scene_page) => self.open_scene_to_page(scene_page),
                None => self.log("activity", "this output view has no full visualization"),
            },
        }
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

type FocusedHotkeyHandler = fn(&mut ShellApp, ViewHotkeyAction) -> InputUpdate;

const FOCUSED_HOTKEY_HANDLERS: &[FocusedHotkeyHandler] = &[
    ShellApp::apply_scroll_hotkey_update,
    ShellApp::apply_recommend_hotkey,
    ShellApp::apply_prompt_or_tune_hotkey,
    ShellApp::apply_actor_hotkey_update,
];

fn activity_task_deck_page(task_id: &str) -> Option<ActivityDeckPage> {
    if task_id == "threat-model:build" {
        return Some(ActivityDeckPage::Dfd);
    }
    if let Some(page) = viz_page_for_tool(task_id) {
        return Some(ActivityDeckPage::from_scene_page(page));
    }
    if task_produces_findings(task_id) {
        return Some(ActivityDeckPage::Findings);
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
