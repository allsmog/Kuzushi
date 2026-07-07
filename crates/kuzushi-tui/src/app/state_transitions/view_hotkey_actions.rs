use super::*;
use std::path::{Component, Path};

impl ShellApp {
    pub(super) fn handle_view_hotkey(&mut self, key: KeyEvent) -> bool {
        if let Some(handled) = self.handle_workbench_depth_key(key) {
            return handled;
        }
        let Some(binding) = self
            .view_keybindings()
            .into_iter()
            .find(|binding| binding.matches(key))
        else {
            return self.handle_generic_scroll_hotkey(key);
        };
        let char_trigger = binding.trigger.is_char();
        let handled = self.apply_view_hotkey(binding.action);
        if handled && char_trigger {
            self.last_char_at = Some(Instant::now());
        }
        handled
    }

    pub(super) fn apply_view_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        if let Some(handled) = self.apply_workbench_hotkey(action) {
            return handled;
        }
        self.apply_focused_view_hotkey(action)
    }

    /// The `bool`-returning handlers, tried in order; each mutates and reports
    /// whether it claimed the action (short-circuit, like the `if` chain).
    fn apply_focused_view_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        self.apply_scroll_hotkey(action)
            || self.apply_recommend_hotkey(action)
            || self.apply_prompt_or_tune_hotkey(action)
            || self.apply_actor_hotkey(action)
            || self.apply_shell_hotkey(action)
    }

    /// Pane-aware Workbench navigation: `Tab` cycles focus, `j/k/g/G` move
    /// within the focused pane (FINDINGS cursor, or SOURCE/CENTER/DETAILS scroll),
    /// and `Enter` selects the cursored finding when the FINDINGS pane is focused.
    fn apply_workbench_hotkey(&mut self, action: ViewHotkeyAction) -> Option<bool> {
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
            ViewHotkeyAction::WorkbenchValidate => self.validate_workbench_finding(),
            ViewHotkeyAction::WorkbenchOrderChain => self.order_workbench_chain(),
            ViewHotkeyAction::WorkbenchCluster => self.open_workbench_coverage_clusters(),
            ViewHotkeyAction::Back if self.focus_workbench_findings_before_back() => {}
            _ => return None,
        }
        Some(true)
    }

    /// Depth-stack review keys (opt-in `ui.workbench_depth_stack`). Returns
    /// `Some(true)` when the depth stack consumed the key, `None` to fall
    /// through to the standard view keybindings — so `Esc` at the list root
    /// still leaves the view, while inner depths unwind first.
    fn handle_workbench_depth_key(&mut self, key: KeyEvent) -> Option<bool> {
        if !self.workbench_depth_stack_active() {
            return None;
        }
        let bounds = crate::ui_view_models::workbench_depth_bounds(self, &self.workbench_nav);
        match self.workbench_nav.apply_key(key, bounds) {
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
        self.workbench_depth_stack
            && self.shell_view == ShellView::Workbench
            && self.workbench_is_review_page()
    }

    fn jump_findings_selection(&mut self, to_start: bool) {
        self.findings_route
            .jump(to_start, crate::ui_view_models::visible_findings_len(self));
    }

    fn set_workbench_page(&mut self, page: WorkbenchPage) {
        self.workbench_page = Some(page);
        self.shell_view = ShellView::Workbench;
        self.workbench_scroll.set(WorkbenchPane::Center, 0);
        if page == WorkbenchPage::Review {
            self.workbench_focus = WorkbenchPane::Findings;
        } else {
            self.workbench_focus = WorkbenchPane::Center;
        }
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
            self.workbench_focus = WorkbenchPane::Center;
            return;
        }
        self.workbench_focus = if reverse {
            self.workbench_focus.prev()
        } else {
            self.workbench_focus.next()
        };
    }

    fn toggle_workbench_center_mode(&mut self) {
        self.workbench_center_mode = self.workbench_center_mode.toggled();
        self.workbench_scroll.set(WorkbenchPane::Center, 0);
    }

    fn cycle_workbench_center_mode(&mut self, direction: i32) {
        self.workbench_center_mode = if direction >= 0 {
            self.workbench_center_mode.next()
        } else {
            self.workbench_center_mode.prev()
        };
        self.workbench_focus = WorkbenchPane::Center;
        self.workbench_scroll.set(WorkbenchPane::Center, 0);
    }

    fn open_workbench_center_viz(&mut self) {
        let Some(page) = self.workbench_center_mode.scene_page() else {
            self.log(
                "workbench",
                "CODE has no full visualization; choose DFD/CHAIN/FLOW/RISK",
            );
            return;
        };
        self.open_scene_to_page(page);
    }

    fn focus_workbench_findings_before_back(&mut self) -> bool {
        if self.shell_view != ShellView::Workbench || self.workbench_focus != WorkbenchPane::Details
        {
            return false;
        }
        self.workbench_focus = WorkbenchPane::Findings;
        self.log("workbench", "returned to findings — Esc again to leave");
        true
    }

    fn workbench_move(&mut self, delta: isize) {
        if !self.workbench_is_review_page() {
            self.move_workbench_page_body(delta);
            return;
        }
        match self.workbench_focus {
            WorkbenchPane::Findings => self.step_findings_cursor(delta),
            WorkbenchPane::Source | WorkbenchPane::Center | WorkbenchPane::Details => {
                self.scroll_by_delta(delta)
            }
        }
    }

    fn move_workbench_page_body(&mut self, delta: isize) {
        self.workbench_focus = WorkbenchPane::Center;
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
        self.findings_route
            .step_direction(delta, crate::ui_view_models::visible_findings_len(self));
    }

    fn workbench_jump(&mut self, to_start: bool) {
        if !self.workbench_is_review_page() {
            self.jump_workbench_page_body(to_start);
            return;
        }
        match self.workbench_focus {
            WorkbenchPane::Findings => {
                self.findings_route
                    .jump(to_start, crate::ui_view_models::visible_findings_len(self));
            }
            WorkbenchPane::Source | WorkbenchPane::Center | WorkbenchPane::Details => {
                self.jump_scroll_region(to_start);
            }
        }
    }

    fn jump_workbench_page_body(&mut self, to_start: bool) {
        self.workbench_focus = WorkbenchPane::Center;
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
        match self.workbench_focus {
            WorkbenchPane::Center => self.open_workbench_center_viz(),
            WorkbenchPane::Findings => self.open_workbench_finding_or_log(),
            WorkbenchPane::Source | WorkbenchPane::Details => {}
        }
    }

    fn workbench_is_review_page(&self) -> bool {
        crate::ui_view_models::active_workbench_page(self) == WorkbenchPage::Review
    }

    fn open_workbench_finding_or_log(&mut self) {
        if self.findings.is_empty() {
            self.log("findings", "no findings yet — run `scan` first");
            return;
        }
        self.open_finding_at_cursor();
    }

    fn validate_workbench_finding(&mut self) {
        let Some(finding) = self.current_workbench_finding() else {
            self.log(
                "verify",
                "no finding selected — open REVIEW and choose a finding first",
            );
            return;
        };
        let input = serde_json::json!({ "fingerprint": finding.fingerprint }).to_string();
        update_and_execute_effects(
            self,
            Msg::Cmd(ShellCommand::RunTool {
                tool: Some("verify:exploit".to_string()),
                input: Some(input),
            }),
        );
    }

    fn order_workbench_chain(&mut self) {
        update_and_execute_effects(
            self,
            Msg::Cmd(ShellCommand::RunTool {
                tool: Some("exploit-chain:scan".to_string()),
                input: None,
            }),
        );
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

    fn apply_recommend_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        match action {
            ViewHotkeyAction::RecommendCursorPrevious => self.move_recommend_cursor(-1),
            ViewHotkeyAction::RecommendCursorNext => self.move_recommend_cursor(1),
            ViewHotkeyAction::RecommendScanComponent => self.scan_recommend_component(),
            ViewHotkeyAction::RecommendPromoteComponent => self.promote_recommend_component(),
            _ => return false,
        }
        true
    }

    fn move_recommend_cursor(&mut self, delta: isize) {
        let count = crate::ui_view_models::recommendation_components(self).len();
        if count == 0 {
            self.catalog_route.reset_recommend_cursor();
            self.log(
                "component",
                "no component recommendations yet — run `recommend` first",
            );
            return;
        }
        self.catalog_route.move_recommend_cursor(delta, count);
    }

    fn scan_recommend_component(&mut self) {
        let Some(component) = self.selected_recommend_component() else {
            self.log(
                "component",
                "no component selected — run `recommend` to rank components first",
            );
            return;
        };
        self.log(
            "component",
            format!(
                "scanning {} as {} within the current target",
                component.rel_path, component.class_label
            ),
        );
        self.run_tool(Some("sast:scan".to_string()), component.scan_input.clone());
    }

    fn promote_recommend_component(&mut self) {
        let Some(component) = self.selected_recommend_component() else {
            self.log(
                "component",
                "no component selected — run `recommend` to rank components first",
            );
            return;
        };
        if component.promote_command.is_none() {
            self.log(
                "component",
                format!(
                    "{} is best scanned inside the current target",
                    component.rel_path
                ),
            );
            return;
        }
        let Some(target_path) = self.recommend_component_target_path(&component.rel_path) else {
            self.log(
                "component",
                "promotion needs an active target and target-relative component path",
            );
            return;
        };
        match WorkspaceTarget::new(&target_path) {
            Ok(workspace) => {
                self.activate_target(workspace);
                self.log(
                    "component",
                    format!("promoted {} to its own target", component.rel_path),
                );
            }
            Err(error) => self.log(
                "component",
                format!("cannot promote {}: {error}", component.rel_path),
            ),
        }
    }

    fn selected_recommend_component(
        &mut self,
    ) -> Option<crate::ui_view_models::ComponentRecommendationRow> {
        let components = crate::ui_view_models::recommendation_components(self);
        let selected = self
            .catalog_route
            .selected_recommend_cursor(components.len());
        components.get(selected).cloned()
    }

    fn recommend_component_target_path(&self, rel_path: &str) -> Option<PathBuf> {
        let target = self.target.as_ref()?;
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

    fn apply_prompt_or_tune_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        match action {
            ViewHotkeyAction::TuneCursorPrevious => self.move_tune_cursor(-1),
            ViewHotkeyAction::TuneCursorNext => self.move_tune_cursor(1),
            ViewHotkeyAction::TuneActivate => self.activate_tune_action(),
            ViewHotkeyAction::PromptsCursorPrevious => self.move_prompts_cursor(-1),
            ViewHotkeyAction::PromptsCursorNext => self.move_prompts_cursor(1),
            ViewHotkeyAction::PromptsAction(action) => self.activate_prompts_action(action),
            _ => return false,
        }
        true
    }

    fn apply_actor_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        match action {
            ViewHotkeyAction::ActorDetail(index) => self.shell_view = ShellView::ActorDetail(index),
            ViewHotkeyAction::ActorDetailFilterCycle => {
                self.actor_detail_filter = self.actor_detail_filter.next();
            }
            ViewHotkeyAction::ActorDetailFilterReset => {
                self.actor_detail_filter = ActorDetailFilter::All;
            }
            _ => return false,
        }
        true
    }

    fn apply_shell_hotkey(&mut self, action: ViewHotkeyAction) -> bool {
        if self.apply_activity_hotkey(action) {
            return true;
        }
        match action {
            ViewHotkeyAction::ThreatView(view) => {
                self.shell_view = ShellView::Threat(view);
            }
            ViewHotkeyAction::PauseScan => {
                update_and_execute_effects(self, Msg::Cmd(ShellCommand::Pause));
            }
            ViewHotkeyAction::ResumeScan => {
                update_and_execute_effects(self, Msg::Cmd(ShellCommand::Resume(None)));
            }
            ViewHotkeyAction::OpenNextPhase => {
                update_and_execute_effects(self, Msg::Cmd(ShellCommand::Next));
            }
            ViewHotkeyAction::Back => self.go_back(),
            _ => return false,
        }
        true
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
                .activity
                .as_ref()
                .is_some_and(|session| session.tasks.is_empty())
        {
            self.log(
                "activity",
                "no task rows to focus; output is already full width",
            );
            return true;
        }
        let Some(session) = self.activity.as_mut() else {
            return false;
        };
        let Some(apply) = activity_session_action(action) else {
            return false;
        };
        apply(session);
        true
    }

    fn reset_activity_view(&mut self) {
        let Some(session) = self.activity.as_mut() else {
            self.log("activity", "no Activity view state to reset");
            return;
        };
        session.reset_presentation_state();
        self.log("activity", "reset Activity view state; run preserved");
    }

    fn open_activity_deck_artifact(&mut self) {
        let Some(page) = self.activity.as_ref().map(|session| session.deck_page) else {
            self.log("activity", "no active run output to open");
            return;
        };
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
        let Some(cursor) = self.activity.as_ref().and_then(|session| {
            (session.deck_page == ActivityDeckPage::Findings).then_some(session.deck_cursor)
        }) else {
            return;
        };
        let visible_len = crate::ui_view_models::visible_findings_len(self);
        if visible_len == 0 {
            return;
        }
        let index = cursor.min(visible_len - 1);
        let Some((_, finding)) = crate::ui_view_models::visible_finding_at_index(self, index)
        else {
            return;
        };
        self.findings_route.set_cursor(index);
        self.selected_finding = Some(finding);
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
        let Some(session) = self.activity.as_mut() else {
            return;
        };
        session.set_deck_page_by_user(page);
        session.pane_focus = PaneFocus::Right;
        self.log(
            "activity",
            format!("showing {task_id} output in the {} view", page.label()),
        );
    }

    fn log_activity_focus_unavailable(&mut self) {
        let message = match self.activity.as_ref() {
            None => "no active run to focus",
            Some(session) if session.tasks.is_empty() => {
                "no task rows to focus; output is already full width"
            }
            Some(_) => "no visible task at the current cursor",
        };
        self.log("activity", message);
    }

    fn focus_activity_task_at_cursor(&mut self) -> Option<String> {
        let session = self.activity.as_mut()?;
        if session.tasks.is_empty() {
            return None;
        }
        session.focus_task_at_cursor()
    }
}

type ActivitySessionAction = fn(&mut crate::app::ActivitySession);

fn activity_session_action(action: ViewHotkeyAction) -> Option<ActivitySessionAction> {
    const ACTIONS: &[(ViewHotkeyAction, ActivitySessionAction)] = &[
        (
            ViewHotkeyAction::ActivityTabPaneFocus,
            crate::app::ActivitySession::toggle_pane_focus,
        ),
        (
            ViewHotkeyAction::ActivityToggleVerbose,
            crate::app::ActivitySession::toggle_verbose_subsystems,
        ),
        (
            ViewHotkeyAction::ActivityTogglePause,
            crate::app::ActivitySession::toggle_paused,
        ),
        (
            ViewHotkeyAction::ActivityDeckNext,
            crate::app::ActivitySession::next_deck_page,
        ),
        (
            ViewHotkeyAction::ActivityDeckPrev,
            crate::app::ActivitySession::prev_deck_page,
        ),
    ];
    ACTIONS
        .iter()
        .find_map(|(candidate, apply)| (*candidate == action).then_some(*apply))
}

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
