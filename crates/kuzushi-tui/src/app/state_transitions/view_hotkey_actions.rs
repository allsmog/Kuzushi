use super::*;
use kuzushi_core::sorted_finding_aliases;

impl ShellApp {
    pub(super) fn handle_view_hotkey(&mut self, key: KeyEvent) -> bool {
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
            || self.apply_prompt_or_tune_hotkey(action)
            || self.apply_actor_hotkey(action)
            || self.apply_shell_hotkey(action)
    }

    /// Pane-aware Workbench navigation: `Tab` cycles focus, `j/k/g/G` move
    /// within the focused pane (FINDINGS cursor, or SOURCE/CENTER/DETAILS scroll),
    /// and `Enter` selects the cursored finding when the FINDINGS pane is focused.
    fn apply_workbench_hotkey(&mut self, action: ViewHotkeyAction) -> Option<bool> {
        match action {
            ViewHotkeyAction::WorkbenchCyclePane => {
                self.workbench_focus = self.workbench_focus.next();
            }
            ViewHotkeyAction::WorkbenchCyclePanePrev => {
                self.workbench_focus = self.workbench_focus.prev();
            }
            ViewHotkeyAction::WorkbenchScrollNext => self.workbench_move(1),
            ViewHotkeyAction::WorkbenchScrollPrev => self.workbench_move(-1),
            ViewHotkeyAction::WorkbenchScrollFirst => self.workbench_jump(true),
            ViewHotkeyAction::WorkbenchScrollLast => self.workbench_jump(false),
            ViewHotkeyAction::WorkbenchOpen => self.workbench_open_focused(),
            ViewHotkeyAction::Back if self.focus_workbench_findings_before_back() => {}
            _ => return None,
        }
        Some(true)
    }

    fn focus_workbench_findings_before_back(&mut self) -> bool {
        if self.shell_view != ShellView::Workbench || self.workbench_focus != WorkbenchPane::Details
        {
            return false;
        }
        self.workbench_focus = WorkbenchPane::Findings;
        true
    }

    fn workbench_move(&mut self, delta: isize) {
        match self.workbench_focus {
            WorkbenchPane::Findings => self.step_findings_cursor(delta),
            WorkbenchPane::Source | WorkbenchPane::Center | WorkbenchPane::Details => {
                if delta >= 0 {
                    self.scroll_down(1);
                } else {
                    self.scroll_up(1);
                }
            }
        }
    }

    fn step_findings_cursor(&mut self, delta: isize) {
        if delta >= 0 {
            let max = self.findings.len().saturating_sub(1);
            self.findings_cursor = (self.findings_cursor + 1).min(max);
        } else {
            self.findings_cursor = self.findings_cursor.saturating_sub(1);
        }
    }

    fn workbench_jump(&mut self, to_start: bool) {
        match self.workbench_focus {
            WorkbenchPane::Findings => {
                self.findings_cursor = if to_start {
                    0
                } else {
                    self.findings.len().saturating_sub(1)
                };
            }
            WorkbenchPane::Source | WorkbenchPane::Center | WorkbenchPane::Details => {
                if to_start {
                    self.scroll_to_top();
                } else {
                    self.scroll_to_bottom();
                }
            }
        }
    }

    fn workbench_open_focused(&mut self) {
        if self.workbench_focus != WorkbenchPane::Findings {
            return;
        }
        if self.findings.is_empty() {
            self.log("findings", "no findings yet — run `scan` first");
            return;
        }
        self.open_finding_at_cursor();
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
                self.handle_command(ShellCommand::Pause);
            }
            ViewHotkeyAction::ResumeScan => {
                self.handle_command(ShellCommand::Resume(None));
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
            ViewHotkeyAction::ActivityCancelRunning => self.cancel_activity_run(),
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
                "no DAG tasks to focus; output is already full width",
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
        if self.activity_has_live_work() {
            if let Some(session) = self.activity.as_mut() {
                session.reset_presentation_state();
            }
            self.log("activity", "reset Activity view state; live run preserved");
        } else {
            self.activity = None;
        }
    }

    fn activity_has_live_work(&self) -> bool {
        self.running_tool_name().is_some()
            || self.scan.as_ref().is_some_and(|scan| scan.running)
            || self.activity.as_ref().is_some_and(|session| {
                session
                    .tasks
                    .values()
                    .any(|row| row.state == DagTaskState::Active)
            })
    }

    fn cancel_activity_run(&mut self) {
        if !self.activity_cancel_armed() {
            self.arm_activity_cancel();
            return;
        }
        self.activity_cancel_armed_at = None;
        let aborted = self.request_active_abort();
        if !aborted {
            self.log("activity", "no running tool or scan to cancel");
        }
    }

    fn activity_cancel_armed(&self) -> bool {
        self.activity_cancel_armed_at
            .map(|armed_at| std::time::Instant::now().duration_since(armed_at) <= CTRL_C_ARM_WINDOW)
            .unwrap_or(false)
    }

    fn arm_activity_cancel(&mut self) {
        self.activity_cancel_armed_at = Some(std::time::Instant::now());
        self.log(
            "activity",
            "press C again within 2s to cancel the running work",
        );
    }

    fn open_activity_deck_artifact(&mut self) {
        let Some(page) = self.activity.as_ref().map(|session| session.deck_page) else {
            self.log("activity", "no active run output to open");
            return;
        };
        match page {
            ActivityDeckPage::Task => self.open_activity_task_artifact(),
            ActivityDeckPage::Findings => self.open_activity_findings_review(),
            page => match page.scene_page() {
                Some(scene_page) => self.open_scene_to_page(scene_page),
                None => self.log("activity", "this output view has no full visualization"),
            },
        }
    }

    fn open_activity_task_artifact(&mut self) {
        let Some(task_id) = self
            .activity
            .as_ref()
            .and_then(|session| session.selected_task_id())
            .map(ToOwned::to_owned)
        else {
            self.log("activity", "no task selected to open");
            return;
        };
        match activity_task_deck_page(&task_id) {
            Some(ActivityDeckPage::Findings) => self.open_activity_findings_review(),
            Some(page) => match page.scene_page() {
                Some(scene_page) => self.open_scene_to_page(scene_page),
                None => self.log("activity", "selected task has no full artifact"),
            },
            None => self.log("activity", "selected task has no artifact yet"),
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
        let aliases = sorted_finding_aliases(&self.findings);
        if aliases.is_empty() {
            return;
        }
        let index = cursor.min(aliases.len() - 1);
        let (_, finding) = aliases[index].clone();
        self.findings_cursor = index;
        self.selected_finding = Some(finding);
    }

    fn open_or_focus_activity_task(&mut self) {
        let previous_focus = self
            .activity
            .as_ref()
            .and_then(|session| session.focus_task.clone());
        let was_showing_task = self
            .activity
            .as_ref()
            .is_some_and(|session| session.deck_page == ActivityDeckPage::Task);
        let Some(task_id) = self.focus_activity_task_at_cursor() else {
            self.log_activity_focus_unavailable();
            return;
        };
        let page = activity_page_for_focused_task(&task_id, previous_focus, was_showing_task);
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
                "no DAG tasks to focus; output is already full width"
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

fn activity_page_for_focused_task(
    task_id: &str,
    previous_focus: Option<String>,
    was_showing_task: bool,
) -> ActivityDeckPage {
    let same_task = previous_focus.as_deref() == Some(task_id);
    if was_showing_task && same_task {
        return activity_task_deck_page(task_id).unwrap_or(ActivityDeckPage::Task);
    }
    ActivityDeckPage::Task
}

fn activity_task_deck_page(task_id: &str) -> Option<ActivityDeckPage> {
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
