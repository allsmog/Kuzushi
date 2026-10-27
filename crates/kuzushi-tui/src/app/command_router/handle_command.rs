use super::*;

#[cfg(all(test, unix))]
mod dispatcher_tests;

impl ShellApp {
    pub fn handle_command(&mut self, command: ShellCommand) {
        update_and_execute_effects(self, Msg::Cmd(command));
    }

    pub(crate) fn reduce_command_message(&mut self, command: ShellCommand) -> CommandUpdate {
        let previous_view = self.shell_view();
        let update = self.reduce_command_without_effect_execution(command);
        self.discard_stashed_input_after_view_change(&previous_view);
        update
    }

    fn reduce_command_without_effect_execution(&mut self, command: ShellCommand) -> CommandUpdate {
        let rejected = matches!(command, ShellCommand::Unknown(_));
        if let Some(effects) = self.reduce_command_effects(&command) {
            return if rejected {
                CommandUpdate::rejected(effects)
            } else {
                CommandUpdate::handled(effects)
            };
        }
        CommandUpdate::unhandled()
    }

    pub(crate) fn reduce_submitted_line(&mut self, raw: &str) -> CommandUpdate {
        let trimmed = raw.trim();
        // Empty / whitespace-only Enter is a no-op (P-NEW-3): logging an empty
        // `>` bullet just clutters the 2-row transcript with rows the operator
        // never asked for.
        if trimmed.is_empty() {
            return CommandUpdate::unhandled();
        }
        self.reduce_nonempty_submitted_line(raw, trimmed)
    }

    fn reduce_nonempty_submitted_line(&mut self, raw: &str, trimmed: &str) -> CommandUpdate {
        self.set_last_cleared_input(None);
        self.record_session_event(
            kuzushi_core::session_transcript::SessionEvent::CommandSubmitted {
                command: raw.to_string(),
            },
        );
        self.log(">", raw.to_string());
        let mut effects = self.reduce_remember_command(trimmed);
        if self.handle_subverb_query(trimmed) {
            return CommandUpdate::handled(effects);
        }
        if let Some(mut local_effects) = self.handle_editor_local_command(trimmed) {
            effects.append(&mut local_effects);
            return CommandUpdate::handled(effects);
        }
        let parsed = self.phase_intent_or_parsed_command(raw);
        if self.queue_operator_submission_while_busy(trimmed, &parsed) {
            return CommandUpdate::handled(effects);
        }
        let mut command_update = self.reduce_command_message(parsed);
        effects.append(&mut command_update.effects);
        command_update.effects = effects;
        command_update.handled = true;
        command_update
    }

    fn phase_intent_or_parsed_command(&self, raw: &str) -> ShellCommand {
        let parsed = parse_command(raw);
        let ShellCommand::Unknown(text) = parsed else {
            return parsed;
        };
        if self.shell_view() != ShellView::Workbench
            || text.starts_with('/')
            || known_command_head(&text)
        {
            return ShellCommand::Unknown(text);
        }
        let page = crate::ui_view_models::active_workbench_page(self);
        let selected_phase = match page {
            WorkbenchPage::Map => WorkflowPhase::Map,
            WorkbenchPage::Scan => WorkflowPhase::Scan,
            WorkbenchPage::Review => WorkflowPhase::Review,
            WorkbenchPage::Prove => WorkflowPhase::Prove,
            WorkbenchPage::Fix => WorkflowPhase::Fix,
        };
        ShellCommand::PhaseIntent {
            selected_phase,
            text,
        }
    }

    /// Auto-queue the ergonomic path: a `run <tool>` submitted while a job is
    /// live is queued instead of rejected. Only operator submissions flow
    /// through here — internal chain/planning dispatches never reach
    /// `reduce_submitted_line`, so their single-slot ordering is untouched.
    fn queue_operator_submission_while_busy(
        &mut self,
        trimmed: &str,
        parsed: &ShellCommand,
    ) -> bool {
        if !self.has_local_running_work() || !is_steerable_submission(parsed) {
            return false;
        }
        self.enqueue_steer_command(trimmed);
        true
    }

    /// `<group-verb> ?` lists the verb's sub-verbs inline. Editor-local so it
    /// adds no `ShellCommand` route; the listing comes from the same
    /// `subverb_listing` table Tab-completion uses, so they never drift.
    fn handle_subverb_query(&mut self, trimmed: &str) -> bool {
        let stripped = trimmed.strip_prefix('/').unwrap_or(trimmed);
        let mut words = stripped.split_whitespace();
        let (Some(verb), Some("?"), None) = (words.next(), words.next(), words.next()) else {
            return false;
        };
        let Some(subverbs) = subverb_listing(verb) else {
            return false;
        };
        self.log(verb, format!("sub-verbs: {}", subverbs.join(", ")));
        true
    }

    pub(crate) fn reduce_remember_command(&mut self, trimmed: &str) -> Vec<ShellEffect> {
        self.editor
            .push_command_history(trimmed.to_string(), COMMAND_HISTORY_CAP);
        if self.history_file_path().is_some() {
            vec![ShellEffect::PersistCommandHistory]
        } else {
            Vec::new()
        }
    }

    fn handle_editor_local_command(&mut self, trimmed: &str) -> Option<Vec<ShellEffect>> {
        if let Some(effects) = self.handle_prompt_editor_local_command(trimmed) {
            return Some(effects);
        }
        self.handle_tune_local_command(trimmed)
    }

    fn handle_prompt_editor_local_command(&mut self, trimmed: &str) -> Option<Vec<ShellEffect>> {
        if !matches!(self.shell_view(), ShellView::PromptsEditor)
            || trimmed.starts_with('/')
            || !self.is_bare_prompt_verb(trimmed)
        {
            return None;
        }
        Some(self.reduce_prompt_verb(trimmed))
    }

    fn handle_tune_local_command(&mut self, trimmed: &str) -> Option<Vec<ShellEffect>> {
        if !matches!(self.shell_view(), ShellView::Tune)
            || trimmed.starts_with('/')
            || !self.is_bare_tune_verb(trimmed)
        {
            return None;
        }
        Some(self.reduce_tune_verb(trimmed))
    }

    pub(crate) fn is_bare_prompt_verb(&self, raw: &str) -> bool {
        let head = raw.split_whitespace().next().unwrap_or("");
        matches!(head, "edit" | "show" | "diff" | "reset" | "set" | "list")
    }

    pub(crate) fn is_bare_tune_verb(&self, raw: &str) -> bool {
        let head = raw.split_whitespace().next().unwrap_or("");
        matches!(head, "show" | "set" | "reset")
    }

    fn discard_stashed_input_after_view_change(&mut self, previous_view: &ShellView) {
        if &self.shell_view() != previous_view {
            self.set_last_cleared_input(None);
        }
    }
}

fn known_command_head(raw: &str) -> bool {
    let head = raw.split_whitespace().next().unwrap_or_default();
    crate::commands::shell_command_specs().any(|spec| {
        std::iter::once(spec.command)
            .chain(spec.aliases.iter().copied())
            .filter_map(|value| value.trim_start_matches('/').split_whitespace().next())
            .any(|known| known == head)
    })
}

/// A submission that dispatches a tool run — the steerable case that queues
/// behind a live job. Deliberately excludes `Full` and the compatibility
/// `Scan` variant: both open the guided picker rather than dispatching work.
fn is_steerable_submission(command: &ShellCommand) -> bool {
    matches!(command, ShellCommand::RunTool { .. })
}

pub(crate) struct CommandUpdate {
    pub(crate) handled: bool,
    pub(crate) rejected: bool,
    pub(crate) effects: Vec<ShellEffect>,
}

impl CommandUpdate {
    fn handled(effects: Vec<ShellEffect>) -> Self {
        Self {
            handled: true,
            rejected: false,
            effects,
        }
    }

    fn rejected(effects: Vec<ShellEffect>) -> Self {
        Self {
            handled: true,
            rejected: true,
            effects,
        }
    }

    fn unhandled() -> Self {
        Self {
            handled: false,
            rejected: false,
            effects: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn workbench_prose_carries_the_selected_phase_into_planning() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Workbench);
        app.router
            .workbench_mut()
            .set_page(Some(WorkbenchPage::Scan));

        assert_eq!(
            app.phase_intent_or_parsed_command("inspect authentication paths"),
            ShellCommand::PhaseIntent {
                selected_phase: WorkflowPhase::Scan,
                text: "inspect authentication paths".to_string(),
            }
        );
    }

    #[test]
    fn explicit_commands_are_parsed_before_phase_intent() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_shell_view(ShellView::Workbench);

        assert!(matches!(
            app.phase_intent_or_parsed_command("run semgrep:scan"),
            ShellCommand::RunTool { .. }
        ));
    }
}
