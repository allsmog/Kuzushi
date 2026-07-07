use super::*;

impl ShellApp {
    pub fn handle_command(&mut self, command: ShellCommand) {
        update_and_execute_effects(self, Msg::Cmd(command));
    }

    pub(crate) fn reduce_command_message(&mut self, command: ShellCommand) -> CommandUpdate {
        let previous_view = self.shell_view.clone();
        let update = self.reduce_command_without_effect_execution(command);
        self.discard_stashed_input_after_view_change(&previous_view);
        update
    }

    fn reduce_command_without_effect_execution(&mut self, command: ShellCommand) -> CommandUpdate {
        if let Some(effects) = self.reduce_command_effects(&command) {
            return CommandUpdate::handled(effects);
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
        self.set_last_cleared_input(None);
        self.log(">", raw.to_string());
        let mut effects = self.reduce_remember_command(trimmed);
        if self.handle_subverb_query(trimmed) {
            return CommandUpdate::handled(effects);
        }
        if let Some(mut local_effects) = self.handle_editor_local_command(trimmed) {
            effects.append(&mut local_effects);
            return CommandUpdate::handled(effects);
        }
        let mut command_update = self.reduce_command_message(parse_command(raw));
        effects.append(&mut command_update.effects);
        CommandUpdate::handled(effects)
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
        if !matches!(self.shell_view, ShellView::PromptsEditor)
            || trimmed.starts_with('/')
            || !self.is_bare_prompt_verb(trimmed)
        {
            return None;
        }
        Some(self.reduce_prompt_verb(trimmed))
    }

    fn handle_tune_local_command(&mut self, trimmed: &str) -> Option<Vec<ShellEffect>> {
        if !matches!(self.shell_view, ShellView::Tune)
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
        if &self.shell_view != previous_view {
            self.set_last_cleared_input(None);
        }
    }
}

pub(crate) struct CommandUpdate {
    pub(crate) handled: bool,
    pub(crate) effects: Vec<ShellEffect>,
}

impl CommandUpdate {
    fn handled(effects: Vec<ShellEffect>) -> Self {
        Self {
            handled: true,
            effects,
        }
    }

    fn unhandled() -> Self {
        Self {
            handled: false,
            effects: Vec::new(),
        }
    }
}
