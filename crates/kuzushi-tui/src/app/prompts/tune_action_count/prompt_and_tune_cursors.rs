use super::*;

impl ShellApp {
    pub fn tune_action_count(&self) -> usize {
        TuneAction::ORDER.len()
    }

    pub fn tune_cursor_clamped(&self) -> usize {
        let total = self.tune_action_count();
        if total == 0 {
            0
        } else {
            self.router.tune().cursor().min(total - 1)
        }
    }

    pub fn current_tune_action(&self) -> Option<TuneAction> {
        TuneAction::ORDER.get(self.tune_cursor_clamped()).copied()
    }

    pub const PROMPT_VERB_NAMES: &'static [&'static str] = &["scan", "triage", "verify", "summary"];

    pub fn prompts_cursor_clamped(&self) -> usize {
        let total = Self::PROMPT_VERB_NAMES.len();
        if total == 0 {
            0
        } else {
            self.router.prompts().cursor().min(total - 1)
        }
    }

    pub fn current_prompt_verb_name(&self) -> Option<&'static str> {
        Self::PROMPT_VERB_NAMES
            .get(self.prompts_cursor_clamped())
            .copied()
    }

    pub fn move_prompts_cursor(&mut self, delta: i32) {
        let total = Self::PROMPT_VERB_NAMES.len();
        self.router.prompts_mut().move_cursor(delta, total);
    }

    pub(crate) fn activate_prompts_action(&mut self, action: PromptsAction) -> Vec<ShellEffect> {
        let Some(name) = self.current_prompt_verb_name() else {
            return Vec::new();
        };
        if action == PromptsAction::Set {
            self.prefill_prompt_set_action(name);
            return Vec::new();
        }
        if let Some(command) = prompt_action_command(action, name) {
            return self.handle_prompt_verb(&command);
        }
        Vec::new()
    }

    fn prefill_prompt_set_action(&mut self, name: &str) {
        let prefill = format!("set {name} \"\"");
        let cursor = prefill.chars().count() - 1;
        self.set_input(prefill);
        self.set_cursor(cursor);
    }

    pub fn move_tune_cursor(&mut self, delta: i32) {
        let total = self.tune_action_count();
        self.router.tune_mut().move_cursor(delta, total);
    }

    pub(crate) fn activate_tune_action(&mut self) -> Vec<ShellEffect> {
        let Some(action) = self.current_tune_action() else {
            return Vec::new();
        };
        match action {
            TuneAction::ShowHouseRules => self.handle_tune_verb("show"),
            TuneAction::ResetHouseRules => self.handle_tune_verb("reset"),
            TuneAction::EditHouseRules => {
                let prefill = "set \"\"".to_string();
                let cursor = prefill.chars().count() - 1;
                self.set_input(prefill);
                self.set_cursor(cursor);
                Vec::new()
            }
        }
    }
}

fn prompt_action_command(action: PromptsAction, name: &str) -> Option<String> {
    PROMPT_ACTION_PREFIXES
        .iter()
        .find_map(|(candidate, prefix)| (*candidate == action).then(|| format!("{prefix} {name}")))
}

const PROMPT_ACTION_PREFIXES: &[(PromptsAction, &str)] = &[
    (PromptsAction::Show, "show"),
    (PromptsAction::Edit, "edit"),
    (PromptsAction::Diff, "diff"),
    (PromptsAction::Reset, "reset"),
];
