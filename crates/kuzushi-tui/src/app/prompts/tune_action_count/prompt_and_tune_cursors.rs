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
            self.tune_cursor.min(total - 1)
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
            self.prompts_cursor.min(total - 1)
        }
    }

    pub fn current_prompt_verb_name(&self) -> Option<&'static str> {
        Self::PROMPT_VERB_NAMES
            .get(self.prompts_cursor_clamped())
            .copied()
    }

    pub fn move_prompts_cursor(&mut self, delta: i32) {
        let total = Self::PROMPT_VERB_NAMES.len();
        if total == 0 {
            self.prompts_cursor = 0;
            return;
        }
        let cur = self.prompts_cursor.min(total - 1) as i32;
        self.prompts_cursor = (cur + delta).clamp(0, total as i32 - 1) as usize;
    }

    pub fn activate_prompts_action(&mut self, action: PromptsAction) {
        let Some(name) = self.current_prompt_verb_name() else {
            return;
        };
        if action == PromptsAction::Set {
            self.prefill_prompt_set_action(name);
            return;
        }
        if let Some(command) = prompt_action_command(action, name) {
            self.handle_prompt_verb(&command);
        }
    }

    fn prefill_prompt_set_action(&mut self, name: &str) {
        let prefill = format!("set {name} \"\"");
        self.cursor = prefill.chars().count() - 1;
        self.input = prefill;
        self.history_index = None;
    }

    pub fn move_tune_cursor(&mut self, delta: i32) {
        let total = self.tune_action_count();
        if total == 0 {
            self.tune_cursor = 0;
            return;
        }
        let cur = self.tune_cursor.min(total - 1) as i32;
        self.tune_cursor = (cur + delta).clamp(0, total as i32 - 1) as usize;
    }

    pub fn activate_tune_action(&mut self) {
        let Some(action) = self.current_tune_action() else {
            return;
        };
        match action {
            TuneAction::ShowHouseRules => self.handle_tune_verb("show"),
            TuneAction::ResetHouseRules => self.handle_tune_verb("reset"),
            TuneAction::EditHouseRules => {
                let prefill = "set \"\"".to_string();
                self.cursor = prefill.chars().count() - 1;
                self.input = prefill;
                self.history_index = None;
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
