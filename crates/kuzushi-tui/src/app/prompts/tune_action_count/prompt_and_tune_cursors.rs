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
        match action {
            PromptsAction::Show => self.handle_prompt_verb(&format!("show {name}")),
            PromptsAction::Edit => self.handle_prompt_verb(&format!("edit {name}")),
            PromptsAction::Diff => self.handle_prompt_verb(&format!("diff {name}")),
            PromptsAction::Reset => self.handle_prompt_verb(&format!("reset {name}")),
            PromptsAction::Set => {
                let prefill = format!("set {name} \"\"");
                self.cursor = prefill.chars().count() - 1;
                self.input = prefill;
                self.history_index = None;
            }
        }
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
