use super::*;

impl ShellApp {
    pub(super) fn handle_prereq_prompt_key(&mut self, key: KeyEvent) -> bool {
        if self.pending_prereq_prompt.is_none() || !key.modifiers.is_empty() {
            return false;
        }
        let Some(action) = prereq_prompt_action(key.code) else {
            return false;
        };
        self.resolve_prereq_plan(action);
        true
    }
}

fn prereq_prompt_action(code: KeyCode) -> Option<PrereqPlanAction> {
    if matches!(code, KeyCode::Enter) {
        return Some(PrereqPlanAction::Approve);
    }
    if matches!(code, KeyCode::Esc) {
        return Some(PrereqPlanAction::Cancel);
    }
    let KeyCode::Char(ch) = code else {
        return None;
    };
    match ch.to_ascii_lowercase() {
        'a' | 'y' => Some(PrereqPlanAction::Approve),
        'r' => Some(PrereqPlanAction::Reuse),
        'g' => Some(PrereqPlanAction::Regenerate),
        'c' | 'n' => Some(PrereqPlanAction::Cancel),
        _ => None,
    }
}
