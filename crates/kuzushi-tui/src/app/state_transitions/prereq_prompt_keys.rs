use super::*;

impl ShellApp {
    pub(super) fn handle_prereq_prompt_key(&mut self, key: KeyEvent) -> InputUpdate {
        if !self.engagement.has_pending_prereq_prompt() || !key.modifiers.is_empty() {
            return InputUpdate::ignored();
        }
        let Some(action) = prereq_prompt_action(key.code) else {
            return InputUpdate::ignored();
        };
        InputUpdate::handled_with_effects(self.resolve_prereq_plan(action))
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
        'n' => Some(PrereqPlanAction::Cancel),
        _ => None,
    }
}
