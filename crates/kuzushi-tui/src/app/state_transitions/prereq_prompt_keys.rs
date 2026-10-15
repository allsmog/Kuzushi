use super::*;

impl ShellApp {
    pub(super) fn handle_prereq_prompt_key(&mut self, key: KeyEvent) -> InputUpdate {
        if !self.prereq_prompt_receives_key(key) {
            return InputUpdate::ignored();
        }
        if !self.prereq_controls_are_available() {
            return self.handle_prereq_draft_key(key);
        }
        let Some(action) = prereq_prompt_action(key.code) else {
            return InputUpdate::ignored();
        };
        InputUpdate::handled_with_effects(self.resolve_prereq_plan(action))
    }

    pub(crate) fn prereq_controls_are_available(&self) -> bool {
        self.engagement.has_pending_prereq_prompt() && self.input().is_empty()
    }

    fn prereq_prompt_receives_key(&self, key: KeyEvent) -> bool {
        self.engagement.has_pending_prereq_prompt() && key.modifiers.is_empty()
    }

    fn handle_prereq_draft_key(&mut self, key: KeyEvent) -> InputUpdate {
        if key.code == KeyCode::Esc {
            return InputUpdate::handled_if(self.esc_clear_input_or_completion());
        }
        InputUpdate::ignored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn waiting_plan() -> (tempfile::TempDir, ShellApp) {
        let root = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(root.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.start_prereq_chain(
            prereq_steps_for("sast:scan", root.path()),
            "sast:scan".into(),
            serde_json::json!({"taskMode":"manual","tasks":["dep-hygiene"],
                "triage":false,"verify":false,"autoPatch":false,"threatModelRef":null}),
            workspace,
            None,
            ExecutionAuthorization::default(),
        );
        assert!(app.engagement.has_pending_prereq_prompt());
        (root, app)
    }

    #[test]
    fn prerequisite_choice_letters_extend_a_held_draft_without_approval() {
        for ch in ['a', 'y', 'r', 'g', 'n'] {
            let (_root, mut app) = waiting_plan();
            app.set_input("held ");
            app.set_input_mode(InputMode::Prompt);
            let update = app.reduce_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE));
            assert!(update.effects.is_empty(), "{ch}");
            assert!(app.engagement.has_pending_prereq_prompt(), "{ch}");
            assert_eq!(app.input(), format!("held {ch}"));
            assert!(!app.has_running_work());
        }
    }

    #[test]
    fn escape_clears_a_held_draft_without_canceling_the_prerequisite_plan() {
        let (_root, mut app) = waiting_plan();
        app.set_input("held draft");
        app.set_input_mode(InputMode::Prompt);
        let update = app.reduce_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(update.effects.is_empty());
        assert!(app.engagement.has_pending_prereq_prompt());
        assert!(app.input().is_empty());
    }

    #[test]
    fn prerequisite_reuse_owns_the_catalog_refresh_key() {
        let (_root, mut app) = waiting_plan();
        app.set_shell_view(ShellView::Catalog);
        app.set_input_mode(InputMode::Prompt);
        let update = app.reduce_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
        assert!(matches!(
            update.effects.as_slice(),
            [ShellEffect::AdvancePrereqChain(_)]
        ));
        assert!(!app.engagement.has_pending_prereq_prompt());
        assert!(app.engagement.pending_chain_approved());
        assert!(app.input().is_empty());
        assert!(
            !app.has_running_work(),
            "only the explicit effect may start work"
        );
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
