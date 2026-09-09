use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperatorQuestionKeyAction {
    Ignore,
    Consume,
    Background,
    Apply(KeyCode),
}

impl ShellApp {
    pub(super) fn handle_operator_question_key(&mut self, key: KeyEvent) -> InputUpdate {
        if let Some(update) = self.configured_question_update(key) {
            return update;
        }
        let action = operator_question_key_action(
            self.operator_question_is_open(),
            self.question_other_editor().is_some(),
            key,
        );
        match action {
            OperatorQuestionKeyAction::Ignore => InputUpdate::ignored(),
            OperatorQuestionKeyAction::Consume => InputUpdate::handled(),
            OperatorQuestionKeyAction::Background => {
                self.background_handoff();
                InputUpdate::handled()
            }
            OperatorQuestionKeyAction::Apply(code) => {
                self.apply_operator_question_key(code);
                InputUpdate::handled()
            }
        }
    }

    fn configured_question_update(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        if !self.operator_question_is_open() {
            return None;
        }
        let result = self
            .ui_mut()
            .handle_configured_context_key("question", key, Instant::now());
        match result {
            ConfiguredKeyResult::Action(action) => {
                Some(self.apply_configured_question_action(action))
            }
            ConfiguredKeyResult::Pending => Some(InputUpdate::handled()),
            ConfiguredKeyResult::NoMatch if self.question_default_is_overridden(key) => {
                Some(InputUpdate::handled())
            }
            ConfiguredKeyResult::NoMatch => None,
        }
    }

    fn question_default_is_overridden(&self, key: KeyEvent) -> bool {
        question_default_action_id(key, self.question_other_editor().is_some())
            .is_some_and(|action| self.ui().keymap_overrides_action("question", action))
    }

    fn apply_configured_question_action(&mut self, action: ViewHotkeyAction) -> InputUpdate {
        match action {
            ViewHotkeyAction::QuestionSubmit => self.submit_operator_question_answer(),
            ViewHotkeyAction::QuestionCancel => self.return_from_other_or_cancel_question(),
            ViewHotkeyAction::QuestionBackground => self.background_handoff(),
            ViewHotkeyAction::QuestionNextOption => self.move_question_option(1),
            ViewHotkeyAction::QuestionPreviousOption => self.move_question_option(-1),
            ViewHotkeyAction::QuestionNext => self.move_active_question(1),
            ViewHotkeyAction::QuestionPrevious => self.move_active_question(-1),
            ViewHotkeyAction::QuestionOther => {
                self.with_operator_question_mut(PendingOperatorQuestion::open_other)
            }
            _ => return InputUpdate::ignored(),
        }
        InputUpdate::handled()
    }

    fn operator_question_is_open(&self) -> bool {
        matches!(self.shell_view(), ShellView::Activity)
            && self
                .activity()
                .is_some_and(|session| session.operator_question.is_some())
    }

    fn question_other_editor(&self) -> Option<&str> {
        self.activity()
            .and_then(|session| session.operator_question.as_ref())
            .and_then(PendingOperatorQuestion::other_editor)
    }

    fn apply_operator_question_key(&mut self, code: KeyCode) {
        if self
            .activity()
            .and_then(|session| session.operator_question.as_ref())
            .is_some_and(PendingOperatorQuestion::is_submitting)
        {
            return;
        }
        if self.question_other_editor().is_some() {
            self.apply_other_answer_key(code);
            return;
        }
        match code {
            KeyCode::Esc => self.cancel_operator_question(),
            KeyCode::Tab => self.with_operator_question_mut(PendingOperatorQuestion::open_other),
            KeyCode::Up | KeyCode::Char('k') => self.move_question_option(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_question_option(1),
            KeyCode::Left => self.move_active_question(-1),
            KeyCode::Right => self.move_active_question(1),
            KeyCode::Char(ch @ '1'..='3') => self.choose_question_number(ch),
            KeyCode::Enter => self.submit_operator_question_answer(),
            _ => {}
        }
    }

    fn apply_other_answer_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => self.with_operator_question_mut(|card| {
                card.leave_other();
            }),
            KeyCode::Enter => self.submit_operator_question_answer(),
            KeyCode::Char('\u{17}') => {
                self.with_operator_question_mut(PendingOperatorQuestion::delete_other_word_left)
            }
            _ => self.with_operator_question_mut(|card| card.edit_other(code)),
        }
    }

    pub(super) fn paste_operator_question_other(&mut self, text: &str) -> bool {
        if !self.operator_question_is_open() {
            return false;
        }
        self.with_operator_question_mut(PendingOperatorQuestion::open_other);
        self.activity_mut()
            .and_then(|session| session.operator_question.as_mut())
            .is_some_and(|card| card.paste_other(text))
    }

    fn with_operator_question_mut(&mut self, edit: impl FnOnce(&mut PendingOperatorQuestion)) {
        if let Some(card) = self
            .activity_mut()
            .and_then(|session| session.operator_question.as_mut())
        {
            edit(card);
        }
    }

    fn move_question_option(&mut self, delta: isize) {
        self.with_operator_question_mut(|card| card.move_option(delta));
    }

    fn move_active_question(&mut self, delta: isize) {
        self.with_operator_question_mut(|card| card.move_question(delta));
    }

    fn choose_question_number(&mut self, ch: char) {
        let number = ch.to_digit(10).unwrap_or_default() as usize;
        let selected = self
            .activity_mut()
            .and_then(|session| session.operator_question.as_mut())
            .is_some_and(|card| card.select_number(number));
        if selected {
            self.submit_operator_question_answer();
        }
    }

    fn submit_operator_question_answer(&mut self) {
        let finished = self
            .activity_mut()
            .and_then(|session| session.operator_question.as_mut())
            .is_some_and(PendingOperatorQuestion::submit_current);
        let _ = finished;
    }

    fn cancel_operator_question(&mut self) {
        let sent = self
            .activity_mut()
            .and_then(|session| session.operator_question.as_mut())
            .is_some_and(PendingOperatorQuestion::cancel);
        if !sent {
            self.log("agent", "operator question was already resolved");
        }
    }

    fn return_from_other_or_cancel_question(&mut self) {
        if self.question_other_editor().is_some() {
            self.with_operator_question_mut(|card| {
                card.leave_other();
            });
            return;
        }
        self.cancel_operator_question();
    }
}

fn question_default_action_id(key: KeyEvent, other_open: bool) -> Option<&'static str> {
    if !matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) {
        return None;
    }
    match key.code {
        KeyCode::Enter => Some("submit"),
        KeyCode::Esc => Some("cancel"),
        KeyCode::Char('b') if !other_open => Some("background"),
        KeyCode::Up | KeyCode::Char('k') => Some("previous_option"),
        KeyCode::Down | KeyCode::Char('j') => Some("next_option"),
        KeyCode::Left if !other_open => Some("previous_question"),
        KeyCode::Right if !other_open => Some("next_question"),
        KeyCode::Tab if !other_open => Some("other"),
        _ => None,
    }
}

fn operator_question_key_action(
    question_is_open: bool,
    other_is_open: bool,
    key: KeyEvent,
) -> OperatorQuestionKeyAction {
    if !question_is_open {
        return OperatorQuestionKeyAction::Ignore;
    }
    open_operator_question_key_action(other_is_open, key)
}

fn open_operator_question_key_action(
    other_is_open: bool,
    key: KeyEvent,
) -> OperatorQuestionKeyAction {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return OperatorQuestionKeyAction::Ignore;
    }
    if let Some(action) = operator_question_word_delete_action(other_is_open, key) {
        return action;
    }
    if !matches!(key.modifiers, KeyModifiers::NONE | KeyModifiers::SHIFT) {
        return OperatorQuestionKeyAction::Consume;
    }
    allowed_operator_question_key_action(other_is_open, key.code)
}

fn operator_question_word_delete_action(
    other_is_open: bool,
    key: KeyEvent,
) -> Option<OperatorQuestionKeyAction> {
    let ctrl_w = key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('w');
    let modified_backspace = key.code == KeyCode::Backspace
        && key
            .modifiers
            .intersects(KeyModifiers::ALT | KeyModifiers::CONTROL);
    if !ctrl_w && !modified_backspace {
        return None;
    }
    Some(if other_is_open {
        OperatorQuestionKeyAction::Apply(KeyCode::Char('\u{17}'))
    } else {
        OperatorQuestionKeyAction::Consume
    })
}

fn allowed_operator_question_key_action(
    other_is_open: bool,
    code: KeyCode,
) -> OperatorQuestionKeyAction {
    if code == KeyCode::Char('b') && !other_is_open {
        return OperatorQuestionKeyAction::Background;
    }
    OperatorQuestionKeyAction::Apply(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    #[test]
    fn question_card_releases_ctrl_c_to_the_shared_cancel_path() {
        assert_eq!(
            operator_question_key_action(
                true,
                false,
                key(KeyCode::Char('c'), KeyModifiers::CONTROL),
            ),
            OperatorQuestionKeyAction::Ignore
        );
    }

    #[test]
    fn background_key_edits_other_text_only_while_other_is_open() {
        let background =
            operator_question_key_action(true, false, key(KeyCode::Char('b'), KeyModifiers::NONE));
        let edit =
            operator_question_key_action(true, true, key(KeyCode::Char('b'), KeyModifiers::NONE));
        assert_eq!(background, OperatorQuestionKeyAction::Background);
        assert_eq!(edit, OperatorQuestionKeyAction::Apply(KeyCode::Char('b')));
    }

    #[test]
    fn closed_question_card_does_not_own_input() {
        let action =
            operator_question_key_action(false, false, key(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(action, OperatorQuestionKeyAction::Ignore);
    }

    #[test]
    fn terminal_alt_backspace_deletes_an_other_word() {
        let action =
            operator_question_key_action(true, true, key(KeyCode::Backspace, KeyModifiers::ALT));

        assert_eq!(
            action,
            OperatorQuestionKeyAction::Apply(KeyCode::Char('\u{17}'))
        );
    }

    #[test]
    fn ctrl_w_deletes_only_inside_the_other_editor() {
        let ctrl_w = key(KeyCode::Char('w'), KeyModifiers::CONTROL);

        assert_eq!(
            operator_question_key_action(true, true, ctrl_w),
            OperatorQuestionKeyAction::Apply(KeyCode::Char('\u{17}'))
        );
        assert_eq!(
            operator_question_key_action(true, false, ctrl_w),
            OperatorQuestionKeyAction::Consume
        );
    }
}
