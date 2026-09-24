//! Result-card keys that reach Navigate mode without an on-screen card.
//!
//! The RESULT READY card only renders on the Workbench, but its attention chip
//! is visible everywhere, and a lagging frame can show a card that an earlier
//! press already resolved. Navigate mode never edits the prompt, so neither
//! case may fall through to printable composer input: a card key off the
//! Workbench reveals the card it names, and a repeat of the key that just
//! resolved a card is absorbed.

use super::*;

impl ShellApp {
    /// Claim a default result-card key that the on-screen card did not own.
    pub(super) fn reduce_unclaimed_phase_result_key(
        &mut self,
        key: KeyEvent,
    ) -> Option<InputUpdate> {
        let ch = self.default_result_card_char(key)?;
        if let Some(phase) = self.phase_result_target_phase() {
            return Some(self.reveal_phase_result_card(phase, ch));
        }
        (self.editor().resolved_result_key() == Some(ch))
            .then(|| self.absorb_resolved_result_echo(ch))
    }

    /// After a card key was claimed: when no result remains pending, remember
    /// the key so its stale re-presses are absorbed, and drop a draft made only
    /// of card letters an earlier race typed into the composer.
    pub(super) fn settle_claimed_phase_result_key(&mut self, key: KeyEvent) {
        let KeyCode::Char(ch) = key.code else {
            return;
        };
        if self.phase_result_target_phase().is_some() {
            return;
        }
        self.editor_mut().set_resolved_result_key(Some(ch));
        if is_stray_result_card_draft(self.input()) {
            self.editor_mut().clear_input();
        }
    }

    /// Any key other than the remembered one ends the echo window.
    pub(super) fn expire_resolved_result_key(&mut self, key: KeyEvent) {
        let Some(resolved) = self.editor().resolved_result_key() else {
            return;
        };
        if key.code != KeyCode::Char(resolved) || !key.modifiers.is_empty() {
            self.editor_mut().set_resolved_result_key(None);
        }
    }

    fn default_result_card_char(&self, key: KeyEvent) -> Option<char> {
        let KeyCode::Char(ch) = key.code else {
            return None;
        };
        let command = PhaseResultCommand::from_default_key(key.code)?;
        let overridden = self
            .ui()
            .keymap_overrides_action("phase_result", command.action_id());
        (key.modifiers.is_empty() && !overridden).then_some(ch)
    }

    fn reveal_phase_result_card(&mut self, phase: WorkflowPhase, ch: char) -> InputUpdate {
        self.set_workbench_page(WorkbenchPage::from_phase(phase));
        self.set_info_notice(
            "result",
            format!(
                "{} result card opened — press {ch} again to apply it",
                phase.title()
            ),
        );
        InputUpdate::handled()
    }

    fn absorb_resolved_result_echo(&mut self, ch: char) -> InputUpdate {
        self.set_info_notice(
            "result",
            format!("{ch} already resolved that result · Esc returns to the prompt"),
        );
        InputUpdate::handled()
    }
}

fn is_stray_result_card_draft(input: &str) -> bool {
    !input.is_empty()
        && input
            .chars()
            .all(|ch| PhaseResultCommand::from_default_key(KeyCode::Char(ch)).is_some())
}

#[cfg(test)]
mod tests {
    use super::is_stray_result_card_draft;

    #[test]
    fn only_a_draft_made_of_card_letters_is_stray() {
        assert!(is_stray_result_card_draft("uuuu"));
        assert!(is_stray_result_card_draft("un"));
        assert!(!is_stray_result_card_draft(""));
        assert!(!is_stray_result_card_draft("use src/"));
        assert!(!is_stray_result_card_draft("scan"));
    }
}
