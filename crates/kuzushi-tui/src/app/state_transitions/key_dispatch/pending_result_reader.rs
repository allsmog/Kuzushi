use super::*;
use crate::app::guided_scan::GuidedScanStage;

impl ShellApp {
    pub(super) fn reduce_pending_result_reading_key(
        &mut self,
        key: KeyEvent,
    ) -> Option<InputUpdate> {
        if !self.pending_result_owns_reading() {
            return None;
        }
        if let Some(update) = self.reduce_pending_study_read_key(key) {
            return Some(update);
        }
        if key.modifiers != KeyModifiers::NONE {
            return None;
        }
        let direction = match key.code {
            KeyCode::PageDown => crate::renderer::PageDirection::Down,
            KeyCode::PageUp => crate::renderer::PageDirection::Up,
            _ => return None,
        };
        self.page_workbench_surface(direction)
            .then(InputUpdate::handled)
    }

    fn reduce_pending_study_read_key(&mut self, key: KeyEvent) -> Option<InputUpdate> {
        let KeyCode::Char(_) = key.code else {
            return None;
        };
        if self.input_mode() != InputMode::Navigate || !KeyModifierState::new(key).no_modifiers {
            return None;
        }
        let binding = self
            .view_keybindings()
            .into_iter()
            .find(|binding| binding.matches(key))?;
        if binding.action != ViewHotkeyAction::WorkbenchStudyJobs {
            return None;
        }
        self.reduce_configured_phase_result_key(key)
            .or_else(|| Some(self.apply_view_hotkey(binding.action)))
    }

    fn pending_result_owns_reading(&self) -> bool {
        self.phase_result_is_open()
            && !crate::ui_view_models::answers_own_input(self)
            && self.guided_flow_allows_result_reading()
    }

    fn guided_flow_allows_result_reading(&self) -> bool {
        self.engagement
            .guided_scan()
            .is_none_or(|flow| matches!(flow.stage(), GuidedScanStage::AwaitingResult { .. }))
    }
}
