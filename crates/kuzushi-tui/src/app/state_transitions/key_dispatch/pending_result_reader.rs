use super::*;
use crate::app::guided_scan::GuidedScanStage;

impl ShellApp {
    pub(super) fn reduce_pending_result_reading_key(
        &mut self,
        key: KeyEvent,
    ) -> Option<InputUpdate> {
        if !self.pending_result_owns_reading() || key.modifiers != KeyModifiers::NONE {
            return None;
        }
        crate::renderer::workbench_scroll_page_rows(self)?;
        match key.code {
            KeyCode::PageDown => self.page_down_current_view(),
            KeyCode::PageUp => self.page_up_current_view(),
            _ => return None,
        }
        Some(InputUpdate::handled())
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
