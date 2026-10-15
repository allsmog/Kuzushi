use super::*;
use crossterm::event::KeyCode;

impl ShellApp {
    pub(super) fn handle_study_discard_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('d') => self.discard_study_choices(),
            KeyCode::Enter | KeyCode::Esc => {
                self.router
                    .campaign_mut()
                    .batch_scan_config
                    .as_mut()
                    .unwrap()
                    .draft_recovery = StudyDraftRecovery::None
            }
            _ => {}
        }
    }

    fn discard_study_choices(&mut self) {
        let config = self.router.campaign().batch_scan_config.as_ref().unwrap();
        if !super::changes::discovery_study(config) {
            self.discard_model_study_choices();
            return;
        }
        let target = config.target.clone();
        let record = self.discard_checkpoint_record(config);
        if let Some(record) = record {
            if let Err(error) = self.runtime_state.study_checkpoints.enqueue(record) {
                self.set_batch_config_notice(format!(
                    "Discard is not durable: {error}. An older draft may recover."
                ));
                return;
            }
        }
        self.runtime_state.brief_drafts.remove(&target);
        self.finish_closing_study();
    }

    fn discard_checkpoint_record(&self, config: &BatchScanConfig) -> Option<StudyCheckpointRecord> {
        let (_, session_id) = self.runtime_state.study_checkpoints.binding.as_ref()?;
        Some(StudyCheckpointRecord {
            version: 1,
            target: config.target.clone(),
            record_id: config.checkpoint_id.clone(),
            session_id: session_id.clone(),
            saved_at_seconds: 0,
            snapshot: None,
            resolved_hashes: config.checkpoint_origins.clone(),
        })
    }
}
