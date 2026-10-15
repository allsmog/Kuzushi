use super::*;
use crate::app::state_transitions::InputUpdate;

impl ShellApp {
    pub(crate) fn checkpoint_study_choices(&mut self) {
        let Some(config) = self.router.campaign().batch_scan_config.as_ref() else {
            return;
        };
        if config.draft_recovery != StudyDraftRecovery::None
            || !super::changes::discovery_study(config)
        {
            return;
        }
        let Some((_, session_id)) = &self.runtime_state.study_checkpoints.binding else {
            return;
        };
        let record = self.study_checkpoint_record(config, session_id.clone());
        if record
            .as_ref()
            .is_ok_and(|r| r.snapshot.is_none() && r.resolved_hashes.is_empty())
            && !self
                .runtime_state
                .study_checkpoints
                .states
                .contains_key(&config.checkpoint_id)
        {
            return;
        }
        let result = record.and_then(|record| self.runtime_state.study_checkpoints.enqueue(record));
        self.record_checkpoint_enqueue_result(result);
    }

    fn record_checkpoint_enqueue_result(&mut self, result: anyhow::Result<()>) {
        let config = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        config.checkpoint_error = result
            .err()
            .map(|error| format!("Study choices not saved: {error}"));
    }

    fn study_checkpoint_record(
        &self,
        config: &BatchScanConfig,
        session_id: String,
    ) -> anyhow::Result<StudyCheckpointRecord> {
        let snapshot = if self.unfinished_study_choices(config) {
            Some(self.capture_study_checkpoint(config)?)
        } else {
            None
        };
        let resolved_hashes = config.checkpoint_origins.clone();
        Ok(StudyCheckpointRecord {
            version: 1,
            target: config.target.clone(),
            record_id: config.checkpoint_id.clone(),
            session_id,
            saved_at_seconds: 0,
            snapshot,
            resolved_hashes,
        })
    }

    pub(crate) fn drain_study_checkpoints(&mut self) -> bool {
        let changed = self.runtime_state.study_checkpoints.drain_write();
        self.apply_study_draft_recovery() | changed
    }

    pub(crate) fn study_checkpoint_note(&self) -> Option<String> {
        let config = self.router.campaign().batch_scan_config.as_ref()?;
        if !self.unfinished_study_choices(config) {
            return None;
        }
        config
            .checkpoint_error
            .clone()
            .or_else(|| self.study_checkpoint_status_note(config))
    }

    fn study_checkpoint_status_note(&self, config: &BatchScanConfig) -> Option<String> {
        let runtime = &self.runtime_state.study_checkpoints;
        if runtime.binding.is_none() {
            return Some(
                "Session-only study choices; durable session storage is unavailable.".into(),
            );
        }
        let state = runtime.states.get(&config.checkpoint_id)?;
        Some(match &state.status {
            WriteStatus::Pending => "Saving local study choices…".into(),
            WriteStatus::Saved if self.current_study_checkpoint_saved(config) => {
                "Study choices saved locally. Work still needs approval.".into()
            }
            WriteStatus::Saved => {
                "Latest study choices are not saved; keep this session open.".into()
            }
            WriteStatus::Failed(error) => format!("Study choices not saved: {error}"),
        })
    }

    pub(crate) fn study_choices_not_checkpointed(&self) -> bool {
        let Some(config) = self.router.campaign().batch_scan_config.as_ref() else {
            return false;
        };
        self.unfinished_study_choices(config) && !self.current_study_checkpoint_saved(config)
    }

    pub(crate) fn study_choices_checkpointed(&self) -> bool {
        let Some(config) = self.router.campaign().batch_scan_config.as_ref() else {
            return false;
        };
        self.unfinished_study_choices(config) && self.current_study_checkpoint_saved(config)
    }

    fn current_study_checkpoint_saved(&self, config: &BatchScanConfig) -> bool {
        let runtime = &self.runtime_state.study_checkpoints;
        let Some(state) = runtime.states.get(&config.checkpoint_id) else {
            return false;
        };
        let Ok(snapshot) = self.capture_study_checkpoint(config) else {
            return false;
        };
        matches!(state.status, WriteStatus::Saved)
            && state.record.snapshot.as_ref() == Some(&snapshot)
    }

    pub(crate) fn study_checkpoint_pending(&self) -> bool {
        self.runtime_state.study_checkpoints.has_pending()
    }

    pub(crate) fn study_checkpoint_cleanup_failed(&self) -> bool {
        self.runtime_state
            .study_checkpoints
            .states
            .values()
            .any(|state| {
                state.record.snapshot.is_none() && matches!(state.status, WriteStatus::Failed(_))
            })
    }

    pub(crate) fn study_draft_recovery_open(&self) -> bool {
        self.batch_config_open()
            && self
                .router
                .campaign()
                .batch_scan_config
                .as_ref()
                .is_some_and(|c| c.draft_recovery != StudyDraftRecovery::None)
    }

    pub(in crate::app::batch_scan) fn study_recovery_input(
        &mut self,
        code: crossterm::event::KeyCode,
    ) -> InputUpdate {
        self.handle_study_draft_recovery_key(code);
        InputUpdate::handled()
    }
}
