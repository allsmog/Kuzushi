use super::*;
use crate::app::{ContextEditMode, ShellApp};
use kuzushi_core::ThreatModelRef;

impl ShellApp {
    pub(crate) fn drain_context_checkpoints(&mut self) -> bool {
        let changed = self.runtime_state.context_checkpoints.drain_write();
        let Some(result) = self.runtime_state.context_checkpoints.take_recovery() else {
            return changed;
        };
        self.apply_recovered_context_draft(result);
        true
    }

    pub(in crate::app::batch_scan) fn checkpoint_context_draft(&mut self) {
        let Some(key) = self.context_edit_selection_key() else {
            return;
        };
        let Some(draft) = self.runtime_state.context_edit_drafts.get(&key) else {
            return;
        };
        if draft.mode == ContextEditMode::Recovery {
            return;
        }
        let source = draft.reference.clone();
        let snapshot = projection::snapshot(draft);
        let result =
            self.enqueue_context_checkpoint(key.0.clone(), source, Some(snapshot), Vec::new());
        self.note_context_checkpoint_error(&key, result);
    }

    pub(in crate::app::batch_scan) fn resolve_context_checkpoint(&mut self, key: &DraftKey) {
        let Some(draft) = self.runtime_state.context_edit_drafts.get(key) else {
            return;
        };
        let source = draft.reference.clone();
        let origins = draft.checkpoint_origins.clone();
        let result = self.enqueue_context_checkpoint(key.0.clone(), source, None, origins);
        self.note_context_checkpoint_error(key, result);
    }

    fn enqueue_context_checkpoint(
        &mut self,
        target: PathBuf,
        source: ThreatModelRef,
        snapshot: Option<kuzushi_core::session_transcript::ContextDraftSnapshot>,
        resolved_hashes: Vec<String>,
    ) -> anyhow::Result<()> {
        let runtime = &mut self.runtime_state.context_checkpoints;
        let Some((_, session_id)) = &runtime.binding else {
            return Ok(());
        };
        let record = ContextDraftRecord {
            version: 1,
            target,
            source,
            session_id: session_id.clone(),
            saved_at_seconds: 0,
            snapshot,
            resolved_hashes,
        };
        runtime.enqueue(record)
    }

    fn note_context_checkpoint_error(&mut self, key: &DraftKey, result: anyhow::Result<()>) {
        if let Err(error) = result {
            if let Some(draft) = self.runtime_state.context_edit_drafts.get_mut(key) {
                draft.notice = Some(format!(
                    "Local checkpoint not saved: {error}. Your text remains in this session."
                ));
            }
        }
    }

    pub(crate) fn context_checkpoint_note(&self) -> Option<String> {
        let key = self.context_edit_selection_key()?;
        let runtime = &self.runtime_state.context_checkpoints;
        if runtime.binding.is_none() {
            return Some("Session-only draft; durable session recording is unavailable.".into());
        }
        let state = runtime.states.get(&key)?;
        Some(match &state.status {
            CheckpointStatus::Pending => "Saving local draft…".into(),
            CheckpointStatus::Saved => "Draft saved locally.".into(),
            CheckpointStatus::Failed(error) => format!(
                "Local draft not saved: {error}. Keep this session open or save a context copy."
            ),
        })
    }

    pub(crate) fn context_checkpoints_pending(&self) -> bool {
        self.runtime_state.context_checkpoints.has_pending_writes()
    }

    pub(crate) fn context_checkpoint_cleanup_failed(&self) -> bool {
        self.runtime_state
            .context_checkpoints
            .states
            .values()
            .any(|state| {
                state.record.snapshot.is_none()
                    && matches!(state.status, CheckpointStatus::Failed(_))
            })
    }

    pub(crate) fn context_copies_not_checkpointed(&self) -> bool {
        self.runtime_state
            .context_edit_drafts
            .iter()
            .any(|(key, draft)| {
                draft
                    .entries
                    .iter()
                    .any(crate::app::ContextEditEntry::changed)
                    && !self.context_copy_checkpointed(key, draft)
            })
    }

    pub(crate) fn context_copies_checkpointed(&self) -> bool {
        self.runtime_state
            .context_edit_drafts
            .iter()
            .any(|(key, draft)| {
                draft
                    .entries
                    .iter()
                    .any(crate::app::ContextEditEntry::changed)
                    && self.context_copy_checkpointed(key, draft)
            })
    }

    fn context_copy_checkpointed(
        &self,
        key: &DraftKey,
        draft: &crate::app::ContextEditDraft,
    ) -> bool {
        self.runtime_state
            .context_checkpoints
            .states
            .get(key)
            .is_some_and(|state| {
                matches!(state.status, CheckpointStatus::Saved)
                    && state.record.source == draft.reference
                    && state.record.snapshot.as_ref() == Some(&projection::snapshot(draft))
            })
    }
}
