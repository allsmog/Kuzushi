use super::*;
use crate::app::{ContextDraftRecovery, ContextEditMode, ShellApp};
use kuzushi_core::ThreatModelRef;

pub(super) struct RecoveryResult {
    pub key: DraftKey,
    pub source: ThreatModelRef,
    pub result: Result<Vec<RecoveredContextDraft>, String>,
}

impl ContextCheckpointRuntime {
    fn start_recovery(&mut self, target: PathBuf, source: ThreatModelRef) -> anyhow::Result<bool> {
        let Some((store, _)) = &self.binding else {
            return Ok(false);
        };
        anyhow::ensure!(
            self.recovery.is_none(),
            "A draft recovery is finishing. Enter retries after it settles."
        );
        let store = store.clone();
        self.recovery_request = Some((
            (target.clone(), source.revision_id.as_str().into()),
            source.clone(),
        ));
        let (send, receive) = mpsc::channel();
        std::thread::Builder::new()
            .name("context-draft-recovery".into())
            .spawn(move || {
                let result = store
                    .recover(&target, &source)
                    .map_err(|error| error.to_string());
                let key = (target, source.revision_id.as_str().into());
                let _ = send.send(RecoveryResult {
                    key,
                    source,
                    result,
                });
            })?;
        self.recovery = Some(receive);
        Ok(true)
    }

    pub(super) fn take_recovery(&mut self) -> Option<RecoveryResult> {
        let receive = self.recovery.as_ref()?;
        match receive.try_recv() {
            Ok(result) => {
                self.recovery = None;
                self.recovery_request = None;
                Some(result)
            }
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.recovery = None;
                self.recovery_request
                    .take()
                    .map(|(key, source)| RecoveryResult {
                        key,
                        source,
                        result: Err("Draft recovery worker stopped; checkpoints retained".into()),
                    })
            }
        }
    }
}

impl ShellApp {
    pub(in crate::app::batch_scan) fn start_context_draft_recovery(&mut self, key: &DraftKey) {
        let Some(draft) = self.runtime_state.context_edit_drafts.get(key) else {
            return;
        };
        let result = self
            .runtime_state
            .context_checkpoints
            .start_recovery(key.0.clone(), draft.reference.clone());
        let draft = self.runtime_state.context_edit_drafts.get_mut(key).unwrap();
        match result {
            Ok(false) => {}
            Ok(true) => {
                draft.mode = ContextEditMode::Recovery;
                draft.recovery = ContextDraftRecovery::Loading;
            }
            Err(error) => {
                draft.mode = ContextEditMode::Recovery;
                draft.recovery = ContextDraftRecovery::Failed(error.to_string());
            }
        }
    }

    pub(super) fn apply_recovered_context_draft(&mut self, result: RecoveryResult) {
        let Some(draft) = self
            .runtime_state
            .context_edit_drafts
            .get_mut(&result.key)
            .filter(|draft| draft.reference == result.source)
        else {
            return;
        };
        match result.result {
            Ok(records) => install_recovery(draft, records),
            Err(error) => draft.recovery = ContextDraftRecovery::Failed(error),
        }
    }

    pub(in crate::app::batch_scan) fn handle_context_recovery_key(
        &mut self,
        code: crossterm::event::KeyCode,
    ) {
        use crossterm::event::KeyCode;
        if code == KeyCode::Enter {
            self.select_context_recovery();
            return;
        }
        let Some(draft) = self.context_edit_draft_mut() else {
            return;
        };
        if code == KeyCode::Char('n')
            && matches!(draft.recovery, ContextDraftRecovery::Choices { .. })
        {
            draft.mode = ContextEditMode::Fields;
            draft.recovery = Default::default();
            return;
        }
        if let ContextDraftRecovery::Choices { drafts, cursor } = &mut draft.recovery {
            move_recovery_cursor(cursor, drafts.len(), code);
        }
    }

    fn select_context_recovery(&mut self) {
        let Some(key) = self.context_edit_selection_key() else {
            return;
        };
        let draft = self.runtime_state.context_edit_drafts.get(&key).unwrap();
        let ContextDraftRecovery::Choices { drafts, cursor } = &draft.recovery else {
            self.start_context_draft_recovery(&key);
            return;
        };
        let result = projection::restore(draft, &drafts[*cursor]);
        match result {
            Ok(draft) => {
                self.runtime_state.context_edit_drafts.insert(key, draft);
                self.checkpoint_context_draft();
            }
            Err(error) => self.context_edit_draft_mut().unwrap().notice = Some(error.to_string()),
        }
    }
}

fn install_recovery(draft: &mut crate::app::ContextEditDraft, records: Vec<RecoveredContextDraft>) {
    if records.is_empty() {
        draft.mode = ContextEditMode::Fields;
        draft.recovery = Default::default();
        return;
    }
    draft.recovery = ContextDraftRecovery::Choices {
        drafts: records,
        cursor: 0,
    };
}

fn move_recovery_cursor(cursor: &mut usize, count: usize, code: crossterm::event::KeyCode) {
    use crossterm::event::KeyCode;
    match code {
        KeyCode::Up => *cursor = cursor.saturating_sub(1),
        KeyCode::Down => *cursor = (*cursor + 1).min(count.saturating_sub(1)),
        _ => {}
    }
}
