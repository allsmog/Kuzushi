use super::*;
use crossterm::event::KeyCode;

pub(super) enum RecoveryOutcome {
    List(Vec<RecoveredStudyDraft>),
    Selected {
        saved: RecoveredStudyDraft,
        dependencies: RestoreDependencies,
    },
}

pub(super) struct RestoreDependencies {
    pub(super) brief_draft: Option<crate::app::BriefEditor>,
    pub(super) brief: Option<kuzushi_core::capabilities::campaign::BriefRevision>,
    pub(super) accounting: Result<Option<kuzushi_core::allowance::AllowanceSnapshot>, String>,
}

impl ShellApp {
    pub(in crate::app::batch_scan) fn start_study_draft_recovery(&mut self) {
        let Some(config) = self.router.campaign().batch_scan_config.as_ref() else {
            return;
        };
        let Some((store, _)) = &self.runtime_state.study_checkpoints.binding else {
            return;
        };
        let store = store.clone();
        let target = config.target.clone();
        let id = config.checkpoint_id.clone();
        let result = start_reader(store, target.clone());
        let config = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap();
        match result {
            Ok(receive) => {
                config.draft_recovery = StudyDraftRecovery::Loading;
                self.runtime_state.study_checkpoints.recovery = Some((id, target, receive));
            }
            Err(error) => config.draft_recovery = StudyDraftRecovery::Failed(error.to_string()),
        }
    }

    pub(super) fn apply_study_draft_recovery(&mut self) -> bool {
        let Some((id, target, mut result)) = self.runtime_state.study_checkpoints.take_recovery()
        else {
            return false;
        };
        if self.conflicting_goal_draft(&target, &result) {
            result = Err("An unsaved goal is already open in this session. Choose n for a new study and review that text before restoring another draft.".into());
        }
        let Some(config) = self
            .router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .filter(|c| c.checkpoint_id == id && c.target == target)
        else {
            return false;
        };
        let target = config.target.clone();
        if let Some(editor) = apply_outcome(config, result) {
            self.runtime_state.brief_drafts.insert(target, editor);
        }
        self.refresh_batch_worker_resolution();
        self.checkpoint_study_choices();
        true
    }

    pub(super) fn handle_study_draft_recovery_key(&mut self, code: KeyCode) {
        if self
            .router
            .campaign()
            .batch_scan_config
            .as_ref()
            .is_some_and(|c| c.draft_recovery == StudyDraftRecovery::Discard)
        {
            self.handle_study_discard_key(code);
            return;
        }
        self.handle_saved_study_key(code);
    }

    fn handle_saved_study_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Enter => {
                self.restore_study_draft_if_ready();
                return;
            }
            KeyCode::Esc => {
                self.close_batch_config();
                return;
            }
            _ => {}
        }
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        if code == KeyCode::Char('n')
            && matches!(
                config.draft_recovery,
                StudyDraftRecovery::Choices { .. } | StudyDraftRecovery::Failed(_)
            )
        {
            config.draft_recovery = Default::default();
            return;
        }
        if let StudyDraftRecovery::Choices { drafts, cursor } = &mut config.draft_recovery {
            move_cursor(cursor, drafts.len(), code);
        }
    }

    fn restore_study_draft_if_ready(&mut self) {
        if matches!(
            self.router
                .campaign()
                .batch_scan_config
                .as_ref()
                .map(|c| &c.draft_recovery),
            Some(StudyDraftRecovery::Loading)
        ) {
            return;
        }
        self.restore_selected_study_draft();
    }

    fn restore_selected_study_draft(&mut self) {
        let Some(config) = self.router.campaign().batch_scan_config.as_ref() else {
            return;
        };
        let StudyDraftRecovery::Choices { drafts, cursor } = &config.draft_recovery else {
            self.start_study_draft_recovery();
            return;
        };
        let recovered = drafts[*cursor].clone();
        let target = config.target.clone();
        let id = config.checkpoint_id.clone();
        let result = super::dependencies::start_selected(target.clone(), recovered);
        match result {
            Ok(receive) => {
                self.runtime_state.study_checkpoints.recovery = Some((id, target, receive));
                self.router
                    .campaign_mut()
                    .batch_scan_config
                    .as_mut()
                    .unwrap()
                    .draft_recovery = StudyDraftRecovery::Loading;
            }
            Err(error) => {
                self.router
                    .campaign_mut()
                    .batch_scan_config
                    .as_mut()
                    .unwrap()
                    .draft_recovery = StudyDraftRecovery::Failed(error.to_string())
            }
        }
    }
}

impl StudyCheckpointRuntime {
    fn take_recovery(&mut self) -> Option<(String, PathBuf, Result<RecoveryOutcome, String>)> {
        let (_, _, receive) = self.recovery.as_ref()?;
        let result = match receive.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return None,
            Err(mpsc::TryRecvError::Disconnected) => {
                Err("Study recovery worker stopped; original files retained".into())
            }
        };
        let (id, target, _) = self.recovery.take().unwrap();
        Some((id, target, result))
    }
}

fn start_reader(
    store: EditorCheckpointStore,
    target: PathBuf,
) -> anyhow::Result<Receiver<Result<RecoveryOutcome, String>>> {
    let (send, receive) = mpsc::channel();
    std::thread::Builder::new()
        .name("study-draft-recovery".into())
        .spawn(move || {
            let _ = send.send(
                persistence::recover(&store, &target)
                    .map(RecoveryOutcome::List)
                    .map_err(|error| error.to_string()),
            );
        })?;
    Ok(receive)
}

fn restore_record(
    config: &mut BatchScanConfig,
    saved: &RecoveredStudyDraft,
    dependencies: RestoreDependencies,
) -> anyhow::Result<Option<crate::app::BriefEditor>> {
    anyhow::ensure!(
        saved.record.target == config.target,
        "Saved study belongs to another target"
    );
    let snapshot = saved
        .record
        .snapshot
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Study checkpoint is already resolved"))?;
    projection::restore(config, snapshot)?;
    config.checkpoint_origins.push(saved.hash.clone());
    config.checkpoint_origins.sort();
    config.checkpoint_origins.dedup();
    anyhow::ensure!(
        config.checkpoint_origins.len() <= 32,
        "Study draft recovery chain reached its limit; original draft retained"
    );
    config.study.brief = dependencies.brief;
    install_accounting(config, dependencies.accounting);
    config.brief_open = snapshot.brief_draft.as_ref().is_some_and(|d| d.open);
    Ok(dependencies.brief_draft)
}

fn install_accounting(
    config: &mut BatchScanConfig,
    result: Result<Option<kuzushi_core::allowance::AllowanceSnapshot>, String>,
) {
    match result {
        Ok(value) => {
            config.study.allowance = value;
            config.study.accounting_error = None;
        }
        Err(error) => {
            config.study.accounting_error = Some(format!(
                "Recorded spending unavailable: {error}. Recovery does not reset it."
            ))
        }
    }
}

fn apply_outcome(
    config: &mut BatchScanConfig,
    outcome: Result<RecoveryOutcome, String>,
) -> Option<crate::app::BriefEditor> {
    match outcome {
        Ok(RecoveryOutcome::List(drafts)) => {
            config.draft_recovery = if drafts.is_empty() {
                StudyDraftRecovery::None
            } else {
                StudyDraftRecovery::Choices { drafts, cursor: 0 }
            }
        }
        Ok(RecoveryOutcome::Selected {
            saved,
            dependencies,
        }) => {
            let mut next = config.clone();
            match restore_record(&mut next, &saved, dependencies) {
                Ok(editor) => {
                    *config = next;
                    return editor;
                }
                Err(error) => config.draft_recovery = StudyDraftRecovery::Failed(error.to_string()),
            }
        }
        Err(error) => config.draft_recovery = StudyDraftRecovery::Failed(error),
    }
    None
}

fn move_cursor(cursor: &mut usize, count: usize, code: KeyCode) {
    match code {
        KeyCode::Up => *cursor = cursor.saturating_sub(1),
        KeyCode::Down => *cursor = (*cursor + 1).min(count.saturating_sub(1)),
        _ => {}
    }
}
