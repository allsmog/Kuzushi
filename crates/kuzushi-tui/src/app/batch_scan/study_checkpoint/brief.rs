use super::*;
use crate::app::{BriefEditor, BriefMode};
use kuzushi_core::capabilities::campaign::{BriefRevision, MAX_BRIEF_TEXT_BYTES};

impl ShellApp {
    pub(super) fn unsaved_study_brief(&self, config: &BatchScanConfig) -> Option<BriefCheckpoint> {
        let editor = self.runtime_state.brief_drafts.get(&config.target)?;
        let base = editor
            .loaded
            .as_ref()
            .map_or("", |brief| brief.document.text.as_str());
        if editor.editor.text() == base {
            return None;
        }
        let mode = checkpoint_mode(editor.mode)?;
        Some(BriefCheckpoint {
            base_ref: editor.loaded.as_ref().map(|b| b.reference.clone()),
            field: DraftText {
                text: editor.editor.text().into(),
                cursor: editor.editor.cursor(),
            },
            mode,
            scroll: editor.scroll,
            open: config.brief_open,
        })
    }
}

fn checkpoint_mode(mode: BriefMode) -> Option<BriefCheckpointMode> {
    [
        (BriefMode::Loading, BriefCheckpointMode::Read),
        (BriefMode::Read, BriefCheckpointMode::Read),
        (BriefMode::Writing, BriefCheckpointMode::Writing),
        (BriefMode::Review, BriefCheckpointMode::Review),
        (BriefMode::Saving, BriefCheckpointMode::Saving),
    ]
    .into_iter()
    .find_map(|(from, to)| (from == mode).then_some(to))
}

pub(super) fn restore(
    draft: &BriefCheckpoint,
    base: Option<BriefRevision>,
) -> anyhow::Result<BriefEditor> {
    draft.validate()?;
    let mut editor = FieldEditor::new(&draft.field.text);
    editor.restore_cursor(draft.field.cursor)?;
    let mode = restored_mode(draft.mode);
    Ok(BriefEditor {mode,loaded:base,editor,scroll:draft.scroll,preserve_text:false,pending_study:None,
        notice:Some("Goal draft recovered locally. Review and save a revision before using it. Interrupted saves are not replayed; r reads the current base.".into())})
}

fn restored_mode(mode: BriefCheckpointMode) -> BriefMode {
    match mode {
        BriefCheckpointMode::Read => BriefMode::Read,
        BriefCheckpointMode::Writing => BriefMode::Writing,
        BriefCheckpointMode::Review | BriefCheckpointMode::Saving => BriefMode::Review,
    }
}

impl BriefCheckpoint {
    pub(super) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.field.text.len() <= MAX_BRIEF_TEXT_BYTES && !self.field.text.contains('\0'),
            "Saved goal exceeds its text limit"
        );
        anyhow::ensure!(
            self.field.cursor <= self.field.text.chars().count(),
            "Saved goal cursor is outside its text"
        );
        anyhow::ensure!(
            self.scroll <= 8 * 1024 * 1024,
            "Saved goal scroll is out of range"
        );
        Ok(())
    }
}

impl ShellApp {
    pub(crate) fn uncheckpointed_goal_drafts(&self) -> bool {
        self.runtime_state
            .brief_drafts
            .iter()
            .any(|(target, editor)| {
                has_edits(editor) && !self.goal_checkpoint_matches(target, editor)
            })
    }

    fn goal_checkpoint_matches(&self, target: &std::path::Path, editor: &BriefEditor) -> bool {
        self.runtime_state
            .study_checkpoints
            .states
            .values()
            .any(|state| {
                state.record.target == target
                    && matches!(state.status, WriteStatus::Saved)
                    && saved_goal_matches(&state.record, editor)
            })
    }
}

pub(super) fn has_edits(editor: &BriefEditor) -> bool {
    editor.editor.text()
        != editor
            .loaded
            .as_ref()
            .map_or("", |b| b.document.text.as_str())
}

impl ShellApp {
    pub(super) fn conflicting_goal_draft(
        &self,
        target: &std::path::Path,
        outcome: &Result<super::recovery::RecoveryOutcome, String>,
    ) -> bool {
        let Ok(super::recovery::RecoveryOutcome::Selected { dependencies, .. }) = outcome else {
            return false;
        };
        let Some(recovered) = &dependencies.brief_draft else {
            return false;
        };
        self.runtime_state
            .brief_drafts
            .get(target)
            .is_some_and(|current| has_edits(current) && !same_goal(current, recovered))
    }
}

fn saved_goal_matches(record: &StudyCheckpointRecord, editor: &BriefEditor) -> bool {
    let Some(goal) = record
        .snapshot
        .as_ref()
        .and_then(|s| s.brief_draft.as_ref())
    else {
        return false;
    };
    goal.field.text == editor.editor.text()
        && goal.field.cursor == editor.editor.cursor()
        && goal.base_ref.as_ref() == editor.loaded.as_ref().map(|b| &b.reference)
}

fn same_goal(left: &BriefEditor, right: &BriefEditor) -> bool {
    left.editor == right.editor
        && left.loaded.as_ref().map(|b| &b.reference) == right.loaded.as_ref().map(|b| &b.reference)
}
