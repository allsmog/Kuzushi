//! Recover operator choices, never a frozen plan or spending authorization.
use super::{BatchScanConfig, BatchScanConfigRow};
use crate::app::{FieldEditor, ShellApp};
use kuzushi_core::capabilities::campaign::{
    BriefReference, ContextCaseInput, ScopeStudyCaseInput, MAX_CONTEXT_CASES,
};
use kuzushi_core::session_transcript::{DraftText, EditorCheckpointFile, EditorCheckpointStore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
mod application;
mod brief;
mod changes;
mod dependencies;
mod discard;
mod persistence;
mod projection;
mod recovery;
mod validation;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StudyCheckpointRecord {
    version: u8,
    record_id: String,
    session_id: String,
    target: PathBuf,
    saved_at_seconds: u64,
    snapshot: Option<StudyCheckpointSnapshot>,
    resolved_hashes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StudyCheckpointSnapshot {
    investigation_id: String,
    trials: usize,
    requested_workers: usize,
    scan_input: serde_json::Value,
    cases: Vec<ContextCaseInput>,
    baseline_case_id: Option<String>,
    matrix_cursor: usize,
    matrix_open: bool,
    form_cursor: usize,
    detail_scroll: usize,
    name_edit: Option<CaseNameCheckpoint>,
    number_edit: Option<NumberCheckpoint>,
    max_provider_calls: Option<usize>,
    protected_review_calls: Option<usize>,
    max_job_attempts: usize,
    prior_run_id: Option<String>,
    prior_campaign_id: Option<String>,
    context_baseline_run_id: Option<String>,
    brief_ref: Option<BriefReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    brief_draft: Option<BriefCheckpoint>,
    scope: Option<ScopeCheckpoint>,
    origin_hashes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BriefCheckpoint {
    base_ref: Option<BriefReference>,
    field: DraftText,
    mode: BriefCheckpointMode,
    scroll: usize,
    open: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum BriefCheckpointMode {
    Read,
    Writing,
    Review,
    Saving,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ScopeCheckpoint {
    proposal_ref: kuzushi_core::workspace::ScanScopeProposalRef,
    cases: Vec<ScopeStudyCaseInput>,
    labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CaseNameCheckpoint {
    case_id: String,
    field: DraftText,
    open: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NumberCheckpoint {
    row: String,
    field: DraftText,
}

pub(super) fn resource_choices_changed(config: &BatchScanConfig) -> bool {
    let Some(initial) = &config.checkpoint_initial else {
        return false;
    };
    (
        config.study.max_provider_calls,
        config.study.protected_review_calls,
    ) != (initial.max_provider_calls, initial.protected_review_calls)
}

#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) enum StudyDraftRecovery {
    #[default]
    None,
    Loading,
    Choices {
        drafts: Vec<RecoveredStudyDraft>,
        cursor: usize,
    },
    Failed(String),
    Discard,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RecoveredStudyDraft {
    record: StudyCheckpointRecord,
    hash: String,
}

impl RecoveredStudyDraft {
    pub(crate) fn goal_draft(&self) -> Option<&str> {
        self.record
            .snapshot
            .as_ref()?
            .brief_draft
            .as_ref()
            .map(|draft| draft.field.text.as_str())
    }

    pub(crate) fn repetitions(&self) -> usize {
        self.record
            .snapshot
            .as_ref()
            .map_or(0, |snapshot| snapshot.trials)
    }

    pub(crate) fn scope_labels(&self) -> Vec<(String, usize)> {
        let Some(scope) = self.record.snapshot.as_ref().and_then(|s| s.scope.as_ref()) else {
            return Vec::new();
        };
        scope
            .cases
            .iter()
            .map(|case| {
                (
                    scope
                        .labels
                        .get(&case.scope_id)
                        .unwrap_or(&case.scope_id)
                        .clone(),
                    case.passes,
                )
            })
            .collect()
    }

    pub(crate) fn has_selected_scope(&self) -> bool {
        self.record
            .snapshot
            .as_ref()
            .is_some_and(|s| s.scan_input.get("scanScopeRef").is_some())
    }

    pub(crate) fn name_draft(&self) -> Option<&str> {
        self.record
            .snapshot
            .as_ref()?
            .name_edit
            .as_ref()
            .map(|edit| edit.field.text.as_str())
    }

    pub(crate) fn cases(&self) -> Vec<(String, usize, bool)> {
        self.record
            .snapshot
            .as_ref()
            .map_or_else(Vec::new, |snapshot| {
                snapshot
                    .cases
                    .iter()
                    .map(|case| {
                        (
                            case.label.clone(),
                            case.passes,
                            snapshot.baseline_case_id.as_deref() == Some(&case.id),
                        )
                    })
                    .collect()
            })
    }
}

#[derive(Debug, Default)]
pub(crate) struct StudyCheckpointRuntime {
    binding: Option<(EditorCheckpointStore, String)>,
    states: BTreeMap<String, StudyWriteState>,
    pending: BTreeMap<String, (u64, StudyCheckpointRecord)>,
    active: Option<(String, u64, Receiver<Result<(), String>>)>,
    recovery: Option<(
        String,
        PathBuf,
        Receiver<Result<recovery::RecoveryOutcome, String>>,
    )>,
}

#[derive(Debug)]
struct StudyWriteState {
    generation: u64,
    record: StudyCheckpointRecord,
    status: WriteStatus,
}

#[derive(Debug)]
enum WriteStatus {
    Pending,
    Saved,
    Failed(String),
}

#[cfg(test)]
mod tests;
