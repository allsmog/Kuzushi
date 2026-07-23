use crate::WorkflowPhase;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_RECEIPT_ARTIFACT_PREVIEW: usize = 32;
const MAX_RECEIPT_ARTIFACT_BYTES: usize = 512;
const MAX_RECEIPT_RERUN_BYTES: usize = 8 * 1024;
const MAX_RECEIPT_RECOMMENDATION_BYTES: usize = 2 * 1024;
const MAX_RECEIPT_COST_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhaseTargetSnapshot {
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(default)]
    pub dirty: bool,
}

impl PhaseTargetSnapshot {
    pub fn capture(target: impl AsRef<Path>) -> Self {
        let target = target.as_ref();
        let identity = canonical_target_identity(target);
        let git = crate::workspace::target_git_metadata(target);
        Self {
            target: identity,
            revision: git.as_ref().map(|metadata| metadata.sha.clone()),
            dirty: git.is_some_and(|metadata| metadata.dirty),
        }
    }

    pub(crate) fn equivalent_to(&self, other: &Self) -> bool {
        target_identities_match(&self.target, &other.target)
            && self.revision == other.revision
            && self.dirty == other.dirty
    }
}

pub(crate) fn canonical_target_identity(target: impl AsRef<Path>) -> String {
    let target = target.as_ref();
    target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf())
        .display()
        .to_string()
}

pub(crate) fn target_identities_match(left: &str, right: &str) -> bool {
    canonical_target_identity(left) == canonical_target_identity(right)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseAttemptOutcome {
    Completed,
    Partial,
    Failed,
    Canceled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseAttemptDerivation {
    Original,
    Refine,
    Regenerate,
}

/// Operator actions offered for one completed phase attempt.
///
/// These values are persisted with the attempt receipt so a restarted shell
/// restores the exact review contract that was offered when the run finished,
/// instead of guessing actions from the current presentation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseResultAction {
    Select,
    SelectAndContinue,
    SelectAndReport,
    Open,
    Refine,
    RunAgain,
    Regenerate,
    Discard,
    /// Resume the failed run from its stage/loop checkpoint by
    /// re-dispatching the identical recorded input. Offered only when a
    /// live checkpoint exists — never persisted into attempt receipts,
    /// because checkpoint state changes after the receipt is written.
    ContinueRun,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhaseAttemptReceipt {
    pub run_count: usize,
    pub elapsed_secs: u64,
    pub cost: String,
    pub changed_findings: u64,
    /// Bounded preview only. Canonical run artifacts remain authoritative; a
    /// final marker reports entries omitted from the durable receipt.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed_artifacts: Vec<String>,
    pub interaction_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rerun_specification: Option<String>,
    pub actions: Vec<PhaseResultAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_next: Option<String>,
}

impl PhaseAttemptReceipt {
    fn bound_metadata(&mut self) {
        truncate_utf8(&mut self.cost, MAX_RECEIPT_COST_BYTES);
        bound_artifact_preview(&mut self.changed_artifacts);
        bound_optional_text(&mut self.rerun_specification, MAX_RECEIPT_RERUN_BYTES);
        bound_optional_text(&mut self.recommended_next, MAX_RECEIPT_RECOMMENDATION_BYTES);
        deduplicate_actions(&mut self.actions);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhaseAttemptCompleted {
    pub attempt_id: String,
    pub phase: WorkflowPhase,
    pub run_refs: Vec<String>,
    pub target_snapshot: PhaseTargetSnapshot,
    pub outcome: PhaseAttemptOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_blocked_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_attempt_id: Option<String>,
    pub derivation: PhaseAttemptDerivation,
    pub completed_at_unix: u64,
    /// Added after the original attempt-ledger format. Legacy events omit it
    /// and continue to project with conservative phase-derived actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<PhaseAttemptReceipt>,
}

impl PhaseAttemptCompleted {
    pub fn new(
        phase: WorkflowPhase,
        run_refs: Vec<String>,
        target_snapshot: PhaseTargetSnapshot,
        outcome: PhaseAttemptOutcome,
    ) -> Self {
        Self {
            attempt_id: new_phase_attempt_id(),
            phase,
            run_refs,
            target_snapshot,
            outcome,
            selection_blocked_reason: None,
            parent_attempt_id: None,
            derivation: PhaseAttemptDerivation::Original,
            completed_at_unix: now_unix(),
            receipt: None,
        }
    }

    pub fn derived_from(
        mut self,
        parent_attempt_id: impl Into<String>,
        derivation: PhaseAttemptDerivation,
    ) -> Self {
        self.parent_attempt_id = Some(parent_attempt_id.into());
        self.derivation = derivation;
        self
    }

    pub fn with_attempt_id(mut self, attempt_id: impl Into<String>) -> Self {
        self.attempt_id = attempt_id.into();
        self
    }

    pub fn with_receipt(mut self, receipt: PhaseAttemptReceipt) -> Self {
        self.receipt = Some(receipt);
        self.bound_receipt_metadata();
        self
    }

    pub(crate) fn bound_receipt_metadata(&mut self) {
        if let Some(receipt) = self.receipt.as_mut() {
            receipt.bound_metadata();
        }
    }

    pub fn with_selection_blocked(mut self, reason: impl Into<String>) -> Self {
        self.selection_blocked_reason = Some(reason.into());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PhaseAttemptDisposition {
    Selected { acknowledged_partial: bool },
    Discarded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhaseAttemptDispositionRecorded {
    pub attempt_id: String,
    pub disposition: PhaseAttemptDisposition,
    pub recorded_at_unix: u64,
}

impl PhaseAttemptDispositionRecorded {
    pub fn new(attempt_id: impl Into<String>, disposition: PhaseAttemptDisposition) -> Self {
        Self {
            attempt_id: attempt_id.into(),
            disposition,
            recorded_at_unix: now_unix(),
        }
    }
}

/// Durable acknowledgement that an operator intentionally skipped a phase
/// checkpoint for one exact target snapshot. A skip has no run reference and
/// therefore never masquerades as a completed attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhaseCheckpointSkipped {
    pub phase: WorkflowPhase,
    pub target_snapshot: PhaseTargetSnapshot,
    pub recorded_at_unix: u64,
}

impl PhaseCheckpointSkipped {
    pub fn new(phase: WorkflowPhase, target_snapshot: PhaseTargetSnapshot) -> Self {
        Self {
            phase,
            target_snapshot,
            recorded_at_unix: now_unix(),
        }
    }
}

/// Durable human decision to defer empirical proof for one exact finding
/// generation. The discovery run id is part of the record so a later
/// observation of the same durable identity never inherits the deferral.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofDeferralRecorded {
    pub finding_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,
    pub finding_scan_id: String,
    pub target_snapshot: PhaseTargetSnapshot,
    pub reason: String,
    pub actor: ProofDeferralActor,
    pub recorded_at_unix: u64,
}

impl ProofDeferralRecorded {
    pub fn human(
        finding_fingerprint: impl Into<String>,
        identity_id: Option<String>,
        finding_scan_id: impl Into<String>,
        target_snapshot: PhaseTargetSnapshot,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            finding_fingerprint: finding_fingerprint.into(),
            identity_id,
            finding_scan_id: finding_scan_id.into(),
            target_snapshot,
            reason: reason.into(),
            actor: ProofDeferralActor::Human,
            recorded_at_unix: now_unix(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofDeferralActor {
    Human,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum PhaseAttemptEvent {
    PhaseAttemptCompleted(PhaseAttemptCompleted),
    PhaseAttemptDispositionRecorded(PhaseAttemptDispositionRecorded),
    PhaseCheckpointSkipped(PhaseCheckpointSkipped),
    ProofDeferralRecorded(ProofDeferralRecorded),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseAttemptRecord {
    pub completed: PhaseAttemptCompleted,
    pub disposition: Option<PhaseAttemptDispositionRecorded>,
}

pub fn new_phase_attempt_id() -> String {
    format!("phase-{}", uuid::Uuid::new_v4().simple())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn bound_artifact_preview(paths: &mut Vec<String>) {
    paths
        .iter_mut()
        .for_each(|path| truncate_utf8(path, MAX_RECEIPT_ARTIFACT_BYTES));
    if paths.len() <= MAX_RECEIPT_ARTIFACT_PREVIEW {
        return;
    }
    let omitted = paths.len() - (MAX_RECEIPT_ARTIFACT_PREVIEW - 1);
    paths.truncate(MAX_RECEIPT_ARTIFACT_PREVIEW - 1);
    paths.push(format!(
        "… {omitted} additional artifacts retained in canonical run receipts"
    ));
}

fn bound_optional_text(value: &mut Option<String>, max_bytes: usize) {
    if let Some(value) = value.as_mut() {
        truncate_utf8(value, max_bytes);
    }
}

fn deduplicate_actions(actions: &mut Vec<PhaseResultAction>) {
    let mut unique = Vec::with_capacity(actions.len().min(8));
    for action in actions.drain(..) {
        if !unique.contains(&action) {
            unique.push(action);
        }
    }
    *actions = unique;
}

fn truncate_utf8(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes.saturating_sub('…'.len_utf8());
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    value.truncate(end);
    value.push('…');
}
