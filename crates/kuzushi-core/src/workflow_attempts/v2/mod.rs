use super::{
    append_phase_attempt_completed, PhaseAttemptCompleted, PhaseAttemptDisposition,
    PhaseAttemptDispositionRecorded, RecoveredPhaseAttemptLedger,
};
use crate::run_lifecycle::{
    RunAttemptId, RunId, RunItemEnvelopeV1, RunItemId, SafeText,
};
use crate::WorkflowPhase;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::BufReader;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: u16 = 2;
const LEDGER_FILE: &str = "phase-attempts.v2.jsonl";
const LEDGER_LOCK: &str = ".phase-attempts.v2.lock";
const MAX_LEDGER_BYTES: u64 = 8 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 64 * 1024;

mod identity;
mod legacy_projection;
mod receipt;
mod receipt_builder;
mod resolution;
mod storage;
mod validation;
pub use identity::referenced_run_content_identity;
use identity::referenced_run_state;
use legacy_projection::project_typed_receipt_to_legacy;
use receipt::{completed_v2, emit_or_load_phase_receipt};
pub use receipt_builder::PhaseReceiptBuilder;
pub use resolution::load_phase_receipt_projection_v2;
use storage::{append_v2_event, reduce_v2_lines};
use validation::{
    block_unreferenced_uuid_attempts, block_unverifiable_legacy_v1_attempts, validate_v2_attempts,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TargetContentIdentity {
    IndexedSnapshot {
        snapshot_hash: SafeText,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tree_hash: Option<SafeText>,
    },
    CleanGitCommit {
        commit: SafeText,
    },
    Unavailable {
        reason: SafeText,
    },
}

impl TargetContentIdentity {
    pub fn permits_cross_attempt_reuse(&self) -> bool {
        !matches!(self, Self::Unavailable { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhaseReceiptReferenceV2 {
    pub run_id: RunId,
    pub item_id: RunItemId,
    pub event_hash: SafeText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhaseAttemptCompletedV2 {
    pub attempt_id: RunAttemptId,
    pub phase: WorkflowPhase,
    pub run_refs: Vec<RunId>,
    pub final_receipt: PhaseReceiptReferenceV2,
    pub outcome: crate::run_lifecycle::RunItemStatus,
    pub target: SafeText,
    pub target_content_identity: TargetContentIdentity,
}

#[derive(Debug, Clone)]
pub struct PhaseAttemptAppendV2 {
    pub legacy_path: PathBuf,
    pub receipt: RunItemEnvelopeV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PhaseAttemptDispositionV2 {
    pub attempt_id: RunAttemptId,
    pub disposition: PhaseAttemptDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum PhaseAttemptEventV2 {
    Completed(PhaseAttemptCompletedV2),
    Disposition(PhaseAttemptDispositionV2),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PhaseAttemptEnvelopeV2 {
    schema_version: u16,
    record: PhaseAttemptEventV2,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhaseAttemptLedgerV2 {
    pub attempts: BTreeMap<RunAttemptId, PhaseAttemptCompletedV2>,
    pub dispositions: BTreeMap<RunAttemptId, PhaseAttemptDispositionV2>,
    pub malformed_line: Option<usize>,
}

pub fn phase_attempt_v2_ledger_path(target: impl AsRef<Path>) -> PathBuf {
    crate::workspace::workspace_state_dir(target)
        .join("workflow")
        .join(LEDGER_FILE)
}

pub fn append_phase_attempt_completed_with_v2(
    target: impl AsRef<Path>,
    completed: PhaseAttemptCompleted,
) -> Result<PathBuf> {
    append_phase_attempt_completed_with_v2_receipt(target, completed)
        .map(|appended| appended.legacy_path)
}

pub fn append_phase_attempt_completed_with_v2_receipt(
    target: impl AsRef<Path>,
    mut completed: PhaseAttemptCompleted,
) -> Result<PhaseAttemptAppendV2> {
    let target = target.as_ref();
    let attempt_id = RunAttemptId::parse(&completed.attempt_id)
        .context("typed phase attempt ID must be a UUID minted before launch")?;
    let referenced = referenced_run_state(target, &completed.run_refs);
    completed.target_snapshot = referenced.target_snapshot;
    let receipt = emit_or_load_phase_receipt(target, &completed, attempt_id)?;
    project_typed_receipt_to_legacy(target, &mut completed, &receipt)?;
    append_v2_event(
        target,
        PhaseAttemptEventV2::Completed(completed_v2(
            &completed,
            receipt.clone(),
            referenced.content_identity,
        )?),
    )?;
    let legacy_path = append_phase_attempt_completed(target, completed)?;
    Ok(PhaseAttemptAppendV2 {
        legacy_path,
        receipt,
    })
}

pub fn append_phase_attempt_disposition_v2_if_present(
    target: impl AsRef<Path>,
    disposition: &PhaseAttemptDispositionRecorded,
) -> Result<Option<PathBuf>> {
    let Ok(attempt_id) = RunAttemptId::parse(&disposition.attempt_id) else {
        return Ok(None);
    };
    if !load_phase_attempt_ledger_v2(target.as_ref())?
        .attempts
        .contains_key(&attempt_id)
    {
        return Ok(None);
    }
    append_v2_event(
        target.as_ref(),
        PhaseAttemptEventV2::Disposition(PhaseAttemptDispositionV2 {
            attempt_id,
            disposition: disposition.disposition.clone(),
        }),
    )
    .map(Some)
}

pub fn load_phase_attempt_ledger_v2(target: impl AsRef<Path>) -> Result<PhaseAttemptLedgerV2> {
    let path = phase_attempt_v2_ledger_path(target);
    let file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PhaseAttemptLedgerV2::default())
        }
        Err(error) => return Err(error).with_context(|| format!("open {}", path.display())),
    };
    Ok(reduce_v2_lines(BufReader::new(file)))
}

pub fn load_phase_attempt_ledger_prefer_v2_recovering(
    target: impl AsRef<Path>,
) -> Result<RecoveredPhaseAttemptLedger> {
    let target = target.as_ref();
    let mut recovered = super::storage::load_phase_attempt_ledger_v1_recovering(target)?;
    let v2 = load_phase_attempt_ledger_v2(target)?;
    block_unverifiable_legacy_v1_attempts(target, &mut recovered, &v2);
    if v2.attempts.is_empty() && v2.malformed_line.is_none() {
        return Ok(recovered);
    }
    let mut failures = Vec::new();
    if let Some(line) = v2.malformed_line {
        failures.push(format!(
            "phase-attempts.v2.jsonl is malformed at line {line}"
        ));
        recovered.malformed_line = recovered.malformed_line.or(Some(line));
    }
    validate_v2_attempts(target, &mut recovered, &v2, &mut failures);
    block_unreferenced_uuid_attempts(&mut recovered, &v2, &mut failures);
    if !failures.is_empty() {
        recovered.degraded_reason = Some(failures.join("; "));
    }
    Ok(recovered)
}
