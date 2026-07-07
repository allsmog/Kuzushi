use crate::event_log::EventKind;
use serde_json::{json, Value};

mod observations;

pub use observations::{CandidateObservationWrite, ObservationWrite};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionWrite {
    pub stable_fp: String,
    pub finding_id: Option<i64>,
    pub identity_id: Option<String>,
    pub verdict: String,
    pub author: String,
    pub rationale: String,
    pub confidence_millis: u16,
    pub read_watermark: u64,
    pub updates_finding_triage: bool,
}

impl DecisionWrite {
    pub(super) fn event_kind(&self) -> EventKind {
        if self.verdict == "suppressed" {
            EventKind::SuppressionAdded
        } else {
            EventKind::TriageDecided
        }
    }

    pub(super) fn payload(&self) -> Value {
        json!({
            "stableFp": self.stable_fp,
            "findingId": self.finding_id,
            "identityId": self.identity_id,
            "verdict": self.verdict,
            "author": self.author,
            "rationale": self.rationale,
            "confidenceMillis": self.confidence_millis,
            "readWatermark": self.read_watermark,
            "updatesFindingTriage": self.updates_finding_triage,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyWrite {
    pub old_fp: String,
    pub new_fp: String,
    pub method: String,
    pub confidence_millis: u16,
    pub actor: String,
    pub evidence: Option<Value>,
}

impl RekeyWrite {
    pub(super) fn payload(&self) -> Value {
        json!({
            "oldFp": self.old_fp,
            "newFp": self.new_fp,
            "method": self.method,
            "confidence": f64::from(self.confidence_millis) / 1000.0,
            "evidence": self.evidence,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationWrite {
    pub stable_fp: String,
    pub finding_id: Option<i64>,
    pub identity_id: Option<String>,
    pub proof_level: u8,
    pub proof_verdict: String,
    pub backend: String,
    pub language: Option<String>,
    pub harness_path: Option<String>,
    pub crash_evidence: Option<String>,
    pub duration_ms: u64,
    pub cost_usd_micros: i64,
    pub notes: Vec<String>,
    pub actor: String,
}

impl VerificationWrite {
    pub(super) fn payload(&self) -> Value {
        json!({
            "stableFp": self.stable_fp,
            "findingId": self.finding_id,
            "identityId": self.identity_id,
            "proofLevel": self.proof_level,
            "proofVerdict": self.proof_verdict,
            "backend": self.backend,
            "language": self.language,
            "harnessPath": self.harness_path,
            "crashEvidence": self.crash_evidence,
            "durationMs": self.duration_ms,
            "costUsdMicros": self.cost_usd_micros,
            "notes": self.notes,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchAttemptWrite {
    pub stable_fp: String,
    pub fingerprint: String,
    pub patch_run_id: String,
    pub repo: String,
    pub diff_object: Option<String>,
    pub diff_size_bytes: Option<u64>,
    pub status: String,
    pub iterations: u64,
    pub build_command: Option<String>,
    pub test_command: Option<String>,
    pub worktree_path: Option<String>,
    pub cost_usd_micros: Option<i64>,
    pub validator_log: Option<String>,
    pub history_json: String,
    pub actor: String,
}

impl PatchAttemptWrite {
    pub(super) fn payload(&self) -> Value {
        json!({
            "stableFp": self.stable_fp,
            "fingerprint": self.fingerprint,
            "patchRunId": self.patch_run_id,
            "repo": self.repo,
            "diffObject": self.diff_object,
            "diffSizeBytes": self.diff_size_bytes,
            "status": self.status,
            "iterations": self.iterations,
            "buildCommand": self.build_command,
            "testCommand": self.test_command,
            "worktreePath": self.worktree_path,
            "costUsdMicros": self.cost_usd_micros,
            "validatorLog": self.validator_log,
            "historyJson": self.history_json,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditWrite {
    pub event_kind: EventKind,
    pub actor: String,
    pub run_id: Option<String>,
    pub stable_fp: Option<String>,
    pub subject: Option<String>,
    pub summary: String,
    pub details: Value,
}

impl AuditWrite {
    pub(super) fn payload(&self) -> Value {
        json!({
            "stableFp": self.stable_fp,
            "subject": self.subject,
            "summary": self.summary,
            "details": self.details,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLifecycleWrite {
    pub event_kind: EventKind,
    pub run_id: String,
    pub target: Option<String>,
    pub status: String,
    pub findings_count: Option<u64>,
    pub actor: String,
}

impl RunLifecycleWrite {
    pub(super) fn payload(&self) -> Value {
        json!({
            "runId": self.run_id,
            "target": self.target,
            "status": self.status,
            "findingsCount": self.findings_count,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingLifecycleWrite {
    pub event_kind: EventKind,
    pub stable_fp: String,
    pub reason: Option<String>,
    pub actor: String,
    pub run_id: Option<String>,
    /// Rule-originated suppression metadata. Only populated for the
    /// `Suppression*` event kinds; `None` for `FindingDisappeared` /
    /// `FindingReopened`. The projector reads only `stableFp`, so these
    /// fields are additive audit context ignored by existing consumers.
    pub suppression: Option<SuppressionEventMeta>,
}

/// Rich audit context carried on a rule-based suppression lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SuppressionEventMeta {
    pub rule_id: Option<String>,
    pub statement: Option<String>,
    pub origin: Option<String>,
    pub expires_at_unix: Option<u64>,
}

impl FindingLifecycleWrite {
    pub(super) fn payload(&self) -> Value {
        let meta = self.suppression.clone().unwrap_or_default();
        json!({
            "stableFp": self.stable_fp,
            "reason": self.reason,
            "ruleId": meta.rule_id,
            "statement": meta.statement,
            "origin": meta.origin,
            "expiresAtUnix": meta.expires_at_unix,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotWrite {
    pub snapshot_hash: String,
    pub tree_hash: String,
    pub workspace_root_fingerprint: String,
    pub git_commit: Option<String>,
    pub git_branch: Option<String>,
    pub dirty_hash: Option<String>,
    pub index_hash: Option<String>,
    pub config_hash: Option<String>,
    pub actor: String,
}

impl SnapshotWrite {
    pub(super) fn payload(&self) -> Value {
        json!({
            "snapshotHash": self.snapshot_hash,
            "treeHash": self.tree_hash,
            "workspaceRootFingerprint": self.workspace_root_fingerprint,
            "gitCommit": self.git_commit,
            "gitBranch": self.git_branch,
            "dirtyHash": self.dirty_hash,
            "indexHash": self.index_hash,
            "configHash": self.config_hash,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFactWrite {
    pub snapshot_hash: String,
    pub path: String,
    pub blob_hash: String,
    pub storage_path: Option<String>,
    pub file_size: u64,
    pub mtime_ns: Option<i64>,
    pub git_blob_oid: Option<String>,
    pub language: Option<String>,
    pub ast_hash: Option<String>,
    pub actor: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDeletedWrite {
    pub snapshot_hash: String,
    pub path: String,
    pub actor: String,
}

impl FileDeletedWrite {
    pub(super) fn payload(&self) -> Value {
        json!({
            "snapshotHash": self.snapshot_hash,
            "path": self.path,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackSurfaceWrite {
    pub snapshot_hash: String,
    pub run_id: Option<String>,
    pub object_hash: Option<String>,
    pub summary: String,
    pub actor: String,
}

impl AttackSurfaceWrite {
    pub(super) fn payload(&self) -> Value {
        json!({
            "snapshotHash": self.snapshot_hash,
            "runId": self.run_id,
            "objectHash": self.object_hash,
            "summary": self.summary,
        })
    }
}
impl FileFactWrite {
    pub(super) fn payload(&self) -> Value {
        json!({
            "snapshotHash": self.snapshot_hash,
            "path": self.path,
            "blobHash": self.blob_hash,
            "storagePath": self.storage_path,
            "fileSize": self.file_size,
            "mtimeNs": self.mtime_ns,
            "gitBlobOid": self.git_blob_oid,
            "language": self.language,
            "astHash": self.ast_hash,
        })
    }
}
