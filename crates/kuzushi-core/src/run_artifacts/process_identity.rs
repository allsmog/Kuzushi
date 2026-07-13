mod identity_read;
mod platform;

#[cfg(test)]
mod tests;

use super::{checked_run_artifact_path, RunSummary};
use serde::{Deserialize, Serialize};
use std::path::Path;

const PROCESS_IDENTITY_LEAF: &str = ".process-identity.json";
const PROCESS_IDENTITY_SCHEMA_VERSION: u8 = 1;
const MAX_PROCESS_IDENTITY_BYTES: usize = 2 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedProcessIdentity {
    schema_version: u8,
    process_id: u32,
    identity: ProcessBirthIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProcessBirthIdentity {
    pub(super) platform: String,
    pub(super) boot_id: Option<String>,
    pub(super) start_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ProcessObservation {
    Alive(Option<ProcessBirthIdentity>),
    Dead,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum OriginalProcessStatus {
    OriginalOwner,
    NotOwner(ProcessOwnershipIssue),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ProcessOwnershipIssue {
    ProcessDead,
    IdentityRejected(String),
}

pub(super) fn persist_running_identity_best_effort(target: &Path, summary: &RunSummary) {
    if summary.status != "running" {
        return;
    }
    let Some(process_id) = summary.process_id else {
        return;
    };
    let ProcessObservation::Alive(Some(identity)) = platform::observe(process_id) else {
        return;
    };
    let persisted = PersistedProcessIdentity {
        schema_version: PROCESS_IDENTITY_SCHEMA_VERSION,
        process_id,
        identity,
    };
    let _ = write_identity(target, &summary.run_id, &persisted);
}

#[cfg(test)]
pub(super) fn original_process_is_alive(target: &Path, run_id: &str, process_id: u32) -> bool {
    original_process_status(target, run_id, process_id) == OriginalProcessStatus::OriginalOwner
}

pub(super) fn original_process_status(
    target: &Path,
    run_id: &str,
    process_id: u32,
) -> OriginalProcessStatus {
    let observation = platform::observe(process_id);
    let observed_identity = observed_birth_identity(&observation);
    let identity = identity_read::read(target, run_id, process_id, observed_identity);
    decide_original_process_status(observation, identity)
}

fn observed_birth_identity(observation: &ProcessObservation) -> Option<&ProcessBirthIdentity> {
    match observation {
        ProcessObservation::Alive(Some(identity)) => Some(identity),
        ProcessObservation::Alive(None)
        | ProcessObservation::Dead
        | ProcessObservation::Unknown => None,
    }
}

fn decide_original_process_status(
    observation: ProcessObservation,
    identity: identity_read::ProcessIdentityReadOutcome,
) -> OriginalProcessStatus {
    if observation == ProcessObservation::Dead {
        return OriginalProcessStatus::NotOwner(ProcessOwnershipIssue::ProcessDead);
    }
    status_from_identity(identity)
}

fn status_from_identity(
    identity: identity_read::ProcessIdentityReadOutcome,
) -> OriginalProcessStatus {
    match identity {
        // Genuine absence is the one intentional compatibility fallback for
        // legacy running summaries written before identity sidecars existed.
        identity_read::ProcessIdentityReadOutcome::Absent
        | identity_read::ProcessIdentityReadOutcome::Valid => OriginalProcessStatus::OriginalOwner,
        identity_read::ProcessIdentityReadOutcome::Invalid(issue) => {
            OriginalProcessStatus::NotOwner(ProcessOwnershipIssue::IdentityRejected(issue.detail))
        }
        identity_read::ProcessIdentityReadOutcome::BindingMismatch(issue) => {
            OriginalProcessStatus::NotOwner(ProcessOwnershipIssue::IdentityRejected(issue.detail))
        }
    }
}

fn write_identity(
    target: &Path,
    run_id: &str,
    identity: &PersistedProcessIdentity,
) -> anyhow::Result<()> {
    let path = checked_run_artifact_path(target, run_id, PROCESS_IDENTITY_LEAF)?;
    let body = serde_json::to_string(identity)?;
    anyhow::ensure!(body.len() <= MAX_PROCESS_IDENTITY_BYTES);
    crate::fs_atomic::write_atomic(&path, &body)?;
    Ok(())
}

#[cfg(test)]
pub(super) fn identity_path(target: &Path, run_id: &str) -> std::path::PathBuf {
    checked_run_artifact_path(target, run_id, PROCESS_IDENTITY_LEAF).unwrap()
}
