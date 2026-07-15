use super::{
    PhaseAttemptCompleted, PhaseAttemptDispositionRecorded, PhaseAttemptEvent,
    PhaseAttemptLedger, PhaseCheckpointSkipped, ProofDeferralRecorded,
};
use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const WORKFLOW_DIR: &str = "workflow";
const ATTEMPT_LEDGER: &str = "phase-attempts.jsonl";
const ATTEMPT_LEDGER_LOCK: &str = ".phase-attempts.lock";
const MAX_LEDGER_BYTES: u64 = 8 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredPhaseAttemptEvents {
    pub events: Vec<PhaseAttemptEvent>,
    pub malformed_line: Option<usize>,
}

impl RecoveredPhaseAttemptEvents {
    pub const fn is_degraded(&self) -> bool {
        self.malformed_line.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredPhaseAttemptLedger {
    pub ledger: PhaseAttemptLedger,
    pub malformed_line: Option<usize>,
}

impl RecoveredPhaseAttemptLedger {
    pub const fn is_degraded(&self) -> bool {
        self.malformed_line.is_some()
    }
}

pub fn phase_attempt_ledger_path(target: impl AsRef<Path>) -> PathBuf {
    crate::workspace::workspace_state_dir(target)
        .join(WORKFLOW_DIR)
        .join(ATTEMPT_LEDGER)
}

pub fn load_phase_attempt_events(target: impl AsRef<Path>) -> Result<Vec<PhaseAttemptEvent>> {
    let path = phase_attempt_ledger_path(target);
    let Some(body) = read_ledger_body(&path)? else {
        return Ok(Vec::new());
    };
    parse_events(&path, &body)
}

pub fn load_phase_attempt_events_recovering(
    target: impl AsRef<Path>,
) -> Result<RecoveredPhaseAttemptEvents> {
    let path = phase_attempt_ledger_path(target);
    let Some(body) = read_ledger_body(&path)? else {
        return Ok(RecoveredPhaseAttemptEvents {
            events: Vec::new(),
            malformed_line: None,
        });
    };
    Ok(parse_event_prefix(&body))
}

pub fn load_phase_attempt_ledger_recovering(
    target: impl AsRef<Path>,
) -> Result<RecoveredPhaseAttemptLedger> {
    let recovered = load_phase_attempt_events_recovering(target)?;
    let ledger = PhaseAttemptLedger::from_events(recovered.events)?;
    Ok(RecoveredPhaseAttemptLedger {
        ledger,
        malformed_line: recovered.malformed_line,
    })
}

fn read_ledger_body(path: &Path) -> Result<Option<String>> {
    match crate::bounded_file::read_utf8_text(path, MAX_LEDGER_BYTES as usize) {
        Ok(body) => Ok(Some(body)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| ledger_read_error(path)),
    }
}

fn parse_events(path: &Path, body: &str) -> Result<Vec<PhaseAttemptEvent>> {
    body.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str(line).with_context(|| {
                format!(
                    "Invalid workflow attempt event at {}:{}",
                    path.display(),
                    index + 1
                )
            })
        })
        .collect()
}

fn parse_event_prefix(body: &str) -> RecoveredPhaseAttemptEvents {
    let mut events = Vec::new();
    for (index, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str(line) {
            Ok(event) => events.push(event),
            Err(_) => {
                return RecoveredPhaseAttemptEvents {
                    events,
                    malformed_line: Some(index + 1),
                };
            }
        }
    }
    RecoveredPhaseAttemptEvents {
        events,
        malformed_line: None,
    }
}

fn ledger_read_error(path: &Path) -> String {
    format!("Could not read workflow attempt ledger {}", path.display())
}

pub fn load_phase_attempt_ledger(target: impl AsRef<Path>) -> Result<PhaseAttemptLedger> {
    PhaseAttemptLedger::from_events(load_phase_attempt_events(target)?)
}

pub fn append_phase_attempt_completed(
    target: impl AsRef<Path>,
    completed: PhaseAttemptCompleted,
) -> Result<PathBuf> {
    append_validated_event(
        target.as_ref(),
        PhaseAttemptEvent::PhaseAttemptCompleted(completed),
    )
}

pub fn append_phase_attempt_disposition(
    target: impl AsRef<Path>,
    disposition: PhaseAttemptDispositionRecorded,
) -> Result<PathBuf> {
    append_validated_event(
        target.as_ref(),
        PhaseAttemptEvent::PhaseAttemptDispositionRecorded(disposition),
    )
}

pub fn append_phase_checkpoint_skipped(
    target: impl AsRef<Path>,
    checkpoint: PhaseCheckpointSkipped,
) -> Result<PathBuf> {
    append_validated_event(
        target.as_ref(),
        PhaseAttemptEvent::PhaseCheckpointSkipped(checkpoint),
    )
}

pub fn append_proof_deferral(
    target: impl AsRef<Path>,
    deferral: ProofDeferralRecorded,
) -> Result<PathBuf> {
    append_validated_event(
        target.as_ref(),
        PhaseAttemptEvent::ProofDeferralRecorded(deferral),
    )
}

fn append_validated_event(target: &Path, event: PhaseAttemptEvent) -> Result<PathBuf> {
    let path = phase_attempt_ledger_path(target);
    let parent = path.parent().context("workflow attempt ledger has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("Could not create workflow state directory {}", parent.display()))?;
    let _guard = crate::file_lock::ExclusiveFileLock::acquire(&parent.join(ATTEMPT_LEDGER_LOCK))?;
    reject_unsafe_target(&path)?;
    validate_appended_event(target, &event)?;
    append_event_line(&path, &event)?;
    Ok(path)
}

fn validate_appended_event(target: &Path, event: &PhaseAttemptEvent) -> Result<()> {
    let mut events = load_phase_attempt_events(target)?;
    events.push(event.clone());
    PhaseAttemptLedger::from_events(events).map(|_| ())
}

fn append_event_line(path: &Path, event: &PhaseAttemptEvent) -> Result<()> {
    let mut line = serde_json::to_string(event)?;
    line.push('\n');
    validate_append_size(path, line.len())?;
    let mut file = open_append_file(path)
        .with_context(|| format!("Could not open workflow attempt ledger {}", path.display()))?;
    file.write_all(line.as_bytes())
        .with_context(|| format!("Could not append workflow attempt ledger {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("Could not fsync workflow attempt ledger {}", path.display()))
}

fn validate_append_size(path: &Path, line_len: usize) -> Result<()> {
    anyhow::ensure!(
        line_len <= MAX_EVENT_BYTES,
        "Workflow attempt event exceeds {MAX_EVENT_BYTES} bytes"
    );
    let current_size = fs::symlink_metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or_default();
    anyhow::ensure!(
        current_size.saturating_add(line_len as u64) <= MAX_LEDGER_BYTES,
        "Workflow attempt ledger exceeds {MAX_LEDGER_BYTES} bytes"
    );
    Ok(())
}

fn reject_unsafe_target(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("Workflow attempt ledger must not be a symlink: {}", path.display())
        }
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => anyhow::bail!("Workflow attempt ledger is not a file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("Could not inspect {}", path.display())),
    }
}

#[cfg(unix)]
fn open_append_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_append_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new().create(true).append(true).open(path)
}
