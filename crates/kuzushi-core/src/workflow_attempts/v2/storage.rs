use super::{
    phase_attempt_v2_ledger_path, PhaseAttemptEnvelopeV2, PhaseAttemptEventV2,
    PhaseAttemptLedgerV2, LEDGER_LOCK, MAX_EVENT_BYTES, MAX_LEDGER_BYTES, SCHEMA_VERSION,
};
use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub(super) fn append_v2_event(target: &Path, event: PhaseAttemptEventV2) -> Result<PathBuf> {
    let path = phase_attempt_v2_ledger_path(target);
    let parent = path
        .parent()
        .context("phase-attempts v2 path has no parent")?;
    fs::create_dir_all(parent)?;
    let _lock = crate::file_lock::ExclusiveFileLock::acquire(&parent.join(LEDGER_LOCK))?;
    reject_unsafe_path(&path)?;
    // A writer killed mid-append leaves a newline-less partial line; the
    // strict duplicate scan below would otherwise fail on it forever.
    crate::jsonl_tail::heal_torn_jsonl_tail_at(&path, MAX_EVENT_BYTES, "phase-attempt v2 ledger")?;
    let envelope = PhaseAttemptEnvelopeV2 {
        schema_version: SCHEMA_VERSION,
        record: event,
    };
    if existing_event(&path, &envelope)? {
        return Ok(path);
    }
    let mut line = serde_json::to_vec(&envelope)?;
    line.push(b'\n');
    validate_append_size(&path, line.len())?;
    let mut file = open_append_file(&path)?;
    file.write_all(&line)?;
    file.sync_data()?;
    Ok(path)
}

fn existing_event(path: &Path, expected: &PhaseAttemptEnvelopeV2) -> Result<bool> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    for line in BufReader::new(file).lines() {
        let current: PhaseAttemptEnvelopeV2 = serde_json::from_str(&line?)?;
        if same_event_identity(&current.record, &expected.record) {
            anyhow::ensure!(
                current == *expected,
                "divergent duplicate phase-attempt v2 event"
            );
            return Ok(true);
        }
    }
    Ok(false)
}

fn same_event_identity(left: &PhaseAttemptEventV2, right: &PhaseAttemptEventV2) -> bool {
    match (left, right) {
        (PhaseAttemptEventV2::Completed(left), PhaseAttemptEventV2::Completed(right)) => {
            left.attempt_id == right.attempt_id
        }
        (PhaseAttemptEventV2::Disposition(left), PhaseAttemptEventV2::Disposition(right)) => {
            left.attempt_id == right.attempt_id
        }
        _ => false,
    }
}

pub(super) fn reduce_v2_lines(reader: impl BufRead) -> PhaseAttemptLedgerV2 {
    let mut ledger = PhaseAttemptLedgerV2::default();
    for (index, line) in reader.lines().enumerate() {
        let envelope = line.map_err(anyhow::Error::from).and_then(|line| {
            serde_json::from_str::<PhaseAttemptEnvelopeV2>(&line).map_err(Into::into)
        });
        let Ok(envelope) = envelope else {
            ledger.malformed_line = Some(index + 1);
            break;
        };
        if envelope.schema_version != SCHEMA_VERSION
            || apply_v2_event(&mut ledger, envelope.record).is_err()
        {
            ledger.malformed_line = Some(index + 1);
            break;
        }
    }
    ledger
}

fn apply_v2_event(ledger: &mut PhaseAttemptLedgerV2, event: PhaseAttemptEventV2) -> Result<()> {
    match event {
        PhaseAttemptEventV2::Completed(completed) => {
            anyhow::ensure!(
                !ledger.attempts.contains_key(&completed.attempt_id),
                "duplicate v2 attempt"
            );
            ledger.attempts.insert(completed.attempt_id, completed);
        }
        PhaseAttemptEventV2::Disposition(disposition) => {
            anyhow::ensure!(
                ledger.attempts.contains_key(&disposition.attempt_id),
                "orphan v2 disposition"
            );
            anyhow::ensure!(
                !ledger.dispositions.contains_key(&disposition.attempt_id),
                "duplicate v2 disposition"
            );
            ledger
                .dispositions
                .insert(disposition.attempt_id, disposition);
        }
    }
    Ok(())
}

fn validate_append_size(path: &Path, line_len: usize) -> Result<()> {
    anyhow::ensure!(
        line_len <= MAX_EVENT_BYTES,
        "phase-attempt v2 event exceeds size bound"
    );
    let current = fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or_default();
    anyhow::ensure!(
        current.saturating_add(line_len as u64) <= MAX_LEDGER_BYTES,
        "phase-attempt v2 ledger exceeds size bound"
    );
    Ok(())
}

fn reject_unsafe_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!("phase-attempt v2 ledger must not be a symlink")
        }
        Ok(metadata) if !metadata.is_file() => {
            anyhow::bail!("phase-attempt v2 ledger is not a file")
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn open_append_file(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?)
}

#[cfg(not(unix))]
fn open_append_file(path: &Path) -> Result<fs::File> {
    Ok(OpenOptions::new().create(true).append(true).open(path)?)
}

#[cfg(test)]
mod tests {
    use super::super::{
        PhaseAttemptCompletedV2, PhaseReceiptReferenceV2, TargetContentIdentity,
    };
    use super::*;
    use crate::run_lifecycle::{RunAttemptId, RunId, RunItemId, RunItemStatus, SafeText};
    use crate::WorkflowPhase;

    fn sample_completed_event() -> PhaseAttemptEventV2 {
        let run_id = RunId::parse(&crate::run_artifacts::new_run_id("torn")).unwrap();
        PhaseAttemptEventV2::Completed(PhaseAttemptCompletedV2 {
            attempt_id: RunAttemptId::new(),
            phase: WorkflowPhase::Scan,
            run_refs: vec![run_id.clone()],
            final_receipt: PhaseReceiptReferenceV2 {
                run_id,
                item_id: RunItemId::new(),
                event_hash: SafeText::operator_visible("hash"),
            },
            outcome: RunItemStatus::Completed,
            target: SafeText::operator_visible("/target"),
            target_content_identity: TargetContentIdentity::Unavailable {
                reason: SafeText::operator_visible("test fixture"),
            },
        })
    }

    #[test]
    fn append_heals_a_torn_tail_left_by_a_killed_writer() {
        let target = tempfile::tempdir().unwrap();
        let path = phase_attempt_v2_ledger_path(target.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "{\"schemaVersion\":2,\"tor").unwrap();

        append_v2_event(target.path(), sample_completed_event()).unwrap();

        let body = fs::read_to_string(&path).unwrap();
        assert_eq!(body.lines().count(), 1);
        assert!(body.starts_with("{\"schemaVersion\":2"), "{body}");
        assert!(body.ends_with('\n'));
        let ledger = super::super::load_phase_attempt_ledger_v2(target.path()).unwrap();
        assert_eq!(ledger.attempts.len(), 1);
        assert_eq!(ledger.malformed_line, None);
    }
}
