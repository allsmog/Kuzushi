use super::super::stream_reader::{parse_record, RunItemStreamReader};
use super::WriterState;
use crate::run_lifecycle::{RunId, RunItemEnvelopeV1};
use anyhow::{Context, Result};
use std::fs::{File, OpenOptions};
use std::path::Path;

pub(super) fn open_writer_state(target: &Path, run_id: &str) -> Result<WriterState> {
    let run_id = RunId::parse(run_id)?;
    let directory = crate::run_artifacts::ensure_run_dir(target, run_id.as_str())?;
    record_stream_artifact(target, run_id.as_str())?;
    let path = directory.join("items.jsonl");
    let lock = crate::file_lock::ExclusiveFileLock::acquire(&directory.join("items.lock"))?;
    let (next_seq, previous_hash, bytes_written) = recover_tail(&path)?;
    let file = open_append_file(&path)?;
    let state = WriterState {
        run_id,
        file,
        next_seq,
        previous_hash,
        bytes_written,
        delivery: None,
        failure: None,
        _lock: lock,
    };
    Ok(state)
}

fn record_stream_artifact(target: &Path, run_id: &str) -> Result<()> {
    let spec = crate::artifact_contract::optional_run_artifact_spec("items.jsonl")
        .expect("run-item stream must be in the shared optional artifact contract");
    let artifact =
        crate::run_artifacts::RunArtifact::from_declared(spec.label, spec.leaf, Some(spec.kind))
            .expect("run-item artifact spec is valid");
    crate::run_artifacts::record_run_artifact(target, run_id, &artifact)?;
    Ok(())
}

fn recover_tail(path: &Path) -> Result<(u64, Option<String>, u64)> {
    let Some(mut reader) = RunItemStreamReader::open(path)
        .with_context(|| format!("open {}", path.display()))?
    else {
        return Ok((1, None, 0));
    };
    let mut next_seq = 1;
    let mut previous_hash = None;
    while let Some(record) = reader.next_record()? {
        let envelope = parse_record(record).map_err(anyhow::Error::msg)?;
        validate_recovered_envelope(&envelope, next_seq, &previous_hash)?;
        next_seq += 1;
        previous_hash = Some(envelope.event_hash);
    }
    reader.verify_path_unchanged()?;
    let bytes = reader.bytes_read();
    Ok((next_seq, previous_hash, bytes))
}

fn validate_recovered_envelope(
    envelope: &RunItemEnvelopeV1,
    expected_seq: u64,
    previous_hash: &Option<String>,
) -> Result<()> {
    envelope.verify_hash()?;
    anyhow::ensure!(
        envelope.seq == expected_seq,
        "run-item sequence is not contiguous"
    );
    anyhow::ensure!(
        envelope.prev_event_hash == *previous_hash,
        "run-item chain is broken"
    );
    Ok(())
}

#[cfg(unix)]
fn open_append_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}

#[cfg(not(unix))]
fn open_append_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}
