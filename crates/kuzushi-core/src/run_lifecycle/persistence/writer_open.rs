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
    let lock = crate::file_lock::ExclusiveFileLock::acquire(&directory.join("items.lock"))?;
    let path = crate::run_artifacts::checked_run_artifact_path(
        target,
        run_id.as_str(),
        "items.jsonl",
    )?;
    let file = open_append_file(&path)?;
    let recovery_file = file.try_clone().context("clone run-item stream handle")?;
    let (next_seq, previous_hash, bytes_written) = recover_tail(&path, recovery_file)?;
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

fn recover_tail(path: &Path, file: File) -> Result<(u64, Option<String>, u64)> {
    let mut reader = RunItemStreamReader::from_open_file(path, file)
        .with_context(|| format!("open {}", path.display()))?;
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
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    reject_non_regular_file(path, &file)?;
    Ok(file)
}

#[cfg(windows)]
fn open_append_file(path: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    reject_windows_reparse_file(path, &file)?;
    reject_non_regular_file(path, &file)?;
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
fn open_append_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    reject_non_regular_file(path, &file)?;
    Ok(file)
}

fn reject_non_regular_file(path: &Path, file: &File) -> Result<()> {
    anyhow::ensure!(
        file.metadata()?.is_file(),
        "run-item stream is not a regular file: {}",
        path.display()
    );
    Ok(())
}

#[cfg(windows)]
fn reject_windows_reparse_file(path: &Path, file: &File) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    anyhow::ensure!(
        file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "run-item stream is a reparse point: {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[cfg(unix)]
    #[test]
    fn recovered_writer_handle_cannot_be_redirected_to_a_replacement_path() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("items.jsonl");
        let displaced = temp.path().join("original.jsonl");
        let mut writer = open_append_file(&path).unwrap();
        let recovery = writer.try_clone().unwrap();
        assert_eq!(recover_tail(&path, recovery).unwrap(), (1, None, 0));

        std::fs::rename(&path, &displaced).unwrap();
        std::fs::write(&path, b"replacement\n").unwrap();
        writer.write_all(b"retained handle\n").unwrap();
        writer.sync_data().unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"replacement\n");
        assert_eq!(std::fs::read(&displaced).unwrap(), b"retained handle\n");
    }
}
