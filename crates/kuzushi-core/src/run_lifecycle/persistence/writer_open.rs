use super::super::stream_reader::{parse_record, RunItemStreamReader};
use super::writer_model_reserve::ModelReceiptReserve;
use super::WriterState;
use crate::run_lifecycle::{RunId, RunItemEnvelopeV1, MAX_SERIALIZED_RUN_ITEM_BYTES};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::Path;

pub(super) fn open_writer_state(target: &Path, run_id: &str) -> Result<WriterState> {
    let run_id = RunId::parse(run_id)?;
    let directory = crate::run_artifacts::ensure_run_dir(target, run_id.as_str())?;
    record_stream_artifact(target, run_id.as_str())?;
    let lock = crate::file_lock::ExclusiveFileLock::acquire(&directory.join("items.lock"))?;
    let path =
        crate::run_artifacts::checked_run_artifact_path(target, run_id.as_str(), "items.jsonl")?;
    let mut file = crate::bounded_file::open_append_regular_file_within(target, &path)
        .with_context(|| format!("open {}", path.display()))?;
    crate::jsonl_tail::heal_torn_jsonl_tail(
        &mut file,
        &path,
        MAX_SERIALIZED_RUN_ITEM_BYTES,
        "Run item stream",
    )?;
    let recovery_file = file.try_clone().context("clone run-item stream handle")?;
    let (next_seq, previous_hash, bytes_written, model_receipts) =
        recover_tail(target, &path, recovery_file)?;
    let state = WriterState {
        run_id,
        file,
        next_seq,
        previous_hash,
        bytes_written,
        model_receipts,
        delivery: None,
        failure: None,
        _lock: lock,
    };
    Ok(state)
}

fn record_stream_artifact(target: &Path, run_id: &str) -> Result<()> {
    let spec = crate::artifact_contract::canonical_run_artifact_spec("items.jsonl")
        .expect("run-item stream must be in the shared artifact contract");
    let artifact =
        crate::run_artifacts::RunArtifact::from_declared(spec.label, spec.leaf, Some(spec.kind))
            .expect("run-item artifact spec is valid");
    crate::run_artifacts::record_run_artifact(target, run_id, &artifact)?;
    Ok(())
}

fn recover_tail(
    root: &Path,
    path: &Path,
    mut file: File,
) -> Result<(u64, Option<String>, u64, ModelReceiptReserve)> {
    file.seek(SeekFrom::Start(0))?;
    let mut reader = RunItemStreamReader::from_open_file_within(root, path, file)
        .with_context(|| format!("open {}", path.display()))?;
    let mut next_seq = 1;
    let mut previous_hash = None;
    let mut model_receipts = ModelReceiptReserve::default();
    while let Some(record) = reader.next_record()? {
        let envelope = parse_record(record).map_err(anyhow::Error::msg)?;
        validate_recovered_envelope(&envelope, next_seq, &previous_hash)?;
        model_receipts.observe(&envelope);
        next_seq += 1;
        previous_hash = Some(envelope.event_hash);
    }
    reader.verify_path_unchanged()?;
    let bytes = reader.bytes_read();
    Ok((next_seq, previous_hash, bytes, model_receipts))
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
        let mut writer =
            crate::bounded_file::open_append_regular_file_within(temp.path(), &path).unwrap();
        let recovery = writer.try_clone().unwrap();
        assert_eq!(
            recover_tail(temp.path(), &path, recovery).unwrap(),
            (1, None, 0, ModelReceiptReserve::default())
        );

        std::fs::rename(&path, &displaced).unwrap();
        std::fs::write(&path, b"replacement\n").unwrap();
        writer.write_all(b"retained handle\n").unwrap();
        writer.sync_data().unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"replacement\n");
        assert_eq!(std::fs::read(&displaced).unwrap(), b"retained handle\n");
    }

    #[cfg(unix)]
    #[test]
    fn rooted_append_rejects_parent_replaced_after_path_validation() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let run_dir = temp.path().join(".kuzushi/v3/runs/run-1");
        let displaced = temp.path().join("displaced-run");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let checked =
            crate::run_artifacts::checked_run_artifact_path(temp.path(), "run-1", "items.jsonl")
                .unwrap();

        std::fs::rename(&run_dir, &displaced).unwrap();
        symlink(&outside, &run_dir).unwrap();

        let error = crate::bounded_file::open_append_regular_file_within(temp.path(), &checked)
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!outside.join("items.jsonl").exists());
    }
}
