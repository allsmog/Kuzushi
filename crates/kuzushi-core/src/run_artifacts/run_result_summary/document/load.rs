use super::*;

pub fn load_correlated_result_document(
    target: impl AsRef<Path>,
    run_id: &str,
    expected_producer: RunItemId,
    expected_digest: &str,
) -> Result<RunResultDocument> {
    let target = target.as_ref();
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(target, run_id)?;
    let (producer, status, reference) = single_result_artifact(&projection)
        .context("Saved output requires one tracked tool result")?;
    anyhow::ensure!(
        producer == expected_producer && reference.digest.as_str() == expected_digest,
        "Selected result reference changed; reload the receipt before reading"
    );
    anyhow::ensure!(
        reference.byte_count <= MAX_DOCUMENT_BYTES as u64,
        "Saved result exceeds the 4 MiB reader limit"
    );
    let (_, body) =
        crate::run_artifacts::read_run_artifact_text(target, run_id, reference.path.as_str())
            .require("Saved result")?;
    decode_correlated_result_document(producer, reference, status, &body)
}
