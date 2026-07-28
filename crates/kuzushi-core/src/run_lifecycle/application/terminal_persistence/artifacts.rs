use crate::modules::ToolCallIdentity;
use crate::run_artifacts::{read_run_artifact_bytes, RunArtifact, RunArtifactRead};
use crate::run_lifecycle::{
    ArtifactReference, RunItemId, RunItemRecord, RunItemSource, RunItemV1, RunObservationHandle,
    SafeText,
};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;

pub(super) fn emit_artifact_references(
    observation: &RunObservationHandle,
    target: &Path,
    run_id: &str,
    artifacts: &[RunArtifact],
    producing_call: ToolCallIdentity,
) -> Result<()> {
    let known = crate::run_lifecycle::load_run_projection_unhydrated(target, run_id)?
        .artifacts
        .into_values()
        .collect::<Vec<_>>();
    for artifact in artifacts
        .iter()
        .take(crate::run_lifecycle::MAX_ARTIFACT_REFERENCES)
    {
        emit_artifact_reference(
            observation,
            target,
            run_id,
            artifact,
            producing_call,
            &known,
        )?;
    }
    Ok(())
}

fn emit_artifact_reference(
    observation: &RunObservationHandle,
    target: &Path,
    run_id: &str,
    artifact: &RunArtifact,
    producing_call: ToolCallIdentity,
    known: &[ArtifactReference],
) -> Result<()> {
    if artifact.path == "items.jsonl" {
        return Ok(());
    }
    let Some(reference) =
        verified_run_artifact_reference(target, run_id, artifact, producing_call.item_id)?
    else {
        return Ok(());
    };
    if known.contains(&reference) {
        return Ok(());
    }
    observation.emit(
        RunItemRecord::new(
            RunItemId::new(),
            RunItemSource::Persistence,
            RunItemV1::ArtifactProduced {
                artifact: reference,
            },
        )
        .with_call(producing_call.call_id),
    )
}

pub fn verified_run_artifact_reference(
    target: &Path,
    run_id: &str,
    artifact: &RunArtifact,
    producing_item_id: RunItemId,
) -> Result<Option<ArtifactReference>> {
    let Some(artifact) = contained_artifact(target, run_id, artifact)? else {
        return Ok(None);
    };
    let RunArtifactRead::Ready { value, .. } =
        read_run_artifact_bytes(target, run_id, &artifact.path)
    else {
        return Ok(None);
    };
    Ok(Some(artifact_reference(
        &artifact,
        &value,
        producing_item_id,
    )))
}

fn contained_artifact(target: &Path, run_id: &str, artifact: &RunArtifact) -> Result<Option<RunArtifact>> {
    let path = Path::new(&artifact.path);
    if path.is_relative() {
        return Ok(Some(artifact.clone()));
    }
    let run_dir = crate::run_artifacts::run_dir(target, run_id).canonicalize()?;
    let Ok(relative) = path.strip_prefix(run_dir) else {
        return Ok(None);
    };
    if relative.as_os_str().is_empty() {
        return Ok(None);
    }
    Ok(Some(RunArtifact {
        label: artifact.label.clone(),
        path: relative.display().to_string(),
        kind: artifact.kind.clone(),
    }))
}

fn artifact_reference(
    artifact: &RunArtifact,
    value: &[u8],
    producing_item_id: RunItemId,
) -> ArtifactReference {
    let digest = format!("sha256:{:x}", Sha256::digest(value));
    let line_count = std::str::from_utf8(value)
        .ok()
        .map(|text| text.lines().count() as u64);
    ArtifactReference {
        path: SafeText::operator_visible(&artifact.path),
        kind: SafeText::operator_visible(&artifact.kind),
        label: SafeText::operator_visible(&artifact.label),
        digest: SafeText::operator_visible(digest),
        byte_count: value.len() as u64,
        line_count,
        producing_item_id,
    }
}

pub fn verified_result_artifact_reference(
    target: &Path,
    run_id: &str,
    producing_item_id: RunItemId,
) -> Result<ArtifactReference> {
    let spec = crate::run_artifacts::tool_result_artifact_spec("result.json")
        .expect("result artifact is declared in the shared contract");
    let artifact = RunArtifact {
        label: spec.label.to_string(),
        path: spec.leaf.to_string(),
        kind: spec.kind.to_string(),
    };
    verified_run_artifact_reference(target, run_id, &artifact, producing_item_id)?
        .ok_or_else(|| anyhow::anyhow!("durable result artifact is unavailable"))
}
