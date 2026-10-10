//! Preserve the source captured before a SAST parent can be interrupted.
use super::*;
use crate::run_lifecycle::{RunItemId, RunItemRecord, RunItemSource, RunItemV1};

pub(super) fn persist(
    ctx: &ToolExecutionContext<'_>,
    tool: &str,
    target: &Path,
    source: &SourceSnapshot,
) -> Result<()> {
    if tool != "sast:scan" {
        return Ok(());
    }
    let Some(observation) = ctx.run_observation() else {
        return Ok(());
    };
    let Some(producer) = observation.parent_item_id() else {
        return Ok(());
    };
    let run = ctx
        .run_id()
        .ok_or_else(|| anyhow::anyhow!("source receipt has no run identity"))?;
    let call = producer_call(target, &run, producer)?;
    let reference = write_source_reference(target, &run, producer, source)?;
    observation.emit_and_flush(
        RunItemRecord::new(
            RunItemId::new(),
            RunItemSource::Persistence,
            RunItemV1::ArtifactProduced {
                artifact: reference,
            },
        )
        .with_call(call),
    )?;
    Ok(())
}

fn write_source_reference(
    target: &Path,
    run: &str,
    producer: RunItemId,
    source: &SourceSnapshot,
) -> Result<crate::run_lifecycle::ArtifactReference> {
    let leaf = crate::artifact_contract::scan_start_source_artifact_leaf(producer);
    let output = source.clone().attach(json!({"data":{}}));
    let artifact = crate::run_artifacts::write_run_artifact_json(
        target,
        run,
        &leaf,
        "Scan start source",
        &output,
    )?;
    crate::run_lifecycle::verified_run_artifact_reference(target, run, &artifact, producer)?
        .ok_or_else(|| anyhow::anyhow!("source receipt could not be authenticated"))
}

fn producer_call(
    target: &Path,
    run: &str,
    producer: RunItemId,
) -> Result<crate::run_lifecycle::RunCallId> {
    let projection = crate::run_lifecycle::load_run_projection_unhydrated(target, run)?;
    projection
        .calls
        .iter()
        .find(|(_, call)| call.item_id == producer)
        .map(|(id, _)| *id)
        .ok_or_else(|| anyhow::anyhow!("source receipt has no producing call"))
}
