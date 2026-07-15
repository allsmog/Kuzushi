use super::DetectorBinding;
use crate::findings::{FindingStore, PatchLifecycleRecord, PatchProvenance};
use crate::run_artifacts::{load_run_summary, read_run_artifact_text};
use anyhow::{Context, Result};
use std::path::Path;

pub(super) fn originating_detector_binding(
    store: &FindingStore,
    target: &Path,
    record: &PatchLifecycleRecord,
) -> Result<DetectorBinding> {
    let patch = originating_patch(store, record)?;
    let provenance = patch
        .provenance
        .context("legacy patch has no detector provenance; regenerate the patch")?;
    provenance.ensure_complete_for_apply()?;
    ensure_provenance_target(target, record, &provenance)?;
    ensure_finding_generation(store, record, &provenance)?;
    let reference = required_detector_reference(&provenance)?;
    let (tool, input) = load_bound_detector_input(target, &reference)?;
    Ok(DetectorBinding {
        tool,
        run_id: reference.run_id.to_string(),
        input,
    })
}

fn ensure_finding_generation(
    store: &FindingStore,
    record: &PatchLifecycleRecord,
    provenance: &PatchProvenance,
) -> Result<()> {
    let lifecycle_scan_id = record
        .finding_scan_id
        .as_deref()
        .context("legacy patch application has no finding generation; regenerate the patch")?;
    anyhow::ensure!(
        provenance.detector_run_id.as_deref() == Some(lifecycle_scan_id),
        "patch detector and application finding generations differ; regenerate the patch"
    );
    let finding = store
        .get_finding_by_fingerprint(&record.fingerprint)?
        .context("patch finding is unavailable; regenerate the patch")?;
    anyhow::ensure!(
        finding.scan_id.as_deref() == Some(lifecycle_scan_id),
        "patch application belongs to an earlier finding generation; regenerate the patch"
    );
    Ok(())
}

fn originating_patch(
    store: &FindingStore,
    record: &PatchLifecycleRecord,
) -> Result<crate::findings::PatchResult> {
    store
        .get_patch_results_for_finding(&record.fingerprint)?
        .into_iter()
        .find(|patch| patch.patch_run_id == record.patch_run_id)
        .context("originating patch result is unavailable; regenerate the patch")
}

struct DetectorReference<'a> {
    tool: &'a str,
    run_id: &'a str,
    input_digest: &'a str,
}

fn required_detector_reference(provenance: &PatchProvenance) -> Result<DetectorReference<'_>> {
    Ok(DetectorReference {
        tool: provenance
            .detector_tool
            .as_deref()
            .context("patch has no originating detector tool; regenerate the patch")?,
        run_id: provenance
            .detector_run_id
            .as_deref()
            .context("patch has no replayable detector run; regenerate the patch")?,
        input_digest: provenance
            .detector_input_digest
            .as_deref()
            .context("patch has no detector input digest; regenerate the patch")?,
    })
}

fn load_bound_detector_input(
    target: &Path,
    reference: &DetectorReference<'_>,
) -> Result<(String, serde_json::Value)> {
    let summary = load_run_summary(target, reference.run_id)
        .with_context(|| format!("originating run {:?} is unavailable", reference.run_id))?;
    let observed_tool = summary
        .tool
        .context("the originating run does not identify its detector tool")?;
    ensure_detector_identity(&observed_tool, reference.tool)?;
    let (_, body) = read_run_artifact_text(target, reference.run_id, "input.json")
        .require("originating detector input")?;
    ensure_detector_input_digest(&body, reference.input_digest)?;
    let input =
        serde_json::from_str(&body).context("originating detector input is invalid JSON")?;
    Ok((observed_tool, input))
}

fn ensure_detector_input_digest(body: &str, expected: &str) -> Result<()> {
    let observed = PatchProvenance::digest_detector_input(body.as_bytes());
    anyhow::ensure!(
        observed == expected,
        "originating detector input changed; regenerate the patch"
    );
    Ok(())
}

fn ensure_provenance_target(
    target: &Path,
    record: &PatchLifecycleRecord,
    provenance: &PatchProvenance,
) -> Result<()> {
    let recorded_target = std::fs::canonicalize(&provenance.target)
        .context("patch generation target is unavailable; regenerate the patch")?;
    let active_target = std::fs::canonicalize(target)?;
    anyhow::ensure!(
        recorded_target == active_target,
        "patch was generated for another target; regenerate the patch"
    );
    anyhow::ensure!(
        record.base_commit.as_deref() == Some(provenance.source_commit.as_str()),
        "patch application source binding is incomplete; regenerate the patch"
    );
    Ok(())
}

fn ensure_detector_identity(observed_tool: &str, recorded_tool: &str) -> Result<()> {
    anyhow::ensure!(
        super::super::super::detector_identity::qualified_tool_matches_identity(
            observed_tool,
            recorded_tool
        ),
        "originating run tool {observed_tool:?} does not match recorded detector {recorded_tool:?}"
    );
    anyhow::ensure!(
        !matches!(observed_tool, "patch:finding" | "patch:reverify"),
        "patch tools cannot be used as originating detectors"
    );
    Ok(())
}
