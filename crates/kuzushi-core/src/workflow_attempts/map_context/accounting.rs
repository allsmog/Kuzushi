//! Read-only spending continuity through explicit immutable context copies.
use super::*;
use crate::allowance::AllowanceReferenceV1;
use crate::capabilities::threat_model::{
    load_threat_model_manifest, ThreatModelManifest, ThreatModelRevisionId,
    ThreatModelRevisionMetadata,
};
use std::collections::BTreeSet;

const MAX_ACCOUNTING_COPY_DEPTH: usize = 64;

pub(super) fn resolve(target: &Path, context: &MapRunContext) -> Result<Option<AllowanceReferenceV1>> {
    if context.allowance_ref.is_some() {
        return Ok(context.allowance_ref.clone());
    }
    match context.model_ref.as_ref() {
        Some(reference) => inherited_reference(target, reference),
        None => Ok(None),
    }
}

fn inherited_reference(target: &Path, origin: &ThreatModelRef) -> Result<Option<AllowanceReferenceV1>> {
    let manifest = load_threat_model_manifest(target)?.context("Context accounting history is missing")?;
    let mut cursor = origin.clone();
    let mut visited = BTreeSet::new();
    for _ in 0..MAX_ACCOUNTING_COPY_DEPTH {
        anyhow::ensure!(visited.insert(cursor.revision_id.clone()), "Context accounting copy history contains a cycle; inspect its recorded revisions");
        let Some(parent) = copy_source(&manifest, &cursor)? else {
            return Ok(None);
        };
        load_exact_threat_model(target, &parent)?;
        if let Some(reference) = producing_allowance(target, &manifest, &parent)? {
            return Ok(Some(reference));
        }
        cursor = parent;
    }
    finish_copy_history(&manifest, &cursor)
}

fn finish_copy_history(manifest: &ThreatModelManifest, cursor: &ThreatModelRef) -> Result<Option<AllowanceReferenceV1>> {
    anyhow::ensure!(copy_source(manifest, cursor)?.is_none(), "Context accounting copy history exceeds {MAX_ACCOUNTING_COPY_DEPTH} links; inspect its original recorded run before planning new work");
    Ok(None)
}

fn copy_source(manifest: &ThreatModelManifest, reference: &ThreatModelRef) -> Result<Option<ThreatModelRef>> {
    let (recorded, revision) = find_revision(manifest, &reference.revision_id)?;
    anyhow::ensure!(recorded == *reference, "Context accounting revision identity changed");
    revision.source_revision_id.as_ref()
        .map(|id| find_revision(manifest, id).map(|(reference, _)| reference))
        .transpose()
}

fn find_revision<'a>(manifest: &'a ThreatModelManifest, id: &ThreatModelRevisionId) -> Result<(ThreatModelRef, &'a ThreatModelRevisionMetadata)> {
    manifest.models.iter().find_map(|model| {
        model.revisions.iter().find(|revision| revision.revision_id == *id).map(|revision| {
            (ThreatModelRef { model_id: model.model_id.clone(), revision_id: id.clone(), sha256: revision.sha256.clone() }, revision)
        })
    }).context("Context accounting copy origin is missing; restore its recorded history before planning work")
}

fn producing_allowance(target: &Path, manifest: &ThreatModelManifest, reference: &ThreatModelRef) -> Result<Option<AllowanceReferenceV1>> {
    let (_, revision) = find_revision(manifest, &reference.revision_id)?;
    let Some(run) = revision.run_id.as_ref() else {
        return Ok(None);
    };
    let context = super::context_from_run(target, run)?
        .context("Context accounting origin has no authenticated result; inspect its producing run")?;
    anyhow::ensure!(context.model_ref.as_ref() == Some(reference), "Context accounting producing run names a different revision");
    Ok(context.allowance_ref)
}

#[cfg(test)]
mod tests;
