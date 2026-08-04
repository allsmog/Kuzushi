use self::artifacts::{build_receipt, cached_git_metadata, read_artifact, ArtifactDocument};
use self::catalog::{
    catalog_entries, deprioritized_entries, entry_point_counts, model_entries, union_entries,
};
use self::helpers::{grouped_counts, NOT_MODELED_ZONE};
use super::dfd::{dfd_model, DfdModel};
use super::ShellApp;
use crate::EntryPointBreakdownCacheKey;
use kuzushi_core::RunTargetGitMetadata;
use std::path::Path;
use std::sync::Arc;

mod artifacts;
mod catalog;
mod helpers;
mod model;
pub(crate) use model::*;

pub(crate) fn entry_point_breakdown(app: &ShellApp) -> Arc<EntryPointBreakdown> {
    let Some(target) = app.target() else {
        return Arc::new(empty_breakdown(
            "select a target to inspect entry-point evidence",
        ));
    };
    let catalog_path =
        kuzushi_core::workspace::workspace_state_root(target).join("entry-points.json");
    let context_path = kuzushi_core::context_snapshot_path(target);
    let model_path = kuzushi_core::capabilities::persistent_threat_model_path(target);
    let git = cached_git_metadata(app, target);
    let (key, context_digest) = cache_inputs(
        app,
        target,
        &catalog_path,
        &context_path,
        &model_path,
        git.as_ref(),
    );
    if let Some(cached) = app.workbench_cache().borrow().entry_point_breakdown(&key) {
        return cached;
    }
    let catalog = read_artifact(app, target, &catalog_path);
    let model = read_artifact(app, target, &model_path);
    let breakdown = Arc::new(entry_point_breakdown_from_artifacts(
        target,
        &catalog,
        &model,
        &dfd_model(app),
        context_digest.as_deref(),
        git.as_ref(),
    ));
    app.workbench_cache()
        .borrow_mut()
        .cache_entry_point_breakdown(key, Arc::clone(&breakdown));
    breakdown
}

fn cache_inputs(
    app: &ShellApp,
    target: &Path,
    catalog_path: &Path,
    context_path: &Path,
    model_path: &Path,
    git: Option<&RunTargetGitMetadata>,
) -> (EntryPointBreakdownCacheKey, Option<String>) {
    let cache = app.workbench_cache().borrow();
    let key = EntryPointBreakdownCacheKey::from_parts(
        target,
        cache.cached_json_file_version(catalog_path),
        cache.cached_json_file_version(context_path),
        cache.cached_json_file_version(model_path),
        git.map(|git| (git.sha.as_str(), git.dirty)),
    );
    (key, cache.cached_json_file_content_sha256(context_path))
}

fn entry_point_breakdown_from_artifacts(
    target: &std::path::Path,
    catalog: &ArtifactDocument,
    model: &ArtifactDocument,
    topology: &DfdModel,
    current_context_digest: Option<&str>,
    current_git: Option<&RunTargetGitMetadata>,
) -> EntryPointBreakdown {
    let mut warnings = artifact_warnings(catalog.status, model.status);
    let catalog_entries = catalog_entries(catalog.doc(), &mut warnings);
    let model_entries = model_entries(model.doc(), topology, &mut warnings);
    let deprioritized = deprioritized_entries(model.doc());
    let counts = entry_point_counts(&catalog_entries, &model_entries, &deprioritized);
    let entries = union_entries(catalog_entries, model_entries, &deprioritized);
    let receipt = build_receipt(
        target,
        catalog,
        model,
        current_context_digest,
        current_git,
        &counts,
        warnings,
    );
    complete_breakdown(entries, counts, receipt)
}

fn artifact_warnings(
    catalog: EntryPointArtifactStatus,
    model: EntryPointArtifactStatus,
) -> Vec<String> {
    [("extractor catalog", catalog), ("threat model", model)]
        .into_iter()
        .filter(|(_, status)| *status != EntryPointArtifactStatus::Ready)
        .map(|(name, status)| format!("{name} {}", status.label()))
        .collect()
}

fn complete_breakdown(
    entries: Vec<EntryPointItem>,
    counts: EntryPointCounts,
    receipt: EntryPointReceipt,
) -> EntryPointBreakdown {
    if entries.is_empty() {
        return empty_breakdown_with_receipt(receipt);
    }
    let linked_target_count = entries.iter().map(|entry| entry.targets.len()).sum();
    let target_count = entries
        .iter()
        .map(|entry| entry.targets.len() + entry.unresolved_target_count)
        .sum();
    EntryPointBreakdown {
        kinds: grouped_counts(entries.iter().map(|entry| entry.kind.as_str())),
        zones: modeled_zone_counts(&entries),
        dispositions: disposition_counts(&entries),
        entries,
        counts,
        receipt,
        linked_target_count,
        target_count,
        empty_hint: None,
    }
}

fn modeled_zone_counts(entries: &[EntryPointItem]) -> Vec<EntryPointGroup> {
    grouped_counts(
        entries
            .iter()
            .filter(|entry| entry.trust_zone != NOT_MODELED_ZONE)
            .map(|entry| entry.trust_zone.as_str()),
    )
}

fn disposition_counts(entries: &[EntryPointItem]) -> Vec<EntryPointGroup> {
    EntryPointDisposition::ALL
        .into_iter()
        .filter_map(|disposition| disposition_group(entries, disposition))
        .collect()
}

fn disposition_group(
    entries: &[EntryPointItem],
    disposition: EntryPointDisposition,
) -> Option<EntryPointGroup> {
    let count = entries
        .iter()
        .filter(|entry| entry.disposition == disposition)
        .count();
    (count > 0).then(|| EntryPointGroup {
        name: disposition.label().to_string(),
        count,
    })
}

fn empty_breakdown(hint: &str) -> EntryPointBreakdown {
    EntryPointBreakdown {
        empty_hint: Some(hint.to_string()),
        ..Default::default()
    }
}

fn empty_breakdown_with_receipt(receipt: EntryPointReceipt) -> EntryPointBreakdown {
    let hint = if receipt.warnings.is_empty() {
        "no entry-point rows in the extractor catalog or threat model".to_string()
    } else {
        receipt.warnings.join(" · ")
    };
    EntryPointBreakdown {
        receipt,
        empty_hint: Some(hint),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests;
