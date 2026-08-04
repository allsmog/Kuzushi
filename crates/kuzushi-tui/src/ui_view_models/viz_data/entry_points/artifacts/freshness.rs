use super::fields::ReceiptFields;
use crate::ui_view_models::viz_data::entry_points::{EntryPointComposition, EntryPointFreshness};
use kuzushi_core::RunTargetGitMetadata;

pub(super) fn freshness_state(
    catalog_authenticated: bool,
    catalog_context_authenticated: Option<bool>,
    composition: EntryPointComposition,
    fields: &ReceiptFields,
    current_context_digest: Option<&str>,
    current_git: Option<&RunTargetGitMetadata>,
) -> EntryPointFreshness {
    let prerequisite = freshness_prerequisite(
        catalog_authenticated,
        catalog_context_authenticated,
        composition,
    );
    if let Some(freshness) = prerequisite {
        return freshness;
    }
    freshness_from_checks(fields, composition, current_context_digest, current_git)
}

fn freshness_prerequisite(
    catalog_authenticated: bool,
    catalog_context_authenticated: Option<bool>,
    composition: EntryPointComposition,
) -> Option<EntryPointFreshness> {
    if !catalog_authenticated {
        return Some(EntryPointFreshness::Unknown);
    }
    match catalog_context_authenticated {
        Some(false) => return Some(EntryPointFreshness::Stale),
        None => return Some(EntryPointFreshness::Unknown),
        Some(true) => {}
    }
    match composition {
        EntryPointComposition::ChangedSinceModel => Some(EntryPointFreshness::Stale),
        EntryPointComposition::Current | EntryPointComposition::CatalogOnly => None,
        EntryPointComposition::ProvenanceUnknown
        | EntryPointComposition::ModelOnly
        | EntryPointComposition::Unavailable => Some(EntryPointFreshness::Unknown),
    }
}

fn freshness_from_checks(
    fields: &ReceiptFields,
    composition: EntryPointComposition,
    current_context_digest: Option<&str>,
    current_git: Option<&RunTargetGitMetadata>,
) -> EntryPointFreshness {
    let checks = freshness_checks(fields, composition, current_context_digest, current_git);
    if checks.contains(&Some(false)) {
        return EntryPointFreshness::Stale;
    }
    if checks.contains(&None) || fields.catalog_revision_dirty != Some(false) {
        return EntryPointFreshness::Unknown;
    }
    EntryPointFreshness::Current
}

fn freshness_checks(
    fields: &ReceiptFields,
    composition: EntryPointComposition,
    current_context_digest: Option<&str>,
    current_git: Option<&RunTargetGitMetadata>,
) -> [Option<bool>; 4] {
    [
        context_matches(fields, current_context_digest),
        revision_matches(fields, current_git),
        dirty_state_matches(fields, current_git),
        model_provenance_matches_catalog(fields, composition),
    ]
}

fn context_matches(fields: &ReceiptFields, current_context_digest: Option<&str>) -> Option<bool> {
    fields
        .catalog_context_digest
        .as_deref()
        .zip(current_context_digest)
        .map(|(catalog, current)| catalog == current)
}

fn revision_matches(
    fields: &ReceiptFields,
    current_git: Option<&RunTargetGitMetadata>,
) -> Option<bool> {
    fields
        .catalog_revision
        .as_deref()
        .zip(current_git.map(|git| git.sha.as_str()))
        .map(|(catalog, current)| catalog == current)
}

fn dirty_state_matches(
    fields: &ReceiptFields,
    current_git: Option<&RunTargetGitMetadata>,
) -> Option<bool> {
    fields
        .catalog_revision_dirty
        .zip(current_git.map(|git| git.dirty))
        .map(|(catalog, current)| catalog == current)
}

fn model_provenance_matches_catalog(
    fields: &ReceiptFields,
    composition: EntryPointComposition,
) -> Option<bool> {
    if composition == EntryPointComposition::CatalogOnly {
        return Some(true);
    }
    let revision_matches = fields
        .catalog_revision
        .as_deref()
        .zip(fields.model_revision.as_deref())
        .map(|(catalog, model)| catalog == model);
    let dirty_matches = fields
        .catalog_revision_dirty
        .zip(fields.model_revision_dirty)
        .map(|(catalog, model)| catalog == model);
    let context_matches = fields
        .catalog_context_digest
        .as_deref()
        .zip(fields.model_context_digest.as_deref())
        .map(|(catalog, model)| catalog == model);
    let tree_matches = optional_model_attestation_matches(
        fields.catalog_tree_hash.as_deref(),
        fields.model_tree_hash.as_deref(),
    );
    [
        revision_matches,
        dirty_matches,
        context_matches,
        tree_matches,
    ]
    .into_iter()
    .try_fold(true, |matches, check| check.map(|check| matches && check))
}

fn optional_model_attestation_matches(catalog: Option<&str>, model: Option<&str>) -> Option<bool> {
    match catalog {
        Some(catalog) => model.map(|model| catalog == model),
        None => Some(true),
    }
}

pub(super) fn warn_provenance_disagreements(
    catalog_authenticated: bool,
    composition: EntryPointComposition,
    fields: &ReceiptFields,
    current_context_digest: Option<&str>,
    warnings: &mut Vec<String>,
) {
    if !catalog_authenticated {
        return;
    }
    warn_context_disagreement(fields, current_context_digest, warnings);
    if composition == EntryPointComposition::Current {
        warn_model_disagreement(fields, warnings);
    }
}

fn warn_context_disagreement(
    fields: &ReceiptFields,
    current_context_digest: Option<&str>,
    warnings: &mut Vec<String>,
) {
    match (
        fields.catalog_context_digest.as_deref(),
        current_context_digest,
    ) {
        (Some(catalog), Some(current)) if catalog != current => warnings
            .push("catalog context digest does not match the current context snapshot".to_string()),
        (_, None) => warnings
            .push("current context snapshot digest unavailable; freshness is unprovable".into()),
        _ => {}
    }
}

fn warn_model_disagreement(fields: &ReceiptFields, warnings: &mut Vec<String>) {
    match model_provenance_matches_catalog(fields, EntryPointComposition::Current) {
        Some(false) => warnings.push("model receipt provenance disagrees with the catalog".into()),
        None => warnings.push(
            "model receipt lacks catalog revision, context, or dirty-state provenance; freshness is unprovable"
                .into(),
        ),
        Some(true) => {}
    }
}

pub(super) fn warn_when_dirty_freshness_is_unprovable(
    fields: &ReceiptFields,
    current_git: Option<&RunTargetGitMetadata>,
    warnings: &mut Vec<String>,
) {
    let both_dirty = fields.catalog_revision_dirty == Some(true)
        && current_git.is_some_and(|current| current.dirty);
    if both_dirty {
        warnings
            .push("dirty revision matches by commit only; artifact freshness is unprovable".into());
    }
}
