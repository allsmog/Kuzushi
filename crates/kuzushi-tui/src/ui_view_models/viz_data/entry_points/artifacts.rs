use super::model::{
    EntryPointArtifactStatus, EntryPointComposition, EntryPointCounts, EntryPointReceipt,
};
use crate::app::{EntryPointCatalogContextAuthentication, JsonFileState};
use crate::{ShellApp, ViewDataState};
use kuzushi_core::RunTargetGitMetadata;
use serde_json::Value;
use std::path::Path;

mod authentication;
mod fields;
mod freshness;
mod validation;
use fields::{pointer_usize, receipt_fields, ReceiptFields};
use freshness::{
    freshness_state, warn_provenance_disagreements, warn_when_dirty_freshness_is_unprovable,
};
use validation::{validate_receipt_counts, warn_unless_coverage_is_complete};

#[derive(Debug, Clone)]
pub(super) struct ArtifactDocument {
    pub(super) status: EntryPointArtifactStatus,
    value: Option<Value>,
    catalog_authentication: Option<
        Result<kuzushi_core::capabilities::entry_points::EntryPointCatalogAuthentication, String>,
    >,
    catalog_context_authentication: Option<EntryPointCatalogContextAuthentication>,
}

impl ArtifactDocument {
    #[cfg(test)]
    pub(super) fn ready(value: Value) -> Self {
        Self {
            status: EntryPointArtifactStatus::Ready,
            value: Some(value),
            catalog_authentication: None,
            catalog_context_authentication: None,
        }
    }

    pub(super) fn ready_with_catalog_authentication(
        value: Value,
        authentication: Option<
            Result<
                kuzushi_core::capabilities::entry_points::EntryPointCatalogAuthentication,
                String,
            >,
        >,
        context_authentication: Option<EntryPointCatalogContextAuthentication>,
    ) -> Self {
        Self {
            status: EntryPointArtifactStatus::Ready,
            value: Some(value),
            catalog_authentication: authentication,
            catalog_context_authentication: context_authentication,
        }
    }

    pub(super) fn without_value(status: EntryPointArtifactStatus) -> Self {
        Self {
            status,
            value: None,
            catalog_authentication: None,
            catalog_context_authentication: None,
        }
    }

    pub(super) fn doc(&self) -> Option<&Value> {
        self.value.as_ref()
    }
}

pub(super) fn read_artifact(app: &ShellApp, target: &Path, path: &Path) -> ArtifactDocument {
    let (state, authentication, context_authentication) = {
        let cache = app.workbench_cache().borrow();
        (
            cache.cached_json_file(target, path),
            cache.cached_entry_point_catalog_authentication(path),
            cache.cached_entry_point_catalog_context_authentication(path),
        )
    };
    match state {
        ViewDataState::Ready(JsonFileState::Present(value)) if value.is_object() => {
            ArtifactDocument::ready_with_catalog_authentication(
                value,
                authentication,
                context_authentication,
            )
        }
        ViewDataState::Ready(JsonFileState::Present(_))
        | ViewDataState::Ready(JsonFileState::Malformed) => {
            ArtifactDocument::without_value(EntryPointArtifactStatus::Malformed)
        }
        ViewDataState::Ready(JsonFileState::Missing) => {
            ArtifactDocument::without_value(EntryPointArtifactStatus::Missing)
        }
        ViewDataState::Ready(JsonFileState::NonFile) => {
            ArtifactDocument::without_value(EntryPointArtifactStatus::NonFile)
        }
        ViewDataState::Ready(JsonFileState::Unreadable) => {
            ArtifactDocument::without_value(EntryPointArtifactStatus::Unreadable)
        }
        ViewDataState::NotRequested | ViewDataState::Loading => {
            ArtifactDocument::without_value(EntryPointArtifactStatus::Loading)
        }
    }
}

pub(super) fn cached_git_metadata(app: &ShellApp, target: &Path) -> Option<RunTargetGitMetadata> {
    match app
        .workbench_cache()
        .borrow()
        .cached_git_metadata(Some(target))
    {
        ViewDataState::Ready(git) => git,
        ViewDataState::NotRequested | ViewDataState::Loading => None,
    }
}

pub(super) fn build_receipt(
    _target: &Path,
    catalog: &ArtifactDocument,
    model: &ArtifactDocument,
    current_context_digest: Option<&str>,
    current_git: Option<&RunTargetGitMetadata>,
    counts: &EntryPointCounts,
    mut warnings: Vec<String>,
) -> EntryPointReceipt {
    let mut fields = receipt_fields(catalog.doc(), model.doc());
    let catalog_authenticated = authenticate_catalog(catalog, &mut fields, &mut warnings);
    let catalog_context_authenticated =
        authenticate_catalog_context(catalog, catalog_authenticated, &mut fields, &mut warnings);
    let composition = composition_state(catalog, model, &fields);
    warn_unless_coverage_is_complete(catalog.doc(), &mut warnings);
    validate_receipt_counts(catalog.doc(), &fields, counts, &mut warnings);
    warn_provenance_disagreements(
        catalog_authenticated,
        composition,
        &fields,
        current_context_digest,
        &mut warnings,
    );
    warn_when_dirty_freshness_is_unprovable(&fields, current_git, &mut warnings);
    receipt_from_fields(
        catalog,
        model,
        current_git,
        catalog_authenticated,
        catalog_context_authenticated,
        composition,
        current_context_digest,
        fields,
        warnings,
    )
}

fn receipt_from_fields(
    catalog: &ArtifactDocument,
    model: &ArtifactDocument,
    current_git: Option<&RunTargetGitMetadata>,
    catalog_authenticated: bool,
    catalog_context_authenticated: Option<bool>,
    composition: EntryPointComposition,
    current_context_digest: Option<&str>,
    fields: ReceiptFields,
    warnings: Vec<String>,
) -> EntryPointReceipt {
    let freshness = freshness_state(
        catalog_authenticated,
        catalog_context_authenticated,
        composition,
        &fields,
        current_context_digest,
        current_git,
    );
    let mut receipt = provenance_receipt(
        catalog,
        model,
        catalog_authenticated,
        composition,
        freshness,
        &fields,
    );
    apply_receipt_counts(&mut receipt, &fields, catalog.doc());
    receipt.warnings = warnings;
    receipt
}

fn provenance_receipt(
    catalog: &ArtifactDocument,
    model: &ArtifactDocument,
    catalog_authenticated: bool,
    composition: EntryPointComposition,
    freshness: super::model::EntryPointFreshness,
    fields: &ReceiptFields,
) -> EntryPointReceipt {
    EntryPointReceipt {
        catalog_artifact: effective_catalog_status(catalog, catalog_authenticated),
        model_artifact: model.status,
        composition,
        freshness,
        catalog_status: fields.catalog_status.clone(),
        catalog_digest: fields.catalog_digest.clone(),
        model_catalog_digest: fields.model_catalog_digest.clone(),
        context_digest: fields.catalog_context_digest.clone(),
        model_context_digest: fields.model_context_digest.clone(),
        tree_hash: fields.catalog_tree_hash.clone(),
        model_tree_hash: fields.model_tree_hash.clone(),
        catalog_timestamp_ms: fields.catalog_timestamp_ms,
        snapshot_timestamp_ms: fields.snapshot_timestamp_ms,
        model_built_at_ms: fields.model_built_at_ms,
        revision: fields.revision.clone(),
        revision_dirty: fields.revision_dirty,
        selection_policy: fields.selection_policy.clone(),
        ..Default::default()
    }
}

/// How many records the catalog holds, in descending order of authority: what
/// the model recorded reading, then the model's own coverage rollup, then the
/// catalog's declared `total`. The last source is the only one a catalog with
/// no threat model beside it has, and it is the count `validate_receipt_counts`
/// already cross-checks against the rows the page parsed, so quoting it leaves
/// the receipt no less checked — and stops a real catalog from reporting its
/// size as unknown. The remaining counts are written only by
/// `threat-model:build`, so they stay absent until it runs.
fn apply_receipt_counts(
    receipt: &mut EntryPointReceipt,
    fields: &ReceiptFields,
    catalog: Option<&Value>,
) {
    receipt.records = fields.records.or_else(|| pointer_usize(catalog, "/total"));
    receipt.records_selected = fields.records_selected;
    receipt.grounding_limit = fields.grounding_limit;
    receipt.grounding_records_selected = fields.grounding_records_selected;
    receipt.records_linked = fields.records_linked;
}

fn composition_state(
    catalog: &ArtifactDocument,
    model: &ArtifactDocument,
    fields: &ReceiptFields,
) -> EntryPointComposition {
    match (catalog.doc(), model.doc()) {
        (Some(_), Some(_)) => match (&fields.catalog_digest, &fields.model_catalog_digest) {
            (Some(catalog), Some(modeled)) if catalog == modeled => EntryPointComposition::Current,
            (Some(_), Some(_)) => EntryPointComposition::ChangedSinceModel,
            _ => EntryPointComposition::ProvenanceUnknown,
        },
        (Some(_), None) => EntryPointComposition::CatalogOnly,
        (None, Some(_)) => EntryPointComposition::ModelOnly,
        (None, None) => EntryPointComposition::Unavailable,
    }
}
use authentication::{
    authenticate_catalog, authenticate_catalog_context, effective_catalog_status,
};
