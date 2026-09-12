use super::collection::collect_entry_points;
use super::domain::*;
use super::persistence::*;
use super::source_identity::*;
use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn refresh_entry_point_catalog(target: &Path) -> Result<(EntryPointCatalog, PathBuf)> {
    let snapshot = read_context_snapshot(target)?.with_context(|| {
        format!(
            "entry-points:extract requires {} — run `context:build` first",
            crate::context::context_snapshot_path(target).display()
        )
    })?;
    validate_snapshot_for_current_target(target, &snapshot)?;
    let catalog = catalog_from_snapshot(target, &snapshot)?;
    validate_catalog(target, &catalog, &snapshot)?;
    let path = write_entry_point_catalog(target, &catalog)?;
    revalidate_snapshot_source(target, &snapshot.identity)?;
    Ok((catalog, path))
}

pub(crate) fn ensure_current_entry_point_catalog(
    target: &Path,
) -> Result<EntryPointCatalogResolution> {
    let path = entry_points_path(target);
    let Some(snapshot) = read_context_snapshot(target)? else {
        return Ok(EntryPointCatalogResolution {
            catalog: None,
            status: "missing".to_string(),
            path,
        });
    };
    validate_snapshot_for_current_target(target, &snapshot)?;
    snapshot_coverage(&snapshot.value).require_complete()?;
    if let Ok(Some(catalog)) = read_entry_point_catalog(target) {
        if validate_catalog(target, &catalog, &snapshot).is_ok() {
            revalidate_snapshot_source(target, &snapshot.identity)?;
            return Ok(EntryPointCatalogResolution {
                catalog: Some(catalog),
                status: "current".to_string(),
                path,
            });
        }
    }
    let catalog = catalog_from_snapshot(target, &snapshot)?;
    validate_catalog(target, &catalog, &snapshot)?;
    write_entry_point_catalog(target, &catalog)?;
    revalidate_snapshot_source(target, &snapshot.identity)?;
    Ok(EntryPointCatalogResolution {
        catalog: Some(catalog),
        status: "refreshed".to_string(),
        path,
    })
}

pub(crate) fn load_explicit_entry_point_catalog(
    target: &Path,
) -> Result<EntryPointCatalogResolution> {
    let path = entry_points_path(target);
    let catalog = read_entry_point_catalog(target)?.with_context(|| {
        format!(
            "explicit entry-points source requires {}; run `entry-points:extract` first",
            path.display()
        )
    })?;
    validate_catalog_shape(target, &catalog).with_context(|| {
        "explicit entry-points source is not a self-validating catalog; rebuild it with `entry-points:extract`"
    })?;
    validate_catalog_source_identity(target, &catalog)
        .context("explicit entry-points source is stale against the current target")?;
    validate_catalog_extraction_policy(&catalog)?;
    catalog.snapshot_coverage.require_complete()?;
    Ok(EntryPointCatalogResolution {
        catalog: Some(catalog),
        status: "explicit".to_string(),
        path,
    })
}

fn validate_catalog_extraction_policy(catalog: &EntryPointCatalog) -> Result<()> {
    use crate::workspace::rust_surface_policy::{has_legacy_rust_surface, REBUILD_RUST_SURFACES};
    anyhow::ensure!(
        !catalog.entry_points.iter().any(|entry| {
            let surface = &entry.surface;
            has_legacy_rust_surface(&surface.language, &surface.path, &surface.metadata)
        }),
        REBUILD_RUST_SURFACES
    );
    Ok(())
}

pub(super) fn authenticate_catalog_document(
    target: &Path,
    document: &Value,
) -> Result<EntryPointCatalogAuthentication> {
    let catalog: EntryPointCatalog = serde_json::from_value(document.clone())
        .context("entry-point catalog does not match the typed artifact contract")?;
    validate_catalog_shape(target, &catalog)?;
    Ok(EntryPointCatalogAuthentication {
        sha256: catalog.provenance.sha256,
        total: catalog.total,
        snapshot_timestamp: catalog.snapshot_timestamp,
        context_sha256: catalog.provenance.context_snapshot_sha256,
        tree_hash: catalog.provenance.context_snapshot_tree_hash,
    })
}

pub(super) fn authenticate_catalog_against_context_documents(
    target: &Path,
    catalog_document: &Value,
    context_document: &Value,
    context_sha256: &str,
) -> Result<EntryPointCatalogAuthentication> {
    let catalog: EntryPointCatalog = serde_json::from_value(catalog_document.clone())
        .context("entry-point catalog does not match the typed artifact contract")?;
    let identity = context_snapshot_identity_with_sha(
        context_document,
        context_sha256.to_string(),
    )?;
    let snapshot = ContextSnapshotDocument {
        value: context_document.clone(),
        identity,
    };
    validate_snapshot_target(target, &snapshot.identity)?;
    validate_catalog(target, &catalog, &snapshot)?;
    Ok(EntryPointCatalogAuthentication {
        sha256: catalog.provenance.sha256,
        total: catalog.total,
        snapshot_timestamp: catalog.snapshot_timestamp,
        context_sha256: catalog.provenance.context_snapshot_sha256,
        tree_hash: catalog.provenance.context_snapshot_tree_hash,
    })
}

pub(crate) fn validate_catalog(
    target: &Path,
    catalog: &EntryPointCatalog,
    snapshot: &ContextSnapshotDocument,
) -> Result<()> {
    validate_catalog_shape(target, catalog)?;
    validate_catalog_snapshot_identity(catalog, &snapshot.identity)?;
    anyhow::ensure!(
        catalog.snapshot_coverage == snapshot_coverage(&snapshot.value),
        "entry-point coverage does not match its context snapshot"
    );
    let expected = collect_entry_points(&snapshot.value)?;
    anyhow::ensure!(
        catalog.entry_points == expected,
        "entry-point catalog rows do not match the authenticated context snapshot"
    );
    Ok(())
}

fn validate_catalog_snapshot_identity(
    catalog: &EntryPointCatalog,
    identity: &ContextSnapshotIdentity,
) -> Result<()> {
    anyhow::ensure!(
        catalog.snapshot_timestamp == identity.timestamp,
        "entry-point snapshot timestamp is stale"
    );
    anyhow::ensure!(
        catalog.provenance.context_snapshot_timestamp == identity.timestamp,
        "entry-point provenance timestamp is stale"
    );
    anyhow::ensure!(
        catalog.provenance.context_snapshot_sha256 == identity.sha256,
        "entry-point context digest is stale"
    );
    anyhow::ensure!(
        catalog.provenance.revision == identity.revision,
        "entry-point revision does not match its context snapshot"
    );
    anyhow::ensure!(
        catalog.provenance.revision_dirty == identity.revision_dirty,
        "entry-point dirty state does not match its context snapshot"
    );
    anyhow::ensure!(
        catalog.provenance.context_snapshot_tree_hash == identity.tree_hash,
        "entry-point tree identity does not match its context snapshot"
    );
    Ok(())
}

fn validate_catalog_shape(target: &Path, catalog: &EntryPointCatalog) -> Result<()> {
    validate_catalog_target(target, &catalog.target)?;
    validate_catalog_payload(catalog)
}

fn validate_catalog_payload(catalog: &EntryPointCatalog) -> Result<()> {
    anyhow::ensure!(
        catalog.timestamp == catalog.provenance.built_at_ms,
        "entry-point build timestamp does not match its provenance"
    );
    anyhow::ensure!(
        catalog.snapshot_timestamp == catalog.provenance.context_snapshot_timestamp,
        "entry-point snapshot timestamp does not match its provenance"
    );
    anyhow::ensure!(
        !catalog
            .provenance
            .context_snapshot_sha256
            .trim()
            .is_empty(),
        "entry-point context digest is missing"
    );
    anyhow::ensure!(
        catalog.total == catalog.entry_points.len(),
        "entry-point total mismatch"
    );
    anyhow::ensure!(
        unique_nonempty_ids(&catalog.entry_points),
        "entry-point IDs must be unique and non-empty"
    );
    anyhow::ensure!(
        canonical_ids(&catalog.entry_points),
        "entry-point IDs must equal their canonical surface identity"
    );
    anyhow::ensure!(
        catalog.provenance.sha256 == entry_points_sha256(&catalog.entry_points)?,
        "entry-point payload digest mismatch"
    );
    Ok(())
}

fn catalog_from_snapshot(
    target: &Path,
    snapshot: &ContextSnapshotDocument,
) -> Result<EntryPointCatalog> {
    let entry_points = collect_entry_points(&snapshot.value)?;
    let built_at_ms = now_ms()?;
    let sha256 = entry_points_sha256(&entry_points)?;
    Ok(EntryPointCatalog {
        target: canonical_target(target)?,
        timestamp: built_at_ms,
        snapshot_timestamp: snapshot.identity.timestamp,
        total: entry_points.len(),
        entry_points,
        snapshot_coverage: snapshot_coverage(&snapshot.value),
        provenance: EntryPointCatalogProvenance {
            built_at_ms,
            sha256,
            revision: snapshot.identity.revision.clone(),
            revision_dirty: snapshot.identity.revision_dirty,
            context_snapshot_timestamp: snapshot.identity.timestamp,
            context_snapshot_sha256: snapshot.identity.sha256.clone(),
            context_snapshot_tree_hash: snapshot.identity.tree_hash.clone(),
        },
    })
}

fn unique_nonempty_ids(entries: &[EntryPointRecord]) -> bool {
    let mut ids = BTreeSet::new();
    entries
        .iter()
        .all(|entry| !entry.surface.id.trim().is_empty() && ids.insert(entry.surface.id.as_str()))
}

fn canonical_ids(entries: &[EntryPointRecord]) -> bool {
    entries.iter().all(|entry| {
        entry.surface.id == crate::workspace::attack_surface::attack_surface_id(&entry.surface)
    })
}

pub(crate) fn entry_points_sha256(entries: &[EntryPointRecord]) -> Result<String> {
    let canonical = serde_json::to_string(entries).context("serializing entry-point payload")?;
    Ok(crate::options::prompt_content_sha256(&canonical))
}

fn validate_snapshot_target(target: &Path, snapshot: &ContextSnapshotIdentity) -> Result<()> {
    validate_catalog_target(target, &snapshot.target)
        .context("context snapshot target does not match the active target")
}

fn validate_snapshot_for_current_target(
    target: &Path,
    snapshot: &ContextSnapshotDocument,
) -> Result<()> {
    validate_snapshot_target(target, &snapshot.identity)?;
    validate_current_source_identity(target, &snapshot.identity)
}

/// A snapshot states its own truncation; the catalog inherits that coverage
/// rather than refusing to exist, so large targets still get an entry-point
/// catalog that says exactly what it could not see.
fn snapshot_coverage(snapshot: &Value) -> EntryPointSnapshotCoverage {
    let marker = snapshot
        .pointer("/repositoryInventory/truncation")
        .or_else(|| snapshot.pointer("/snapshotTruncation"));
    let Some(marker) = marker.filter(|marker| !marker.is_null()) else {
        return EntryPointSnapshotCoverage::Complete;
    };
    EntryPointSnapshotCoverage::Partial {
        reason: marker
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("unspecified truncation")
            .to_string(),
        array_cap: marker.get("arrayCap").and_then(Value::as_u64),
        omitted_entries: marker.get("omittedEntries").and_then(Value::as_u64),
    }
}

fn validate_catalog_target(target: &Path, recorded: &str) -> Result<()> {
    let actual = canonical_target(target)?;
    let recorded = canonical_target(Path::new(recorded))?;
    anyhow::ensure!(
        actual == recorded,
        "recorded target {recorded:?} does not match {actual:?}"
    );
    Ok(())
}

fn canonical_target(target: &Path) -> Result<String> {
    std::fs::canonicalize(target)
        .with_context(|| format!("Could not resolve target {}", target.display()))
        .map(|path| path.display().to_string())
}

fn now_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis() as u64)
}
