use super::{snapshot, write_snapshot};
use crate::capabilities::entry_points::*;
use std::cell::Cell;

fn prior_catalog(target: &std::path::Path) -> (std::path::PathBuf, Vec<u8>) {
    write_snapshot(target, &snapshot(target));
    let (_, path) = refresh_entry_point_catalog(target).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    (path, bytes)
}

#[test]
fn cancellation_during_row_collection_stops_before_normalizing_more_rows() {
    let target = tempfile::tempdir().unwrap();
    let mut document = snapshot(target.path());
    let row = document["attackSurfaceMap"]["surfaces"][0].clone();
    document["attackSurfaceMap"]["surfaces"] = serde_json::json!([row.clone(), row]);
    let checks = Cell::new(0);
    let cancelled = || {
        checks.set(checks.get() + 1);
        checks.get() == 3
    };
    let error = super::super::collection::collect_entry_points_cancellable(&document, &cancelled)
        .unwrap_err();
    assert!(error.to_string().contains("cancelled"));
    assert_eq!(checks.get(), 3);
}

#[test]
fn cancelled_source_authentication_is_not_degraded_as_stale_context() {
    let target = tempfile::tempdir().unwrap();
    std::fs::write(target.path().join("source.txt"), "inert source").unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));
    let document = super::super::persistence::read_context_snapshot(target.path())
        .unwrap()
        .unwrap();
    let checks = Cell::new(0);
    let cancelled = || {
        checks.set(checks.get() + 1);
        checks.get() >= 3
    };
    let error = super::super::source_identity::validate_current_source_identity_cancellable(
        target.path(),
        &document.identity,
        &cancelled,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("cancel"));
    assert!(super::super::source_identity::stale_source_disclosure(&error).is_none());
}

#[test]
fn cancellation_at_publication_preserves_the_prior_catalog() {
    let target = tempfile::tempdir().unwrap();
    let (path, before) = prior_catalog(target.path());
    let cancelled = Cell::new(false);
    let error = refresh_entry_point_catalog_cancellable(target.path(), &|| cancelled.get(), || {
        cancelled.set(true);
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("cancelled"));
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn source_drift_at_publication_preserves_the_prior_catalog() {
    let target = tempfile::tempdir().unwrap();
    let (path, before) = prior_catalog(target.path());
    let error = refresh_entry_point_catalog_cancellable(target.path(), &|| false, || {
        std::fs::write(target.path().join("source.txt"), "changed source")?;
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("tree identity is stale"));
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn context_drift_at_publication_preserves_the_prior_catalog() {
    let target = tempfile::tempdir().unwrap();
    let (path, before) = prior_catalog(target.path());
    let error = refresh_entry_point_catalog_cancellable(target.path(), &|| false, || {
        let mut changed = snapshot(target.path());
        changed["timestamp"] = serde_json::json!(456);
        write_snapshot(target.path(), &changed);
        Ok(())
    })
    .unwrap_err();
    assert!(error.to_string().contains("snapshot changed"));
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn outer_source_validation_failure_preserves_the_prior_catalog() {
    let target = tempfile::tempdir().unwrap();
    let (path, before) = prior_catalog(target.path());
    let error = refresh_entry_point_catalog_cancellable(target.path(), &|| false, || {
        anyhow::bail!("source changed during execution")
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "source changed during execution");
    assert_eq!(std::fs::read(path).unwrap(), before);
}
