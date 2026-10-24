use super::*;
use serde_json::json;

mod cancellation;

fn snapshot(target: &std::path::Path) -> serde_json::Value {
    let tree_hash = crate::incremental_index::current_workspace_tree_hash(target).unwrap();
    json!({
        "target": target.display().to_string(),
        "timestamp": 123,
        "provenance": {"treeHash": tree_hash},
        "attackSurfaceMap": {
            "surfaces": [{
                "kind": "http_route",
                "path": "src/api.rs",
                "line": 42,
                "language": "Rust",
                "title": "POST /oauth/callback",
                "evidence": "router.post",
                "method": "POST",
                "route": "/oauth/callback",
                "boundary": "public_http",
                "risk": {"rank": 1, "score": 80, "tier": "high", "reasons": []},
                "metadata": {"handler": "oauth_callback", "sourcePolicy": crate::workspace::rust_surface_policy::RUST_SURFACE_POLICY}
            }]
        }
    })
}

fn write_snapshot(target: &std::path::Path, value: &serde_json::Value) {
    let path = crate::context::context_snapshot_path(target);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
}

#[test]
fn legacy_rust_snapshot_cannot_recreate_the_same_test_surface_catalog() {
    let target = tempfile::tempdir().unwrap();
    let mut old = snapshot(target.path());
    old["attackSurfaceMap"]["surfaces"][0]["metadata"] = json!({});
    write_snapshot(target.path(), &old);
    let freshness = crate::context::context_snapshot_freshness(target.path(), &old);
    assert!(freshness
        .disclosure()
        .unwrap()
        .contains("test-scope filtering"));
    let error = ensure_current_entry_point_catalog(target.path()).unwrap_err();
    assert!(error.to_string().contains("context:build"), "{error:#}");
    assert!(!target.path().join(".kuzushi/entry-points.json").exists());
}

#[test]
fn explicit_legacy_rust_catalog_refuses_new_grounding_without_rewriting_history() {
    let target = tempfile::tempdir().unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));
    let (mut catalog, path) = refresh_entry_point_catalog(target.path()).unwrap();
    catalog.entry_points[0]
        .surface
        .metadata
        .as_object_mut()
        .unwrap()
        .remove("sourcePolicy");
    catalog.provenance.sha256 = entry_points_sha256(&catalog.entry_points).unwrap();
    super::persistence::write_entry_point_catalog(target.path(), &catalog).unwrap();
    let before = std::fs::read(&path).unwrap();
    let error = load_explicit_entry_point_catalog(target.path()).unwrap_err();
    assert!(
        error.to_string().contains("test-scope filtering"),
        "{error:#}"
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn refresh_writes_a_typed_catalog_with_payload_and_snapshot_digests() {
    let target = tempfile::tempdir().unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));

    let (catalog, path) = refresh_entry_point_catalog(target.path()).unwrap();

    assert_eq!(catalog.total, 1);
    assert!(catalog.entry_points[0].surface.id.starts_with("AS-"));
    assert_eq!(catalog.entry_points[0].name, json!("POST /oauth/callback"));
    assert_eq!(
        catalog.provenance.sha256,
        entry_points_sha256(&catalog.entry_points).unwrap()
    );
    assert!(catalog
        .provenance
        .context_snapshot_sha256
        .starts_with("sha256:"));
    assert!(path.exists());
}

#[test]
fn ensure_refreshes_a_malformed_or_stale_catalog() {
    let target = tempfile::tempdir().unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));
    let path = crate::workspace::workspace_state_root(target.path()).join(ENTRY_POINTS_FILE);
    std::fs::write(&path, "not json").unwrap();

    let resolution = ensure_current_entry_point_catalog(target.path()).unwrap();

    assert_eq!(resolution.status, "refreshed");
    assert_eq!(resolution.catalog.unwrap().total, 1);
}

#[test]
fn validation_rejects_total_and_id_inconsistency() {
    let target = tempfile::tempdir().unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));
    let (mut catalog, _) = refresh_entry_point_catalog(target.path()).unwrap();
    let context = super::persistence::read_context_snapshot(target.path())
        .unwrap()
        .unwrap();
    catalog.total = 2;

    let error = validate_catalog(target.path(), &catalog, &context).unwrap_err();

    assert!(error.to_string().contains("total mismatch"));
}

#[test]
fn refresh_rejects_duplicate_ids_before_writing_an_artifact() {
    let target = tempfile::tempdir().unwrap();
    let mut value = snapshot(target.path());
    let duplicate = value["attackSurfaceMap"]["surfaces"][0].clone();
    value["attackSurfaceMap"]["surfaces"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    write_snapshot(target.path(), &value);

    let error = refresh_entry_point_catalog(target.path()).unwrap_err();

    assert!(error.to_string().contains("unique and non-empty"));
    assert!(!crate::workspace::workspace_state_root(target.path())
        .join(ENTRY_POINTS_FILE)
        .exists());
}

#[test]
fn partial_legacy_risk_is_normalized_without_dropping_the_row() {
    let target = tempfile::tempdir().unwrap();
    let mut value = snapshot(target.path());
    value["attackSurfaceMap"]["surfaces"][0]["risk"] = json!({"score": 80});
    write_snapshot(target.path(), &value);

    let (catalog, _) = refresh_entry_point_catalog(target.path()).unwrap();

    assert_eq!(catalog.total, 1);
    assert_eq!(catalog.entry_points[0].surface.risk.score, 80);
    assert_eq!(catalog.entry_points[0].surface.risk.tier, "high");
    assert_eq!(catalog.entry_points[0].surface.risk.rank, 0);
}

#[test]
fn missing_or_non_array_surface_catalog_is_not_stamped_complete() {
    let target = tempfile::tempdir().unwrap();
    let mut missing = snapshot(target.path());
    missing["attackSurfaceMap"]
        .as_object_mut()
        .unwrap()
        .remove("surfaces");
    write_snapshot(target.path(), &missing);
    assert!(refresh_entry_point_catalog(target.path())
        .unwrap_err()
        .to_string()
        .contains("neither surfaces nor legacy nodes"));

    let mut malformed = snapshot(target.path());
    malformed["attackSurfaceMap"]["surfaces"] = json!({});
    write_snapshot(target.path(), &malformed);
    assert!(refresh_entry_point_catalog(target.path())
        .unwrap_err()
        .to_string()
        .contains("surfaces is not an array"));
}

#[test]
fn explicit_empty_surface_array_is_a_valid_complete_catalog() {
    let target = tempfile::tempdir().unwrap();
    let mut value = snapshot(target.path());
    value["attackSurfaceMap"]["surfaces"] = json!([]);
    write_snapshot(target.path(), &value);

    let (catalog, _) = refresh_entry_point_catalog(target.path()).unwrap();

    assert_eq!(catalog.total, 0);
}

#[test]
fn malformed_recognized_row_fails_instead_of_looking_complete() {
    let target = tempfile::tempdir().unwrap();
    let mut value = snapshot(target.path());
    value["attackSurfaceMap"]["surfaces"][0]["line"] = json!("not-a-line");
    write_snapshot(target.path(), &value);

    let error = refresh_entry_point_catalog(target.path()).unwrap_err();

    assert!(error.to_string().contains("typed surface contract"));
    assert!(!crate::workspace::workspace_state_root(target.path())
        .join(ENTRY_POINTS_FILE)
        .exists());
}

#[test]
fn context_row_with_a_noncanonical_id_is_rejected() {
    let target = tempfile::tempdir().unwrap();
    let mut value = snapshot(target.path());
    value["attackSurfaceMap"]["surfaces"][0]["id"] = json!("AS-forged");
    write_snapshot(target.path(), &value);

    let error = refresh_entry_point_catalog(target.path()).unwrap_err();

    assert!(error.to_string().contains("non-canonical stable id"));
}

/// A snapshot that capped its own arrays still holds real rows. Extraction
/// keeps them and declares the coverage it had, instead of refusing to write
/// any catalog at all for a target too large to snapshot whole.
#[test]
fn truncated_context_snapshot_extracts_a_declared_partial_catalog() {
    let target = tempfile::tempdir().unwrap();
    let mut value = snapshot(target.path());
    value["snapshotTruncation"] = json!({
        "reason": "snapshot byte budget",
        "arrayCap": 2000,
        "omittedEntries": 1186,
    });
    write_snapshot(target.path(), &value);

    let (catalog, path) = refresh_entry_point_catalog(target.path()).unwrap();

    assert_eq!(catalog.total, 1);
    assert_eq!(
        catalog.snapshot_coverage,
        super::domain::EntryPointSnapshotCoverage::Partial {
            reason: "snapshot byte budget".to_string(),
            array_cap: Some(2000),
            omitted_entries: Some(1186),
        }
    );
    let disclosure = catalog.snapshot_coverage.disclosure().unwrap();
    assert!(disclosure.contains("snapshot byte budget"), "{disclosure}");
    assert!(
        disclosure.contains("1186 snapshot entries omitted"),
        "{disclosure}"
    );
    assert!(path.exists());
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(written["snapshotCoverage"]["state"], json!("partial"));
}

/// The inventory spelling of the same marker, with no counts to report.
#[test]
fn inventory_truncation_without_counts_is_still_declared_partial() {
    let target = tempfile::tempdir().unwrap();
    let mut value = snapshot(target.path());
    value["repositoryInventory"] = json!({
        "truncation": {"reason": "content-inspection cap"}
    });
    write_snapshot(target.path(), &value);

    let (catalog, _) = refresh_entry_point_catalog(target.path()).unwrap();

    assert_eq!(
        catalog.snapshot_coverage.disclosure().unwrap(),
        "the context snapshot is truncated (content-inspection cap)"
    );
}

/// Grounding consumers read the catalog as the complete entry-point set, so
/// they refuse a partial one rather than treating its gaps as absence.
#[test]
fn grounding_refuses_a_partial_catalog_extraction_still_wrote() {
    let target = tempfile::tempdir().unwrap();
    let mut value = snapshot(target.path());
    value["snapshotTruncation"] = json!({"reason": "snapshot byte budget", "omittedEntries": 7});
    write_snapshot(target.path(), &value);
    refresh_entry_point_catalog(target.path()).unwrap();

    let ensured = ensure_current_entry_point_catalog(target.path()).unwrap_err();
    let explicit = load_explicit_entry_point_catalog(target.path()).unwrap_err();

    for error in [&ensured, &explicit] {
        assert!(
            error
                .to_string()
                .contains("requires a complete context snapshot"),
            "{error:#}"
        );
        assert!(
            error.to_string().contains("7 snapshot entries omitted"),
            "{error:#}"
        );
    }
}

/// The payload digest covers only the rows, so a coverage field removed from
/// a partial catalog must not read as a completeness claim. Grounding refuses
/// a catalog that records no coverage of its own.
#[test]
fn a_catalog_stripped_of_its_coverage_is_not_read_as_complete() {
    let target = tempfile::tempdir().unwrap();
    let mut value = snapshot(target.path());
    value["snapshotTruncation"] = json!({"reason": "snapshot byte budget"});
    write_snapshot(target.path(), &value);
    let (_, path) = refresh_entry_point_catalog(target.path()).unwrap();
    let mut document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    document.as_object_mut().unwrap().remove("snapshotCoverage");
    std::fs::write(&path, serde_json::to_string_pretty(&document).unwrap()).unwrap();

    let error = load_explicit_entry_point_catalog(target.path()).unwrap_err();

    assert!(
        error.to_string().contains("records none"),
        "a stripped catalog must not stand as complete: {error:#}"
    );
}

/// The other half of the backward-compatibility contract: a catalog written
/// before coverage existed is not refused forever. Against a complete snapshot
/// `ensure` rewrites it, so the artifact states the coverage it was built from
/// instead of carrying its silence forward.
#[test]
fn ensure_rewrites_a_pre_coverage_catalog_with_the_coverage_it_was_built_from() {
    let target = tempfile::tempdir().unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));
    let (_, path) = refresh_entry_point_catalog(target.path()).unwrap();
    let mut document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    document.as_object_mut().unwrap().remove("snapshotCoverage");
    std::fs::write(&path, serde_json::to_string_pretty(&document).unwrap()).unwrap();

    let resolution = ensure_current_entry_point_catalog(target.path()).unwrap();

    assert_eq!(resolution.status, "refreshed");
    let written: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(written["snapshotCoverage"]["state"], json!("complete"));
}

/// A catalog that records no coverage is refused for recording none, not for
/// disagreeing: absence states nothing to conflict with.
#[test]
fn a_pre_coverage_catalog_is_refused_for_its_silence_not_a_mismatch() {
    let target = tempfile::tempdir().unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));
    let (mut catalog, _) = refresh_entry_point_catalog(target.path()).unwrap();
    catalog.snapshot_coverage = super::domain::EntryPointSnapshotCoverage::Unrecorded;
    let context = super::persistence::read_context_snapshot(target.path())
        .unwrap()
        .unwrap();

    let error = validate_catalog(target.path(), &catalog, &context).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("records no snapshot coverage of its own"),
        "{error:#}"
    );
}

/// Coverage is decision-carrying: a catalog may not claim it saw the whole
/// target when its context snapshot says otherwise.
#[test]
fn a_catalog_cannot_claim_complete_coverage_of_a_truncated_snapshot() {
    let target = tempfile::tempdir().unwrap();
    let mut value = snapshot(target.path());
    value["snapshotTruncation"] = json!({"reason": "snapshot byte budget"});
    write_snapshot(target.path(), &value);
    let (mut catalog, _) = refresh_entry_point_catalog(target.path()).unwrap();
    catalog.snapshot_coverage = super::domain::EntryPointSnapshotCoverage::Complete;
    let context = super::persistence::read_context_snapshot(target.path())
        .unwrap()
        .unwrap();

    let error = validate_catalog(target.path(), &catalog, &context).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("coverage does not match its context snapshot"),
        "{error:#}"
    );
}

#[test]
fn non_object_risk_is_not_silently_defaulted() {
    let target = tempfile::tempdir().unwrap();
    let mut value = snapshot(target.path());
    value["attackSurfaceMap"]["surfaces"][0]["risk"] = json!("high");
    write_snapshot(target.path(), &value);

    let error = refresh_entry_point_catalog(target.path()).unwrap_err();

    assert!(error.to_string().contains("non-object risk"));
}

#[test]
fn public_authentication_checks_target_and_payload_identity() {
    let target = tempfile::tempdir().unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));
    let (catalog, _) = refresh_entry_point_catalog(target.path()).unwrap();
    let value = serde_json::to_value(&catalog).unwrap();

    let authentication = authenticate_entry_point_catalog(target.path(), &value).unwrap();

    assert_eq!(authentication.sha256, catalog.provenance.sha256);
    assert_eq!(authentication.total, 1);
    assert_eq!(authentication.snapshot_timestamp, 123);
    let other = tempfile::tempdir().unwrap();
    assert!(authenticate_entry_point_catalog(other.path(), &value).is_err());
}

#[test]
fn public_authentication_rejects_contradictory_provenance_timestamps() {
    let target = tempfile::tempdir().unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));
    let (catalog, _) = refresh_entry_point_catalog(target.path()).unwrap();
    let mut value = serde_json::to_value(catalog).unwrap();

    value["provenance"]["builtAtMs"] = json!(1);
    assert!(authenticate_entry_point_catalog(target.path(), &value)
        .unwrap_err()
        .to_string()
        .contains("build timestamp"));

    value["provenance"]["builtAtMs"] = value["timestamp"].clone();
    value["provenance"]["contextSnapshotTimestamp"] = json!(999);
    assert!(authenticate_entry_point_catalog(target.path(), &value)
        .unwrap_err()
        .to_string()
        .contains("snapshot timestamp"));
}

#[test]
fn public_authentication_rejects_a_missing_context_digest() {
    let target = tempfile::tempdir().unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));
    let (catalog, _) = refresh_entry_point_catalog(target.path()).unwrap();
    let mut value = serde_json::to_value(catalog).unwrap();
    value["provenance"]["contextSnapshotSha256"] = json!("  ");

    let error = authenticate_entry_point_catalog(target.path(), &value).unwrap_err();

    assert!(error.to_string().contains("context digest is missing"));
}

#[test]
fn pair_authentication_rejects_self_hashed_rows_not_derived_from_context() {
    let target = tempfile::tempdir().unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));
    let (mut catalog, _) = refresh_entry_point_catalog(target.path()).unwrap();
    catalog.entry_points[0].surface.risk.score = 99;
    catalog.provenance.sha256 = entry_points_sha256(&catalog.entry_points).unwrap();
    let catalog_value = serde_json::to_value(&catalog).unwrap();
    assert!(authenticate_entry_point_catalog(target.path(), &catalog_value).is_ok());
    let context_path = crate::context::context_snapshot_path(target.path());
    let raw = std::fs::read_to_string(context_path).unwrap();
    let context_value: serde_json::Value = serde_json::from_str(&raw).unwrap();

    let error = authenticate_entry_point_catalog_against_context(
        target.path(),
        &catalog_value,
        &context_value,
        &crate::options::prompt_content_sha256(&raw),
    )
    .unwrap_err();

    assert!(error.to_string().contains("do not match"), "{error:#}");
}

#[test]
fn stale_non_git_snapshot_requires_context_rebuild() {
    let target = tempfile::tempdir().unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));
    std::fs::write(target.path().join("changed.rs"), "fn changed() {}\n").unwrap();

    let error = refresh_entry_point_catalog(target.path()).unwrap_err();

    assert!(
        error.to_string().contains("tree identity is stale"),
        "{error:#}"
    );
}

#[test]
fn explicit_catalog_rejects_current_target_byte_drift() {
    let target = tempfile::tempdir().unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));
    refresh_entry_point_catalog(target.path()).unwrap();
    std::fs::write(target.path().join("changed.rs"), "fn changed() {}\n").unwrap();

    let error = load_explicit_entry_point_catalog(target.path()).unwrap_err();

    assert!(error
        .to_string()
        .contains("stale against the current target"));
}

#[test]
fn writer_refuses_catalogs_above_the_shared_read_write_bound() {
    let target = tempfile::tempdir().unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));
    let (mut catalog, _) = refresh_entry_point_catalog(target.path()).unwrap();
    catalog.entry_points[0].surface.evidence = "x".repeat(MAX_ENTRY_POINTS_BYTES);
    catalog.provenance.sha256 = entry_points_sha256(&catalog.entry_points).unwrap();

    let error = super::persistence::write_entry_point_catalog(target.path(), &catalog).unwrap_err();

    assert!(error.to_string().contains("read/write limit"));
}

#[cfg(unix)]
#[test]
fn writer_rejects_a_symlinked_catalog() {
    use std::os::unix::fs::symlink;
    let target = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    write_snapshot(target.path(), &snapshot(target.path()));
    let path = crate::workspace::workspace_state_root(target.path()).join(ENTRY_POINTS_FILE);
    std::fs::write(outside.path(), "outside").unwrap();
    symlink(outside.path(), &path).unwrap();

    let error = refresh_entry_point_catalog(target.path()).unwrap_err();

    assert!(error.to_string().contains("symlink"));
    assert_eq!(std::fs::read_to_string(outside.path()).unwrap(), "outside");
}

#[test]
fn verification_degrades_on_the_stale_snapshot_producers_still_refuse() {
    let target = tempfile::tempdir().unwrap();
    let mut value = snapshot(target.path());
    value["provenance"]["revision"] = json!("0000000000000000000000000000000000000000");
    write_snapshot(target.path(), &value);

    let extract = refresh_entry_point_catalog(target.path()).unwrap_err();
    let ensured = ensure_current_entry_point_catalog(target.path()).unwrap_err();
    let verification = resolve_entry_point_catalog_for_verification(target.path()).unwrap();

    let stale = "repository identity is unavailable or stale";
    assert!(extract.to_string().contains(stale), "{extract:#}");
    assert!(ensured.to_string().contains(stale), "{ensured:#}");
    let VerificationCatalogGrounding::StaleContext(disclosure) = verification else {
        panic!("a stale context snapshot must degrade verification, not blank it");
    };
    assert!(disclosure.contains(stale), "{disclosure}");
}

#[test]
fn verification_retains_authenticated_observations_from_a_partial_snapshot() {
    let target = tempfile::tempdir().unwrap();
    let mut value = snapshot(target.path());
    value["repositoryInventory"] = json!({"truncation": {"reason": "snapshot byte budget"}});
    write_snapshot(target.path(), &value);

    let verification = resolve_entry_point_catalog_for_verification(target.path()).unwrap();
    let VerificationCatalogGrounding::Catalog(catalog) = verification else {
        panic!("Current partial observations require an authenticated catalog");
    };
    assert_eq!(catalog.total, 1);
    assert!(catalog.snapshot_coverage.is_partial());
    assert!(catalog
        .snapshot_coverage
        .disclosure()
        .unwrap()
        .contains("snapshot byte budget"));
    assert!(ensure_current_entry_point_catalog(target.path()).is_err());
    assert!(load_explicit_entry_point_catalog(target.path()).is_err());
}
