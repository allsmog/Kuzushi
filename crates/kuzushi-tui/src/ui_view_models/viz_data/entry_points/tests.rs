use super::*;
use crate::ui_view_models::{DfdBoundaryModel, DfdKind, DfdNodeModel};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

#[test]
fn union_keeps_catalog_facts_and_overlays_model_context() {
    let target = tempfile::tempdir().unwrap();
    let rows = vec![
        catalog_row(
            "EP-1",
            "catalog name",
            "http_route",
            "src/routes.rs",
            json!({
                "method": "POST", "route": "/admin", "line": 42,
                "framework": "Flask",
                "evidence": "catalog evidence",
                "risk": {"rank": 0, "tier": "high", "score": 78, "reasons": []}
            }),
        ),
        catalog_row(
            "EP-2",
            "parser",
            "deserialization_point",
            "src/parser.rs",
            json!({}),
        ),
    ];
    let catalog = authenticated_catalog(target.path(), rows, "rev", false);
    let digest = catalog_digest(&catalog);
    let model = artifact(json!({
        "provenance": {
            "builtAtMs": 20,
            "entryPointCatalog": {
                "status": "loaded", "sha256": digest, "records": 2,
                "recordsSelected": 1, "snapshotTimestamp": 10,
                "groundingLimit": 2, "groundingRecordsSelected": 2,
                "selectionPolicy": "risk-ranked", "revision": "rev", "revisionDirty": false,
                "contextSha256": "sha256:context"
            }
        },
        "coverage": {
            "catalogEntryPointsTotal": 2,
            "catalogEntryPointsSelected": 1,
            "catalogEntryPointsLinked": 1
        },
        "attackSurface": {"entryPoints": [{
            "id": "EP-1", "name": "model name", "kind": "other_kind",
            "trustZone": "internet", "description": "admin route",
            "path": "model.rs", "evidence": "model evidence",
            "framework": "unverified-model-framework",
            "targetElementIds": ["N1", "TB1"]
        }]}
    }));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &topology(),
        Some("sha256:context"),
        Some(&git("rev", false)),
    );

    assert_eq!(breakdown.counts.extracted, 2);
    assert_eq!(breakdown.counts.modeled, 1);
    assert_eq!(breakdown.counts.overlap, 1);
    assert_eq!(breakdown.counts.union, 2);
    assert_eq!(
        breakdown.receipt.composition,
        EntryPointComposition::Current
    );
    assert_eq!(breakdown.receipt.freshness, EntryPointFreshness::Current);
    assert_eq!(breakdown.receipt.records_selected, Some(1));
    assert_eq!(breakdown.receipt.grounding_records_selected, Some(2));
    assert_eq!(breakdown.receipt.grounding_limit, Some(2));
    let entry = &breakdown.entries[0];
    assert_eq!(entry.name, "catalog name");
    assert_eq!(entry.kind, "http_route");
    assert_eq!(entry.source, "src/routes.rs:42");
    assert_eq!(entry.source_framework.as_deref(), Some("Flask"));
    assert_eq!(entry.evidence, "catalog evidence");
    assert_eq!(entry.risk, "high · score 78 · rank 0");
    assert_eq!(entry.trust_zone, "internet");
    assert_eq!(entry.description, "admin route");
    assert_eq!(entry.targets.len(), 2);
    assert_eq!(entry.disposition, EntryPointDisposition::Modeled);
}

#[test]
fn generated_large_fixture_reports_519_16_7_528_without_dropping_rows() {
    let target = tempfile::tempdir().unwrap();
    let catalog_rows = (0..519)
        .map(|index| {
            json!({
                "id": format!("EP-{index}"), "name": format!("entry {index}"),
                "kind": "http_route", "path": format!("src/{index}.rs"), "line": index + 1
            })
        })
        .collect::<Vec<_>>();
    let model_rows = (0..7)
        .chain(519..528)
        .map(|index| {
            json!({
                "id": format!("EP-{index}"), "name": format!("modeled {index}"),
                "kind": "http_route", "trustZone": "internet", "targetElementIds": []
            })
        })
        .collect::<Vec<_>>();
    let deprioritized = (7..12)
        .map(|index| json!({"entryPointId": format!("EP-{index}"), "reason": "bounded"}))
        .collect::<Vec<_>>();
    let catalog = artifact(json!({"total": 519, "entryPoints": catalog_rows}));
    let model = artifact(json!({
        "attackSurface": {"entryPoints": model_rows}, "deprioritized": deprioritized
    }));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        None,
        None,
    );

    assert_eq!(breakdown.counts.extracted, 519);
    assert_eq!(breakdown.counts.modeled, 16);
    assert_eq!(breakdown.counts.overlap, 7);
    assert_eq!(breakdown.counts.deprioritized, 5);
    assert_eq!(breakdown.counts.unrepresented, 507);
    assert_eq!(breakdown.counts.model_only, 9);
    assert_eq!(breakdown.counts.union, 528);
    assert_eq!(breakdown.entries.len(), 528);
    assert_eq!(
        breakdown.entries[0].disposition,
        EntryPointDisposition::Modeled
    );
    assert_eq!(
        breakdown.entries[527].disposition,
        EntryPointDisposition::ModelOnly
    );
}

#[test]
fn system_parked_rows_remain_extracted_only_and_unrepresented() {
    let target = tempfile::tempdir().unwrap();
    let catalog = artifact(json!({
        "total": 1,
        "entryPoints": [{
            "id": "EP-1", "name": "route", "kind": "http_route", "path": "src/routes.rs"
        }]
    }));
    let model = artifact(json!({
        "attackSurface": {"entryPoints": []},
        "deprioritized": [{
            "entryPointId": "EP-1",
            "reason": "unaccounted: system bookkeeping",
            "parkedBy": "system"
        }]
    }));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        None,
        None,
    );

    assert_eq!(breakdown.counts.deprioritized, 0);
    assert_eq!(breakdown.counts.unrepresented, 1);
    assert_eq!(
        breakdown.entries[0].disposition,
        EntryPointDisposition::ExtractedOnly
    );
}

#[test]
fn legacy_artifacts_never_claim_current_composition_or_freshness() {
    let target = tempfile::tempdir().unwrap();
    let catalog = artifact(json!({
        "total": 0,
        "provenance": {"revision": "rev", "revisionDirty": false},
        "entryPoints": []
    }));
    let model = artifact(json!({
        "provenance": {"revision": "rev", "revisionDirty": false},
        "attackSurface": {"entryPoints": []}
    }));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        None,
        Some(&git("rev", false)),
    );

    assert_eq!(
        breakdown.receipt.composition,
        EntryPointComposition::ProvenanceUnknown
    );
    assert_eq!(breakdown.receipt.freshness, EntryPointFreshness::Unknown);
}

#[test]
fn threat_root_revision_does_not_attest_catalog_freshness() {
    let target = tempfile::tempdir().unwrap();
    let catalog = artifact(json!({"total": 0, "entryPoints": []}));
    let model = artifact(json!({
        "provenance": {"revision": "rev", "revisionDirty": false},
        "attackSurface": {"entryPoints": []}
    }));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        None,
        Some(&git("rev", false)),
    );

    assert_eq!(breakdown.receipt.revision, None);
    assert_eq!(breakdown.receipt.freshness, EntryPointFreshness::Unknown);
}

#[test]
fn missing_model_receipt_revision_keeps_freshness_unknown() {
    let target = tempfile::tempdir().unwrap();
    let catalog = authenticated_catalog(target.path(), Vec::new(), "new", false);
    let digest = catalog_digest(&catalog);
    let model = artifact(json!({
        "provenance": {"entryPointCatalog": {"sha256": digest}},
        "attackSurface": {"entryPoints": []}
    }));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        Some("sha256:context"),
        Some(&git("new", false)),
    );

    assert_eq!(
        breakdown.receipt.composition,
        EntryPointComposition::Current
    );
    assert_eq!(breakdown.receipt.revision.as_deref(), Some("new"));
    assert_eq!(breakdown.receipt.freshness, EntryPointFreshness::Unknown);
}

#[test]
fn matching_payload_with_disagreeing_model_revision_is_stale() {
    let target = tempfile::tempdir().unwrap();
    let catalog = authenticated_catalog(target.path(), Vec::new(), "rev", false);
    let digest = catalog_digest(&catalog);
    let model = artifact(json!({
        "provenance": {"entryPointCatalog": {
            "sha256": digest, "revision": "other", "revisionDirty": false
            , "contextSha256": "sha256:context"
        }},
        "attackSurface": {"entryPoints": []}
    }));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        Some("sha256:context"),
        Some(&git("rev", false)),
    );

    assert_eq!(breakdown.receipt.freshness, EntryPointFreshness::Stale);
    assert!(breakdown
        .receipt
        .warnings
        .iter()
        .any(|warning| warning.contains("disagrees with the catalog")));
}

#[test]
fn changed_catalog_digest_is_stale_even_at_the_same_clean_revision() {
    let target = tempfile::tempdir().unwrap();
    let catalog = authenticated_catalog(target.path(), Vec::new(), "rev", false);
    let model = artifact(json!({
        "provenance": {"entryPointCatalog": {
            "sha256": "sha256:previous", "revision": "rev", "revisionDirty": false
        }},
        "attackSurface": {"entryPoints": []}
    }));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        Some("sha256:context"),
        Some(&git("rev", false)),
    );

    assert_eq!(
        breakdown.receipt.composition,
        EntryPointComposition::ChangedSinceModel
    );
    assert_eq!(breakdown.receipt.freshness, EntryPointFreshness::Stale);
}

#[test]
fn changed_context_snapshot_is_stale_at_the_same_clean_revision() {
    let target = tempfile::tempdir().unwrap();
    let catalog = authenticated_catalog(target.path(), Vec::new(), "rev", false);
    let digest = catalog_digest(&catalog);
    let model = model_with_catalog_digest(&digest);

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        Some("sha256:new-context"),
        Some(&git("rev", false)),
    );

    assert_eq!(breakdown.receipt.freshness, EntryPointFreshness::Stale);
    assert!(breakdown
        .receipt
        .warnings
        .iter()
        .any(|warning| warning.contains("current context snapshot")));
}

#[test]
fn unavailable_context_digest_never_claims_current() {
    let target = tempfile::tempdir().unwrap();
    let catalog = authenticated_catalog(target.path(), Vec::new(), "rev", false);
    let digest = catalog_digest(&catalog);
    let model = model_with_catalog_digest(&digest);

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        None,
        Some(&git("rev", false)),
    );

    assert_eq!(breakdown.receipt.freshness, EntryPointFreshness::Unknown);
    assert!(breakdown
        .receipt
        .warnings
        .iter()
        .any(|warning| warning.contains("digest unavailable")));
}

#[test]
fn rejected_catalog_derivation_is_stale_but_not_malformed() {
    let target = tempfile::tempdir().unwrap();
    let ready = authenticated_catalog(target.path(), Vec::new(), "rev", false);
    let value = ready.doc().unwrap().clone();
    let catalog = artifact_with_context_authentication(
        value,
        crate::app::EntryPointCatalogContextAuthentication::Rejected(
            "catalog rows do not match context".to_string(),
        ),
    );
    let model = model_with_catalog_digest(&catalog_digest(&catalog));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        Some("sha256:context"),
        Some(&git("rev", false)),
    );

    assert_eq!(
        breakdown.receipt.catalog_artifact,
        EntryPointArtifactStatus::Ready
    );
    assert_eq!(breakdown.receipt.freshness, EntryPointFreshness::Stale);
    assert!(breakdown
        .receipt
        .warnings
        .iter()
        .any(|warning| warning.contains("catalog derivation rejected")));
}

#[test]
fn unavailable_catalog_derivation_never_claims_current() {
    let target = tempfile::tempdir().unwrap();
    let ready = authenticated_catalog(target.path(), Vec::new(), "rev", false);
    let value = ready.doc().unwrap().clone();
    let catalog = artifact_with_context_authentication(
        value,
        crate::app::EntryPointCatalogContextAuthentication::Unavailable(
            "context snapshot unreadable".to_string(),
        ),
    );
    let model = model_with_catalog_digest(&catalog_digest(&catalog));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        Some("sha256:context"),
        Some(&git("rev", false)),
    );

    assert_eq!(
        breakdown.receipt.catalog_artifact,
        EntryPointArtifactStatus::Ready
    );
    assert_eq!(breakdown.receipt.freshness, EntryPointFreshness::Unknown);
    assert!(breakdown
        .receipt
        .warnings
        .iter()
        .any(|warning| warning.contains("catalog derivation unavailable")));
}

#[test]
fn changed_digest_and_revision_are_reported_as_stale_evidence() {
    let target = tempfile::tempdir().unwrap();
    let catalog = authenticated_catalog(target.path(), Vec::new(), "old", false);
    let model = artifact(json!({
        "provenance": {"entryPointCatalog": {
            "sha256": "sha256:old", "revision": "old", "revisionDirty": false
        }},
        "attackSurface": {"entryPoints": []}
    }));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        Some("sha256:context"),
        Some(&git("new", false)),
    );

    assert_eq!(
        breakdown.receipt.composition,
        EntryPointComposition::ChangedSinceModel
    );
    assert_eq!(breakdown.receipt.freshness, EntryPointFreshness::Stale);
}

#[test]
fn matching_dirty_commit_never_claims_freshness() {
    let target = tempfile::tempdir().unwrap();
    let catalog = authenticated_catalog(target.path(), Vec::new(), "rev", true);
    let digest = catalog_digest(&catalog);
    let model = artifact(json!({
        "provenance": {"entryPointCatalog": {
            "sha256": digest, "revision": "rev", "revisionDirty": true
            , "contextSha256": "sha256:context"
        }},
        "attackSurface": {"entryPoints": []}
    }));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        Some("sha256:context"),
        Some(&git("rev", true)),
    );

    assert_eq!(breakdown.receipt.freshness, EntryPointFreshness::Unknown);
    assert!(breakdown
        .receipt
        .warnings
        .iter()
        .any(|warning| warning.contains("freshness is unprovable")));
}

#[test]
fn tampered_payload_degrades_catalog_to_malformed_unknown_provenance() {
    let target = tempfile::tempdir().unwrap();
    let row = catalog_row("EP-1", "one", "http_route", "src/a.rs", json!({}));
    let original = authenticated_catalog(target.path(), vec![row], "rev", false);
    let mut document = original.doc().unwrap().clone();
    document["entryPoints"][0]["evidence"] = json!("tampered");
    let catalog =
        artifact_with_authentication_error(document, "entry-point payload digest mismatch");
    let model = model_with_catalog_digest(&catalog_digest(&catalog));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        Some("sha256:context"),
        Some(&git("rev", false)),
    );

    assert_integrity_failure(&breakdown, "payload digest mismatch");
}

#[test]
fn copied_catalog_for_another_target_degrades_to_unknown_provenance() {
    let target = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let copied = authenticated_catalog(other.path(), Vec::new(), "rev", false);
    let catalog = artifact_with_authentication_error(
        copied.doc().unwrap().clone(),
        "recorded target does not match the active target",
    );
    let model = model_with_catalog_digest(&catalog_digest(&catalog));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        Some("sha256:context"),
        Some(&git("rev", false)),
    );

    assert_integrity_failure(&breakdown, "does not match");
}

#[test]
fn malformed_catalog_remains_explicit_while_model_only_rows_survive() {
    let target = tempfile::tempdir().unwrap();
    let catalog = ArtifactDocument::without_value(EntryPointArtifactStatus::Malformed);
    let model = artifact(json!({
        "attackSurface": {"entryPoints": [{"id": "EP-model", "name": "modeled"}]}
    }));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        None,
        None,
    );

    assert_eq!(breakdown.entries.len(), 1);
    assert_eq!(
        breakdown.entries[0].disposition,
        EntryPointDisposition::ModelOnly
    );
    assert!(breakdown
        .receipt
        .warnings
        .iter()
        .any(|warning| warning.contains("catalog malformed")));
}

#[test]
fn impossible_receipt_counts_are_warned_instead_of_presented_as_authoritative() {
    let target = tempfile::tempdir().unwrap();
    let row = catalog_row("EP-1", "one", "http_route", "src/a.rs", json!({}));
    let catalog = authenticated_catalog(target.path(), vec![row], "rev", false);
    let digest = catalog_digest(&catalog);
    let model = artifact(json!({
        "provenance": {"entryPointCatalog": {
            "sha256": digest, "records": 1, "recordsSelected": 2,
            "groundingLimit": 1, "groundingRecordsSelected": 2
        }},
        "coverage": {"catalogEntryPointsLinked": 3},
        "attackSurface": {"entryPoints": [{"id": "EP-1", "name": "one"}]}
    }));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        None,
        None,
    );
    let warnings = breakdown.receipt.warnings.join("\n");

    assert!(
        warnings.contains("linked coverage 3 does not match 1"),
        "{warnings}"
    );
    assert!(warnings.contains("selected exceeds records"), "{warnings}");
    assert!(warnings.contains("linked exceeds records"), "{warnings}");
    assert!(
        warnings.contains("grounding-selected exceeds grounding limit"),
        "{warnings}"
    );
}

/// A catalog the context snapshot could only partly supply must say so on the
/// page; its rows are real but they are not the whole attack surface.
#[test]
fn partial_catalog_coverage_is_disclosed_instead_of_read_as_the_whole_surface() {
    let target = tempfile::tempdir().unwrap();
    let row = catalog_row("EP-1", "one", "http_route", "src/a.rs", json!({}));
    let mut document = authenticated_catalog(target.path(), vec![row], "rev", false)
        .doc()
        .unwrap()
        .clone();
    document["snapshotCoverage"] = json!({
        "state": "partial", "reason": "snapshot byte budget",
        "arrayCap": 2000, "omittedEntries": 1186
    });
    let catalog = authenticated_artifact(target.path(), document);

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &ArtifactDocument::without_value(EntryPointArtifactStatus::Missing),
        &DfdModel::default(),
        None,
        None,
    );

    assert_eq!(breakdown.entries.len(), 1);
    let warnings = breakdown.receipt.warnings.join("\n");
    assert!(warnings.contains("catalog coverage partial"), "{warnings}");
    assert!(warnings.contains("snapshot byte budget"), "{warnings}");
    assert!(
        warnings.contains("1186 snapshot entries omitted"),
        "{warnings}"
    );
}

/// A catalog recording no coverage — an older artifact, or one the field was
/// removed from — is disclosed as such, never presented as complete.
#[test]
fn a_catalog_recording_no_coverage_is_disclosed_not_assumed_complete() {
    let target = tempfile::tempdir().unwrap();
    let row = catalog_row("EP-1", "one", "http_route", "src/a.rs", json!({}));
    let catalog = authenticated_catalog(target.path(), vec![row], "rev", false);

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &ArtifactDocument::without_value(EntryPointArtifactStatus::Missing),
        &DfdModel::default(),
        None,
        None,
    );

    let warnings = breakdown.receipt.warnings.join("\n");
    assert!(
        warnings.contains("records no snapshot coverage of its own"),
        "{warnings}"
    );
}

/// A catalog that states complete coverage collects no coverage warning.
#[test]
fn a_complete_coverage_catalog_is_not_warned_about() {
    let target = tempfile::tempdir().unwrap();
    let row = catalog_row("EP-1", "one", "http_route", "src/a.rs", json!({}));
    let mut document = authenticated_catalog(target.path(), vec![row], "rev", false)
        .doc()
        .unwrap()
        .clone();
    document["snapshotCoverage"] = json!({"state": "complete"});
    let catalog = authenticated_artifact(target.path(), document);

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &ArtifactDocument::without_value(EntryPointArtifactStatus::Missing),
        &DfdModel::default(),
        None,
        None,
    );

    let warnings = breakdown.receipt.warnings.join("\n");
    assert!(!warnings.contains("coverage"), "{warnings}");
}

/// A catalog with no threat model beside it still knows how many records it
/// holds. Reading that count only out of the model's provenance receipt left a
/// real, current catalog reporting its own size as unknown.
#[test]
fn a_catalog_without_a_model_still_reports_its_own_record_count() {
    let target = tempfile::tempdir().unwrap();
    let rows = vec![
        catalog_row("EP-1", "one", "http_route", "src/a.rs", json!({})),
        catalog_row("EP-2", "two", "http_route", "src/b.rs", json!({})),
    ];
    let catalog = authenticated_catalog(target.path(), rows, "rev", false);

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &ArtifactDocument::without_value(EntryPointArtifactStatus::Missing),
        &DfdModel::default(),
        None,
        None,
    );

    assert_eq!(breakdown.receipt.records, Some(2));
    assert_eq!(breakdown.counts.extracted, 2);
    // Selection is the model's work, so it stays absent rather than inheriting
    // the catalog's count.
    assert_eq!(breakdown.receipt.records_selected, None);
    assert_eq!(breakdown.receipt.grounding_limit, None);
    assert_eq!(breakdown.receipt.grounding_records_selected, None);
    assert_eq!(breakdown.receipt.records_linked, None);
    assert_eq!(breakdown.receipt.selection_policy, None);
}

/// What the model recorded reading stays authoritative where it exists; the
/// catalog's declared total is only the fallback.
#[test]
fn a_model_receipt_record_count_outranks_the_catalog_total() {
    let target = tempfile::tempdir().unwrap();
    let rows = vec![catalog_row(
        "EP-1",
        "one",
        "http_route",
        "src/a.rs",
        json!({}),
    )];
    let catalog = authenticated_catalog(target.path(), rows, "rev", false);
    let digest = catalog_digest(&catalog);
    let model = artifact(json!({
        "provenance": {"entryPointCatalog": {
            "status": "loaded", "sha256": digest, "records": 7,
            "revision": "rev", "revisionDirty": false,
            "contextSha256": "sha256:context"
        }},
        "attackSurface": {"entryPoints": []}
    }));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        None,
        None,
    );

    assert_eq!(breakdown.receipt.records, Some(7));
    let warnings = breakdown.receipt.warnings.join("\n");
    assert!(
        warnings.contains("catalog receipt records 7 does not match 1"),
        "{warnings}"
    );
}

/// A receipt naming how many records the model selected while declaring no
/// record count of its own is still weighed against the total the line shows.
/// Without that, the page reported `catalog 1 · modeled 2` — the first read off
/// the catalog, the second off the model — and warned about neither.
#[test]
fn model_counts_are_weighed_against_the_total_the_receipt_reports() {
    let target = tempfile::tempdir().unwrap();
    let rows = vec![catalog_row(
        "EP-1",
        "one",
        "http_route",
        "src/a.rs",
        json!({}),
    )];
    let catalog = authenticated_catalog(target.path(), rows, "rev", false);
    let digest = catalog_digest(&catalog);
    let model = artifact(json!({
        "provenance": {"entryPointCatalog": {
            "status": "loaded", "sha256": digest,
            "recordsSelected": 2, "revision": "rev", "revisionDirty": false,
            "contextSha256": "sha256:context"
        }},
        "attackSurface": {"entryPoints": []}
    }));

    let breakdown = entry_point_breakdown_from_artifacts(
        target.path(),
        &catalog,
        &model,
        &DfdModel::default(),
        None,
        None,
    );

    assert_eq!(breakdown.receipt.records, Some(1));
    assert_eq!(breakdown.receipt.records_selected, Some(2));
    let warnings = breakdown.receipt.warnings.join("\n");
    assert!(warnings.contains("selected exceeds records"), "{warnings}");
}

fn authenticated_catalog(
    target: &Path,
    rows: Vec<Value>,
    revision: &str,
    dirty: bool,
) -> ArtifactDocument {
    let records: Vec<CatalogRecordForDigest> =
        serde_json::from_value(Value::Array(rows.clone())).unwrap();
    let canonical = serde_json::to_string(&records).unwrap();
    let digest = kuzushi_core::prompt_content_sha256(&canonical);
    authenticated_artifact(
        target,
        json!({
            "target": std::fs::canonicalize(target).unwrap(),
            "timestamp": 20,
            "snapshotTimestamp": 10,
            "total": rows.len(),
            "entryPoints": rows,
            "provenance": {
                "builtAtMs": 20, "sha256": digest,
                "revision": revision, "revisionDirty": dirty,
                "contextSnapshotTimestamp": 10, "contextSnapshotSha256": "sha256:context"
            }
        }),
    )
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CatalogRecordForDigest {
    #[serde(flatten)]
    surface: kuzushi_core::workspace::attack_surface::AttackSurface,
    #[serde(default)]
    name: Value,
    #[serde(default)]
    location: Value,
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

fn catalog_row(id: &str, name: &str, kind: &str, path: &str, extra: Value) -> Value {
    let mut row = json!({
        "id": id, "kind": kind, "path": path, "language": "Rust",
        "title": name, "name": name, "location": path,
        "evidence": name, "metadata": null,
        "risk": {"rank": 0, "score": 0, "tier": "low", "reasons": []}
    });
    row.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    row
}

fn catalog_digest(catalog: &ArtifactDocument) -> String {
    catalog
        .doc()
        .and_then(|doc| doc.pointer("/provenance/sha256"))
        .and_then(Value::as_str)
        .unwrap()
        .to_string()
}

fn model_with_catalog_digest(digest: &str) -> ArtifactDocument {
    artifact(json!({
        "provenance": {"entryPointCatalog": {
            "sha256": digest, "revision": "rev", "revisionDirty": false,
            "contextSha256": "sha256:context"
        }},
        "attackSurface": {"entryPoints": []}
    }))
}

fn assert_integrity_failure(breakdown: &EntryPointBreakdown, expected: &str) {
    assert_eq!(
        breakdown.receipt.catalog_artifact,
        EntryPointArtifactStatus::Malformed
    );
    assert_eq!(
        breakdown.receipt.composition,
        EntryPointComposition::ProvenanceUnknown
    );
    assert_eq!(breakdown.receipt.freshness, EntryPointFreshness::Unknown);
    assert!(breakdown
        .receipt
        .warnings
        .iter()
        .any(|warning| warning.contains(expected)));
}

fn artifact(value: Value) -> ArtifactDocument {
    ArtifactDocument::ready(value)
}

fn authenticated_artifact(_target: &Path, value: Value) -> ArtifactDocument {
    let authentication = authentication_for(&value);
    ArtifactDocument::ready_with_catalog_authentication(
        value,
        Some(Ok(authentication.clone())),
        Some(crate::app::EntryPointCatalogContextAuthentication::Authenticated(authentication)),
    )
}

fn artifact_with_context_authentication(
    value: Value,
    context_authentication: crate::app::EntryPointCatalogContextAuthentication,
) -> ArtifactDocument {
    let authentication = authentication_for(&value);
    ArtifactDocument::ready_with_catalog_authentication(
        value,
        Some(Ok(authentication)),
        Some(context_authentication),
    )
}

fn authentication_for(
    value: &Value,
) -> kuzushi_core::capabilities::entry_points::EntryPointCatalogAuthentication {
    kuzushi_core::capabilities::entry_points::EntryPointCatalogAuthentication {
        sha256: value["provenance"]["sha256"].as_str().unwrap().to_string(),
        total: value["total"].as_u64().unwrap() as usize,
        snapshot_timestamp: value["snapshotTimestamp"].as_u64().unwrap(),
        context_sha256: value["provenance"]["contextSnapshotSha256"]
            .as_str()
            .unwrap()
            .to_string(),
        tree_hash: value["provenance"]["contextSnapshotTreeHash"]
            .as_str()
            .map(str::to_string),
    }
}

fn artifact_with_authentication_error(value: Value, error: &str) -> ArtifactDocument {
    ArtifactDocument::ready_with_catalog_authentication(value, Some(Err(error.to_string())), None)
}

fn git(sha: &str, dirty: bool) -> RunTargetGitMetadata {
    RunTargetGitMetadata {
        sha: sha.to_string(),
        branch: None,
        dirty,
    }
}

fn topology() -> DfdModel {
    DfdModel {
        nodes: vec![DfdNodeModel {
            key: "N1".into(),
            name: "Admin API".into(),
            description: None,
            purpose: None,
            zone: "app".into(),
            kind: DfdKind::Process,
        }],
        boundaries: vec![DfdBoundaryModel {
            key: "TB1".into(),
            name: "Internet to app".into(),
            inner_zone: "app".into(),
            outer_zone: "internet".into(),
            crossing_flow_ids: Vec::new(),
        }],
        ..Default::default()
    }
}
