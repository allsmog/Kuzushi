use super::*;

fn fixture_target() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("src")).unwrap();
    std::fs::write(temp.path().join("src/app.py"), "a\nb\nc\n").unwrap();
    temp
}

fn initialize_git(target: &Path) {
    for args in [
        &["init", "-q"][..],
        &["add", "-A"],
        &["commit", "-qm", "init"],
    ] {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(target)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    }
}

fn document(files: &[&str]) -> Value {
    json!({
        "methodology": "stride",
        "dfd": {
            "nodes": [{"id": "download-handler"}],
            "flows": [],
            "trustBoundaries": []
        },
        "threats": [{
            "id": "T-001",
            "targetElementIds": ["download-handler"],
            "title": "traversal",
            "affectedFiles": files,
            "evidenceAnchors": [{"filePath": files[0], "startLine": 2, "description": "join"}],
        }],
        "attackSurface": {
            "entryPoints": [{
                "id": "AS-download",
                "targetElementIds": ["download-handler"],
                "name": "download",
                "evidence": format!("{}:1", files[0])
            }],
        },
    })
}

fn catalog_surface(index: usize) -> crate::attack_surface::AttackSurface {
    let mut surface = crate::attack_surface::AttackSurface {
        id: String::new(),
        kind: crate::attack_surface::AttackSurfaceKind::RpcHandler,
        path: format!("src/command_{index}.rs"),
        line: Some(1),
        language: "Rust".to_string(),
        framework: Some("Tauri".to_string()),
        title: format!("command_{index}"),
        evidence: "#[tauri::command]".to_string(),
        method: None,
        route: None,
        boundary: None,
        risk: crate::attack_surface::AttackSurfaceRisk {
            rank: index + 1,
            score: 100 - index as u16,
            tier: "high".to_string(),
            reasons: vec!["test ingress".to_string()],
        },
        metadata: json!({"sourcePolicy": crate::workspace::rust_surface_policy::RUST_SURFACE_POLICY}),
    };
    surface.id = crate::workspace::attack_surface::attack_surface_id(&surface);
    surface
}

fn write_explicit_catalog(
    target: &Path,
) -> (
    crate::capabilities::entry_points::EntryPointCatalog,
    Vec<String>,
) {
    let entries = catalog_entries();
    let sha256 = crate::capabilities::entry_points::entry_points_sha256(&entries).unwrap();
    let ids = entries
        .iter()
        .map(|entry| entry.surface.id.clone())
        .collect();
    let catalog = explicit_catalog(target, entries, sha256.clone());
    let state = crate::workspace::workspace_state_root(target);
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(
        state.join(crate::capabilities::entry_points::ENTRY_POINTS_FILE),
        serde_json::to_vec_pretty(&catalog).unwrap(),
    )
    .unwrap();
    (catalog, ids)
}

fn catalog_entries() -> Vec<crate::capabilities::entry_points::EntryPointRecord> {
    (0..4)
        .map(
            |index| crate::capabilities::entry_points::EntryPointRecord {
                surface: catalog_surface(index),
                name: Value::Null,
                location: Value::Null,
                extra: Map::new(),
            },
        )
        .collect()
}

fn explicit_catalog(
    target: &Path,
    entries: Vec<crate::capabilities::entry_points::EntryPointRecord>,
    sha256: String,
) -> crate::capabilities::entry_points::EntryPointCatalog {
    let git = crate::workspace::target_git_metadata(target);
    crate::capabilities::entry_points::EntryPointCatalog {
        target: target.canonicalize().unwrap().display().to_string(),
        timestamp: 10,
        snapshot_timestamp: 9,
        total: entries.len(),
        entry_points: entries,
        snapshot_coverage: crate::capabilities::entry_points::EntryPointSnapshotCoverage::Complete,
        provenance: crate::capabilities::entry_points::EntryPointCatalogProvenance {
            built_at_ms: 10,
            sha256: sha256.clone(),
            revision: git.as_ref().map(|metadata| metadata.sha.clone()),
            revision_dirty: git.as_ref().map(|metadata| metadata.dirty),
            context_snapshot_timestamp: 9,
            context_snapshot_sha256: "sha256:explicit-context".to_string(),
            context_snapshot_tree_hash: Some(
                crate::incremental_index::current_workspace_tree_hash(target).unwrap(),
            ),
        },
    }
}

fn catalog_backed_document(
    catalog: &crate::capabilities::entry_points::EntryPointCatalog,
    ids: &[String],
) -> Value {
    json!({
        "dfd": {
            "nodes": [{"id": "desktop-shell"}],
            "flows": [],
            "trustBoundaries": []
        },
        "attackSurface": {"entryPoints": ids.iter().map(|id| json!({
            "id": id,
            "targetElementIds": ["desktop-shell"],
            "name": id,
        })).collect::<Vec<_>>()},
        "threats": [{
            "id": "T-catalog",
            "targetElementIds": ["desktop-shell"],
            "entryPointIds": ids,
            "title": "catalog ingress",
        }],
        "coverage": {"entryPointsConsidered": 1, "scope": "refine delta"},
        "provenance": {"entryPointCatalog": {
            "status": "explicit",
            "sha256": catalog.provenance.sha256,
            "records": catalog.total,
            "recordsSelected": catalog.total,
            "groundingLimit": catalog.total,
            "groundingRecordsSelected": catalog.total,
            "snapshotTimestamp": catalog.snapshot_timestamp,
            "contextSha256": catalog.provenance.context_snapshot_sha256,
            "treeHash": catalog.provenance.context_snapshot_tree_hash,
            "revision": catalog.provenance.revision,
            "revisionDirty": catalog.provenance.revision_dirty,
            "selectionPolicy": crate::capabilities::entry_points::ENTRY_POINT_SELECTION_POLICY,
        }},
    })
}

fn cover_current_grounding(mut document: Value, target: &Path) -> Value {
    let deprioritized = noncatalog_verification_surfaces(target)
        .unwrap()
        .into_iter()
        .map(|surface| {
            json!({
                "entryPointId": surface.id,
                "entryPoint": surface.title,
                "reason": "verification fixture explicitly accepts this surface",
            })
        })
        .collect::<Vec<_>>();
    document["deprioritized"] = json!(deprioritized);
    if !document.get("provenance").is_some_and(Value::is_object) {
        document["provenance"] = json!({});
    }
    let provenance = document["provenance"].as_object_mut().unwrap();
    provenance.insert(
        "treeHash".to_string(),
        json!(crate::incremental_index::current_workspace_tree_hash(target).unwrap()),
    );
    if let Some(git) = crate::workspace::target_git_metadata(target) {
        provenance.insert("revision".to_string(), json!(git.sha));
        provenance.insert("revisionDirty".to_string(), json!(git.dirty));
    }
    document
}

/// A snapshot that parsed fine when it was written but names a revision the
/// target has since moved past — the ordinary "one more commit" state.
fn write_stale_context_snapshot(target: &Path) {
    let path = crate::context::context_snapshot_path(target);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let snapshot = json!({
        "target": target.canonicalize().unwrap().display().to_string(),
        "timestamp": 9,
        "provenance": {
            "revision": "0000000000000000000000000000000000000000",
            "revisionDirty": false,
        },
        "attackSurfaceMap": {"surfaces": []},
    });
    std::fs::write(&path, serde_json::to_string_pretty(&snapshot).unwrap()).unwrap();
}

#[test]
fn path_refs_cover_affected_files_evidence_strings_and_anchors() {
    let refs = cited_path_refs(&document(&["src/app.py"]));
    assert!(refs
        .iter()
        .any(|r| r.path == "src/app.py" && r.line == Some(2)));
    assert!(refs
        .iter()
        .any(|r| r.path == "src/app.py" && r.line == Some(1)));
    assert!(refs
        .iter()
        .any(|r| r.path == "src/app.py" && r.line.is_none()));
}

#[test]
fn existing_citations_verify_and_missing_citations_fail() {
    let target = fixture_target();
    let good_document = cover_current_grounding(document(&["src/app.py"]), target.path());
    let good = verify_threat_model_document(&good_document, target.path()).unwrap();
    assert_eq!(good.verdict, "verified");
    assert_eq!(good.missing_count, 0);
    assert_eq!(
        good.revision.matches, None,
        "non-git target is tri-state unknown, not a failure"
    );

    let bad_document = cover_current_grounding(document(&["src/gone.py"]), target.path());
    let bad = verify_threat_model_document(&bad_document, target.path()).unwrap();
    assert_eq!(bad.verdict, "failed");
    assert!(bad.missing_count >= 1);
    assert!(bad
        .missing
        .iter()
        .any(|entry| entry.contains("src/gone.py")));
}

#[test]
fn dangling_security_context_links_fail_verification() {
    let target = fixture_target();
    let mut doc = cover_current_grounding(document(&["src/app.py"]), target.path());
    doc["attackSurface"]["entryPoints"][0]["targetElementIds"] = json!(["missing"]);

    let verification = verify_threat_model_document(&doc, target.path()).unwrap();

    assert_eq!(verification.verdict, "failed");
    assert_eq!(verification.link_error_count, 1);
    assert!(verification.link_errors[0].contains("unknown DFD id `missing`"));
}

#[test]
fn out_of_range_lines_and_escaping_paths_are_flagged() {
    let target = fixture_target();
    let mut doc = cover_current_grounding(document(&["src/app.py"]), target.path());
    doc["threats"][0]["evidenceAnchors"][0]["startLine"] = json!(999);
    let verification = verify_threat_model_document(&doc, target.path()).unwrap();
    assert_eq!(verification.verdict, "failed");
    assert!(verification
        .missing
        .iter()
        .any(|entry| entry.contains("999")));

    let hostile = cover_current_grounding(document(&["../outside.py"]), target.path());
    let verification = verify_threat_model_document(&hostile, target.path()).unwrap();
    assert!(verification
        .missing
        .iter()
        .any(|entry| entry.contains("escapes the target root")));
}

#[test]
fn revision_mismatch_in_a_git_checkout_is_stale_and_warns() {
    let target = fixture_target();
    let git = |args: &[&str]| {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(target.path())
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-qm", "init"]);

    let mut doc = cover_current_grounding(document(&["src/app.py"]), target.path());
    doc["provenance"] = json!({"revision": "0000000000000000000000000000000000000000"});
    let verification = verify_threat_model_document(&doc, target.path()).unwrap();
    assert_eq!(verification.verdict, "stale");
    assert_eq!(verification.revision.matches, Some(false));
    let warning = verification_warning(&doc, target.path()).unwrap();
    assert!(warning.contains("may be stale"), "warning: {warning}");
}

#[test]
fn stamped_failed_verdict_warns_without_revision_drift() {
    let target = fixture_target();
    let mut doc = cover_current_grounding(document(&["src/app.py"]), target.path());
    let mut verification = verify_threat_model_document(&doc, target.path()).unwrap();
    verification.verdict = "failed".to_string();
    stamp_verification(&mut doc, &verification);
    let warning = verification_warning(&doc, target.path()).unwrap();
    assert!(warning.contains("evidence, security-context-link, or entry-point coverage"));
}

#[test]
fn verification_checks_every_catalog_row_and_fails_uncovered_ingress() {
    let target = fixture_target();
    let (catalog, ids) = write_explicit_catalog(target.path());
    let mut doc = cover_current_grounding(catalog_backed_document(&catalog, &ids), target.path());

    let complete = verify_threat_model_document(&doc, target.path()).unwrap();
    assert!(
        complete.coverage_considered >= catalog.total,
        "verification derives scope from the full catalog and current non-catalog target"
    );
    assert_eq!(complete.coverage_gaps, 0);
    assert_eq!(complete.verdict, "verified");

    doc["threats"][0]["entryPointIds"] = json!([ids[0], ids[1], ids[2]]);
    let incomplete = verify_threat_model_document(&doc, target.path()).unwrap();
    assert_eq!(incomplete.coverage_gaps, 1);
    assert_eq!(incomplete.verdict, "failed");
}

#[test]
fn catalog_backed_verification_never_falls_back_on_digest_drift() {
    let target = fixture_target();
    let (catalog, ids) = write_explicit_catalog(target.path());
    let mut doc = catalog_backed_document(&catalog, &ids);
    doc["provenance"]["entryPointCatalog"]["sha256"] = json!("sha256:other");

    let error = verify_threat_model_document(&doc, target.path()).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("does not match the threat-model receipt"),
        "{error:#}"
    );
}

#[test]
fn catalog_receipt_source_identity_must_match_authenticated_catalog() {
    let target = fixture_target();
    let (catalog, ids) = write_explicit_catalog(target.path());
    let cases = [
        ("contextSha256", json!("sha256:other-context")),
        ("treeHash", json!("sha256:other-tree")),
        ("revisionDirty", json!(true)),
    ];

    for (field, value) in cases {
        let mut doc = catalog_backed_document(&catalog, &ids);
        doc["provenance"]["entryPointCatalog"][field] = value;

        let error = verify_threat_model_document(&doc, target.path()).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("does not match the threat-model receipt"),
            "field {field}: {error:#}"
        );
    }
}

#[test]
fn tampered_catalog_counts_cannot_shrink_verification_scope() {
    let target = fixture_target();
    let (catalog, ids) = write_explicit_catalog(target.path());
    let mut doc =
        cover_current_grounding(catalog_backed_document(&catalog, &ids[..1]), target.path());
    let receipt = &mut doc["provenance"]["entryPointCatalog"];
    receipt["records"] = json!(1);
    receipt["recordsSelected"] = json!(1);
    receipt["groundingLimit"] = json!(1);
    receipt["groundingRecordsSelected"] = json!(1);

    let verification = verify_threat_model_document(&doc, target.path()).unwrap();

    assert!(verification.coverage_considered >= catalog.total);
    assert!(verification.coverage_gaps >= catalog.total - 1);
    assert_eq!(verification.verdict, "failed");
}

#[test]
fn explicit_catalog_rejects_same_head_dirty_tree_byte_drift() {
    let target = fixture_target();
    initialize_git(target.path());
    std::fs::write(target.path().join("src/app.py"), "dirty version one\n").unwrap();
    let (catalog, ids) = write_explicit_catalog(target.path());
    let doc = cover_current_grounding(catalog_backed_document(&catalog, &ids), target.path());
    std::fs::write(target.path().join("src/app.py"), "dirty version two\n").unwrap();

    let error = verify_threat_model_document(&doc, target.path()).unwrap_err();

    assert!(error.to_string().contains("stale"), "{error:#}");
}

#[test]
fn disabled_catalog_rejects_same_head_dirty_tree_byte_drift() {
    let target = fixture_target();
    initialize_git(target.path());
    std::fs::write(target.path().join("src/app.py"), "dirty version one\n").unwrap();
    let mut doc = cover_current_grounding(document(&["src/app.py"]), target.path());
    let provenance = doc["provenance"].clone();
    doc["provenance"]["entryPointCatalog"] = json!({
        "status": "disabled",
        "sha256": null,
        "records": 0,
        "recordsSelected": 0,
        "groundingLimit": 1,
        "groundingRecordsSelected": 1,
        "snapshotTimestamp": null,
        "contextSha256": null,
        "treeHash": provenance["treeHash"],
        "revision": provenance["revision"],
        "revisionDirty": provenance["revisionDirty"],
        "selectionPolicy": crate::capabilities::entry_points::ENTRY_POINT_SELECTION_POLICY,
    });
    std::fs::write(target.path().join("src/app.py"), "dirty version two\n").unwrap();

    let error = verify_threat_model_document(&doc, target.path()).unwrap_err();

    assert!(
        error.to_string().contains("source tree is stale"),
        "{error:#}"
    );
}

#[test]
fn dirty_no_catalog_document_requires_a_bound_tree_identity() {
    let target = fixture_target();
    initialize_git(target.path());
    std::fs::write(target.path().join("src/app.py"), "dirty\n").unwrap();
    let mut doc = cover_current_grounding(document(&["src/app.py"]), target.path());
    doc["provenance"]
        .as_object_mut()
        .unwrap()
        .remove("treeHash");

    let error = verify_threat_model_document(&doc, target.path()).unwrap_err();

    assert!(error
        .to_string()
        .contains("requires a bound provenance treeHash"));
}

#[test]
fn verification_uses_fixed_current_noncatalog_scope() {
    let target = fixture_target();
    let expected = noncatalog_verification_surfaces(target.path()).unwrap();
    let mut doc = cover_current_grounding(document(&["src/app.py"]), target.path());
    doc["coverage"] = json!({"entryPointsConsidered": 1});
    doc["provenance"] = json!({"entryPointCatalog": {
        "status": "missing",
        "sha256": null,
        "records": 0,
        "recordsSelected": 0,
        "groundingLimit": 30,
        "groundingRecordsSelected": 1,
        "snapshotTimestamp": null,
        "contextSha256": null,
        "treeHash": crate::incremental_index::current_workspace_tree_hash(target.path()).unwrap(),
        "selectionPolicy": DETERMINISTIC_ENTRY_POINT_SELECTION_POLICY,
    }});

    let verification = verify_threat_model_document(&doc, target.path()).unwrap();

    assert_eq!(verification.coverage_considered, expected.len());
    assert_eq!(verification.coverage_gaps, 0);
    assert_eq!(verification.verdict, "verified");
}

#[test]
fn stale_context_snapshot_degrades_grounding_instead_of_failing_verification() {
    let target = fixture_target();
    initialize_git(target.path());
    write_stale_context_snapshot(target.path());
    let doc = cover_current_grounding(document(&["src/app.py"]), target.path());

    let verification = verify_threat_model_document(&doc, target.path()).unwrap();

    assert_eq!(verification.verdict, "stale");
    assert_eq!(verification.grounding_source, "noncatalog");
    let disclosure = verification.grounding_degraded.unwrap();
    assert!(
        disclosure.contains("context snapshot revision is stale"),
        "{disclosure}"
    );
    assert!(disclosure.contains("context:build"), "{disclosure}");
}

#[test]
fn degraded_grounding_warns_every_consumer_of_the_stamped_document() {
    let target = fixture_target();
    initialize_git(target.path());
    write_stale_context_snapshot(target.path());
    let mut doc = cover_current_grounding(document(&["src/app.py"]), target.path());
    let verification = verify_threat_model_document(&doc, target.path()).unwrap();
    stamp_verification(&mut doc, &verification);

    let warning = verification_warning(&doc, target.path()).unwrap();

    assert!(
        warning.contains("could not use the entry-point catalog"),
        "{warning}"
    );
}

#[test]
fn absent_and_stale_context_snapshots_ground_verification_the_same_way() {
    let target = fixture_target();
    initialize_git(target.path());
    let doc = cover_current_grounding(document(&["src/app.py"]), target.path());

    let absent = verify_threat_model_document(&doc, target.path()).unwrap();
    write_stale_context_snapshot(target.path());
    let stale = verify_threat_model_document(&doc, target.path()).unwrap();

    assert_eq!(absent.grounding_source, "noncatalog");
    assert_eq!(stale.grounding_source, "noncatalog");
    assert_eq!(absent.coverage_considered, stale.coverage_considered);
    assert_eq!(absent.coverage_gaps, stale.coverage_gaps);
    assert_eq!(absent.verdict, "verified");
    assert!(absent.grounding_degraded.is_none());
    assert_eq!(stale.verdict, "stale", "degraded grounding is never a pass");
    assert!(stale.grounding_degraded.is_some());
}

fn scoped_fixture() -> (tempfile::TempDir, ThreatModelBuildRoots) {
    let workspace = tempfile::tempdir().unwrap();
    let api = workspace.path().join("services/api");
    let web = workspace.path().join("services/web");
    std::fs::create_dir_all(api.join("src")).unwrap();
    std::fs::create_dir_all(web.join("src")).unwrap();
    std::fs::write(
        api.join("src/app.py"),
        "def api(request):\n    return request\n",
    )
    .unwrap();
    std::fs::write(
        web.join("src/app.py"),
        "def web(request):\n    return request\n",
    )
    .unwrap();
    let roots = ThreatModelBuildRoots {
        workspace_root: workspace.path().canonicalize().unwrap(),
        analysis_root: api.canonicalize().unwrap(),
        scope: Some(ScopeRef {
            scope_id: "scope_api".to_string(),
            rel_path: PathBuf::from("services/api"),
            project_model_sha256: format!("sha256:{}", "a".repeat(64)),
            target_revision: "fixture".to_string(),
        }),
    };
    (workspace, roots)
}

fn cover_scoped_grounding(mut doc: Value, roots: &ThreatModelBuildRoots) -> Value {
    let surfaces = scoped_verification_grounding(roots).unwrap().surfaces;
    doc["deprioritized"] = json!(surfaces
        .into_iter()
        .map(|surface| json!({
            "entryPointId": surface.id,
            "entryPoint": surface.title,
            "reason": "scope verification fixture accepts this surface",
        }))
        .collect::<Vec<_>>());
    doc["provenance"] = json!({
        "treeHash": crate::incremental_index::current_workspace_tree_hash(
            &roots.workspace_root
        ).unwrap(),
        "entryPointCatalog": {
            "status": "scoped-derived",
            "sha256": null,
            "records": 0,
            "recordsSelected": 0,
            "groundingLimit": 40,
            "groundingRecordsSelected": 0,
            "snapshotTimestamp": null,
            "contextSha256": null,
            "treeHash": crate::incremental_index::current_workspace_tree_hash(
                &roots.workspace_root
            ).unwrap(),
            "revision": null,
            "revisionDirty": null,
            "selectionPolicy": DETERMINISTIC_ENTRY_POINT_SELECTION_POLICY,
        }
    });
    doc
}

#[test]
fn scoped_verification_resolves_workspace_paths_and_uses_only_scope_surfaces() {
    let (_workspace, roots) = scoped_fixture();
    let doc = cover_scoped_grounding(document(&["services/api/src/app.py"]), &roots);
    let scoped_surfaces = scoped_verification_grounding(&roots).unwrap().surfaces;

    let verification = verify_threat_model_document_with_roots(&doc, &roots).unwrap();

    assert_eq!(verification.missing_count, 0);
    assert_eq!(verification.coverage_considered, scoped_surfaces.len());
    assert_eq!(verification.coverage_gaps, 0);
    assert_eq!(verification.verdict, "verified");
}

#[test]
fn scoped_verification_refuses_a_workspace_sibling_citation() {
    let (_workspace, roots) = scoped_fixture();
    let doc = cover_scoped_grounding(document(&["services/web/src/app.py"]), &roots);

    let verification = verify_threat_model_document_with_roots(&doc, &roots).unwrap();

    assert_eq!(verification.verdict, "failed");
    assert!(verification
        .missing
        .iter()
        .any(|problem| problem.contains("outside the selected scope")));
}
