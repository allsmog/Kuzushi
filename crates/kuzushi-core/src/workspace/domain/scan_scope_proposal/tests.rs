use super::*;
mod editing;

#[test]
fn loose_root_files_and_prefix_collisions_remain_uncovered() {
    let draft = draft(vec![scope("app", &["app"]), scope("library", &["lib"])]);
    let coverage = draft
        .evaluate(&inventory(&[
            "app/a.rs",
            "app2/b.rs",
            "lib/c.rs",
            "root.rs",
        ]))
        .unwrap();
    assert_eq!(coverage.uncovered_files.files, vec!["app2/b.rs", "root.rs"]);
    assert_eq!(coverage.discovery_members["app"].files, vec!["app/a.rs"]);
}

#[test]
fn literal_route_names_and_spaces_are_matched_without_glob_interpretation() {
    let draft = draft(vec![scope("route", &["app/[slug]", " space.rs"])]);
    let coverage = draft
        .evaluate(&inventory(&[
            "app/[slug]/route.ts",
            "app/other.ts",
            " space.rs",
        ]))
        .unwrap();
    assert_eq!(
        coverage.discovery_members["route"].files,
        vec![" space.rs", "app/[slug]/route.ts"]
    );
    assert_eq!(coverage.uncovered_files.files, vec!["app/other.ts"]);
}

#[test]
fn overlapping_scopes_are_visible_without_duplicating_members_within_a_scope() {
    let draft = draft(vec![scope("root", &[".", "app"]), scope("app", &["app"])]);
    let coverage = draft
        .evaluate(&inventory(&["app/a.rs", "root.rs"]))
        .unwrap();
    assert_eq!(coverage.overlaps.files["app/a.rs"], vec!["root", "app"]);
    assert_eq!(coverage.discovery_members["root"].files.len(), 2);
}

#[test]
fn shared_context_never_becomes_discovery_without_an_explicit_choice() {
    let mut draft = draft(vec![scope("app", &["app"])]);
    draft.shared_scope = Some(scope("integration", &["root.rs"]));
    let inventory = inventory(&["app/a.rs", "root.rs"]);
    let coverage = draft.evaluate(&inventory).unwrap();
    assert_eq!(
        coverage.context_members["integration"].files,
        vec!["root.rs"]
    );
    assert_eq!(coverage.uncovered_files.files, vec!["root.rs"]);
    assert!(!coverage.discovery_members.contains_key("integration"));
    draft.shared_discovery = true;
    let coverage = draft.evaluate(&inventory).unwrap();
    assert!(coverage.uncovered_files.files.is_empty());
    assert_eq!(
        coverage.discovery_members["integration"].files,
        vec!["root.rs"]
    );
}

#[test]
fn explicit_exclusions_remove_discovery_and_disclose_the_conflict() {
    let mut draft = draft(vec![scope("root", &["."])]);
    draft.exclusions.push(ScanScopeExclusion {
        path: "lib".into(),
        reason: "Operator excluded this dependency".into(),
    });
    let coverage = draft
        .evaluate(&inventory(&["app/a.rs", "lib/b.rs"]))
        .unwrap();
    assert_eq!(coverage.excluded_files.files, vec!["lib/b.rs"]);
    assert_eq!(
        coverage.conflicting_exclusions.files["lib/b.rs"],
        vec!["root"]
    );
    assert_eq!(coverage.discovery_members["root"].files, vec!["app/a.rs"]);
    assert!(coverage.uncovered_files.files.is_empty());
}

#[test]
fn invalid_and_unknown_paths_fail_before_coverage_is_reported() {
    let inventory = inventory(&["app/a.rs"]);
    for path in [
        "",
        "/app",
        "../app",
        "app/../app",
        "./app",
        "app//a.rs",
        "app/",
        "C:/app",
        "app\\a.rs",
        "app/*",
        "missing",
        " app",
        "app\n",
    ] {
        let draft = draft(vec![scope("app", &[path])]);
        assert!(draft.evaluate(&inventory).is_err(), "accepted {path:?}");
    }
}

#[test]
fn excessive_scope_counts_and_invalid_dependency_references_fail() {
    let inventory = inventory(&["a.rs"]);
    let groups = (0..9)
        .map(|i| scope(&format!("scope-{i}"), &["."]))
        .collect();
    assert!(draft(groups).evaluate(&inventory).is_err());
    let mut proposal = draft(vec![scope("a", &["."])]);
    proposal.scopes[0]
        .shared_dependencies
        .push("missing".into());
    assert!(proposal.evaluate(&inventory).is_err());
    proposal.scopes[0].shared_dependencies = vec!["a".into()];
    assert!(proposal.evaluate(&inventory).is_err());
    proposal.scopes[0].shared_dependencies.clear();
    proposal.scopes.push(scope("a", &["."]));
    assert!(proposal.evaluate(&inventory).is_err());
}

#[test]
fn inventory_gaps_and_legacy_unknown_membership_are_honest() {
    let draft = draft(vec![scope("all", &["."])]);
    let mut inventory = inventory(&["a.rs"]);
    inventory.truncation = Some(crate::workspace::InventoryTruncation {
        reason: "entry limit".into(),
    });
    let coverage = draft.evaluate(&inventory).unwrap();
    assert!(!coverage.enumeration_complete);
    assert!(coverage
        .limitations
        .iter()
        .any(|line| line.contains("entry limit")));
    inventory.inspection = None;
    assert!(draft
        .evaluate(&inventory)
        .unwrap_err()
        .to_string()
        .contains("rebuild inventory"));
}

#[test]
fn schema_and_text_limits_reject_unreviewable_drafts() {
    let inventory = inventory(&["a.rs"]);
    let mut draft = draft(vec![scope("all", &["."])]);
    draft.schema_version = 2;
    assert!(draft.evaluate(&inventory).is_err());
    draft.schema_version = 1;
    draft.scopes[0].rationale = "x".repeat(2049);
    assert!(draft.evaluate(&inventory).is_err());
    let mut raw = serde_json::to_value(draft).unwrap();
    raw["recursiveJobs"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ScanScopeDraft>(raw).is_err());
}

fn draft(scopes: Vec<ProposedScanScope>) -> ScanScopeDraft {
    ScanScopeDraft {
        schema_version: 1,
        scopes,
        shared_scope: None,
        shared_discovery: false,
        exclusions: Vec::new(),
    }
}

fn scope(id: &str, paths: &[&str]) -> ProposedScanScope {
    ProposedScanScope {
        id: id.into(),
        name: id.into(),
        paths: paths.iter().map(|p| (*p).into()).collect(),
        rationale: "Coherent component boundary".into(),
        shared_dependencies: Vec::new(),
        open_questions: Vec::new(),
    }
}

fn inventory(paths: &[&str]) -> RepositoryInventory {
    RepositoryInventory {
        root_name: "fixture".into(),
        languages: Vec::new(),
        source_files: Vec::new(),
        manifests: Vec::new(),
        dependency_manifests: Vec::new(),
        config_files: Vec::new(),
        frameworks: Vec::new(),
        entrypoints: Vec::new(),
        routes_controllers: Vec::new(),
        generated_vendor_paths: Vec::new(),
        truncation: None,
        inspection: Some(crate::workspace::InventoryInspection {
            files: paths.iter().map(|p| (*p).into()).collect(),
            enumeration: "fixture".into(),
            entries: paths.len(),
            inspected_bytes: 0,
            max_entries: 100000,
            max_inspected_bytes: 512 * 1024 * 1024,
            max_file_inspection_bytes: 256 * 1024,
            omitted_paths: Vec::new(),
            truncated_files: Vec::new(),
        }),
    }
}

#[test]
fn coverage_previews_are_bounded_while_totals_and_paging_remain_exact() {
    let paths = (0..1000).map(|i| format!("f{i:04}.rs")).collect::<Vec<_>>();
    let inventory = inventory(&paths.iter().map(String::as_str).collect::<Vec<_>>());
    let draft = draft(vec![scope("first", &["."]), scope("second", &["."])]);
    let coverage = draft.evaluate(&inventory).unwrap();
    assert_eq!(coverage.discovery_members["first"].total, 1000);
    assert_eq!(
        coverage.discovery_members["first"].files.len(),
        MAX_COVERAGE_PREVIEW
    );
    assert_eq!(coverage.overlaps.total, 1000);
    assert_eq!(coverage.overlaps.files.len(), MAX_COVERAGE_PREVIEW);
    assert!(serde_json::to_vec(&coverage).unwrap().len() < 64000);
    let page = draft
        .file_page(
            &inventory,
            ScopeFileFilter::Scope {
                scope_id: "first".into(),
            },
            990,
            128,
        )
        .unwrap();
    assert_eq!(page.total, 1000);
    assert_eq!(page.files.len(), 10);
    assert_eq!(page.files[0], "f0990.rs");
    assert_eq!(page.files[9], "f0999.rs");
    assert!(draft
        .file_page(&inventory, ScopeFileFilter::Uncovered, 0, 129)
        .is_err());
}

#[test]
fn file_paging_uses_the_same_exclusion_overlap_and_uncovered_rules() {
    let mut draft = draft(vec![scope("all", &["."]), scope("app", &["app"])]);
    draft.exclusions = vec![ScanScopeExclusion {
        path: "app/excluded.rs".into(),
        reason: "Operator exclusion".into(),
    }];
    let inventory = inventory(&["app/a.rs", "app/excluded.rs", "loose.rs"]);
    let page = |filter| draft.file_page(&inventory, filter, 0, 128).unwrap().files;
    assert_eq!(page(ScopeFileFilter::Overlap), vec!["app/a.rs"]);
    assert_eq!(
        page(ScopeFileFilter::ConflictingExclusion),
        vec!["app/excluded.rs"]
    );
    assert_eq!(page(ScopeFileFilter::Excluded), vec!["app/excluded.rs"]);
    assert!(page(ScopeFileFilter::Uncovered).is_empty());
    assert!(draft
        .file_page(
            &inventory,
            ScopeFileFilter::Scope {
                scope_id: "missing".into()
            },
            0,
            128
        )
        .is_err());
}

#[test]
fn accepting_coverage_requires_explicit_review_and_never_waives_uncovered_files() {
    let mut draft = draft(vec![scope("app", &["app"]), scope("also-app", &["app"])]);
    let mut inventory = inventory(&["app/a.rs", "loose.rs"]);
    inventory.truncation = Some(crate::workspace::InventoryTruncation {
        reason: "entry limit".into(),
    });
    let all = ScopeCoverageApproval {
        inventory_limitations: true,
        overlapping_discovery: true,
        exclusions: true,
    };
    let coverage = draft.evaluate(&inventory).unwrap();
    assert!(coverage
        .ensure_acceptable(&all)
        .unwrap_err()
        .to_string()
        .contains("residual scope"));
    draft.exclusions = vec![ScanScopeExclusion {
        path: "loose.rs".into(),
        reason: "Operator excluded the loose file".into(),
    }];
    let coverage = draft.evaluate(&inventory).unwrap();
    assert!(coverage
        .ensure_acceptable(&ScopeCoverageApproval::default())
        .is_err());
    for missing in [
        ScopeCoverageApproval {
            inventory_limitations: false,
            ..all.clone()
        },
        ScopeCoverageApproval {
            overlapping_discovery: false,
            ..all.clone()
        },
        ScopeCoverageApproval {
            exclusions: false,
            ..all.clone()
        },
    ] {
        assert!(coverage.ensure_acceptable(&missing).is_err());
    }
    coverage.ensure_acceptable(&all).unwrap();
}

#[test]
fn whole_repository_stays_available_for_an_empty_inventory_without_claiming_work() {
    let draft = draft(vec![scope("repository", &["."])]);
    let coverage = draft.evaluate(&inventory(&[])).unwrap();
    assert_eq!(coverage.enumerated_files, 0);
    assert!(coverage.discovery_members.is_empty());
    coverage
        .ensure_acceptable(&ScopeCoverageApproval::default())
        .unwrap();
}
