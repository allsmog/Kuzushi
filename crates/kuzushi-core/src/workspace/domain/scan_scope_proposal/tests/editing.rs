use super::*;

#[test]
fn rename_changes_the_label_and_preserves_identity_and_membership() {
    let draft = draft(vec![scope("app", &["app"])]);
    let inventory = inventory(&["app/a.rs"]);
    let before = draft.evaluate(&inventory).unwrap();
    let (edited, after) = draft
        .edited(
            ScanScopeEdit::Rename {
                scope_id: "app".into(),
                name: "Payments".into(),
            },
            &inventory,
        )
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(edited.scopes[0].id, "app");
    assert_eq!(edited.scopes[0].name, "Payments");
    assert_eq!(draft.scopes[0].name, "app");
}

#[test]
fn merge_preserves_membership_and_rewrites_dependency_references() {
    let mut library = scope("library", &["lib"]);
    library.name = "Shared library".into();
    let mut service = scope("service", &["service"]);
    service.shared_dependencies = vec!["library".into()];
    let mut client = scope("client", &["client"]);
    client.shared_dependencies = vec!["library".into()];
    let draft = draft(vec![library, service, client]);
    let inventory = inventory(&["lib/a.rs", "service/b.rs", "client/c.rs"]);
    let (edited, coverage) = draft
        .edited(
            ScanScopeEdit::Merge {
                from_scope: "library".into(),
                into_scope: "service".into(),
            },
            &inventory,
        )
        .unwrap();
    assert_eq!(draft.scopes.len(), 3);
    assert_eq!(edited.scopes.len(), 2);
    assert_eq!(edited.scopes[0].paths, vec!["lib", "service"]);
    assert!(edited.scopes[0].shared_dependencies.is_empty());
    assert_eq!(edited.scopes[1].shared_dependencies, vec!["service"]);
    assert!(edited.scopes[0].rationale.contains("Shared library"));
    assert!(coverage.uncovered_files.files.is_empty());
}

#[test]
fn split_keeps_loose_files_and_rewrites_parent_dependencies() {
    let mut tooling = scope("tooling", &["tooling"]);
    tooling.shared_dependencies = vec!["app".into()];
    let draft = draft(vec![scope("app", &["app"]), tooling]);
    let inventory = inventory(&[
        "app/auth/a.rs",
        "app/billing/b.rs",
        "app/loose.rs",
        "tooling/c.rs",
    ]);
    let children = vec![
        scope("auth", &["app/auth"]),
        scope("billing", &["app/billing"]),
        scope("shared", &["app/loose.rs"]),
    ];
    let (edited, coverage) = draft
        .edited(
            ScanScopeEdit::Split {
                scope_id: "app".into(),
                children,
            },
            &inventory,
        )
        .unwrap();
    assert_eq!(
        edited.scopes[3].shared_dependencies,
        vec!["auth", "billing", "shared"]
    );
    assert!(coverage.uncovered_files.files.is_empty());
    assert!(coverage.overlaps.total == 0);
    assert_eq!(draft.scopes.len(), 2);
}

#[test]
fn invalid_split_cannot_drop_parent_files_or_add_outside_members() {
    let draft = draft(vec![scope("app", &["app"])]);
    let inventory = inventory(&["app/a.rs", "app/loose.rs", "outside.rs"]);
    for children in [
        vec![scope("a", &["app/a.rs"]), scope("outside", &["outside.rs"])],
        vec![scope("a", &["app/a.rs"]), scope("also-a", &["app/a.rs"])],
    ] {
        assert!(draft
            .edited(
                ScanScopeEdit::Split {
                    scope_id: "app".into(),
                    children
                },
                &inventory
            )
            .is_err());
        assert_eq!(draft.scopes[0].paths, vec!["app"]);
    }
}

#[test]
fn repeated_explicit_splits_still_cannot_exceed_the_scope_cap() {
    let paths = (0..16).map(|i| format!("f{i}.rs")).collect::<Vec<_>>();
    let inventory = inventory(&paths.iter().map(String::as_str).collect::<Vec<_>>());
    let half = |id: &str, range: std::ops::Range<usize>| {
        scope(id, &range.map(|i| paths[i].as_str()).collect::<Vec<_>>())
    };
    let initial = draft(vec![scope("all", &["."])]);
    let (draft, _) = initial
        .edited(
            ScanScopeEdit::Split {
                scope_id: "all".into(),
                children: vec![half("first", 0..8), half("second", 8..16)],
            },
            &inventory,
        )
        .unwrap();
    let children = (0..8)
        .map(|i| scope(&format!("file-{i}"), &[paths[i].as_str()]))
        .collect();
    assert!(draft
        .edited(
            ScanScopeEdit::Split {
                scope_id: "first".into(),
                children
            },
            &inventory
        )
        .is_err());
    assert_eq!(draft.scopes.len(), 2);
}

#[test]
fn whole_repository_preserves_explicit_exclusions_and_their_reasons() {
    let initial = draft(vec![scope("app", &["app"])]);
    let inventory = inventory(&["app/a.rs", "loose.rs"]);
    let (excluded, coverage) = initial
        .edited(
            ScanScopeEdit::Exclude {
                scope_id: "app".into(),
                reason: "Operator excluded this component".into(),
            },
            &inventory,
        )
        .unwrap();
    assert_eq!(coverage.excluded_files.files, vec!["app/a.rs"]);
    assert_eq!(coverage.uncovered_files.files, vec!["loose.rs"]);
    assert!(initial.exclusions.is_empty());
    let (whole, coverage) = excluded
        .edited(ScanScopeEdit::WholeRepository, &inventory)
        .unwrap();
    assert_eq!(whole.scopes.len(), 1);
    assert_eq!(whole.exclusions, excluded.exclusions);
    assert_eq!(coverage.excluded_files.files, vec!["app/a.rs"]);
    assert!(coverage.uncovered_files.files.is_empty());
    assert_eq!(
        coverage.discovery_members["repository"].files,
        vec!["loose.rs"]
    );
}

#[test]
fn invalid_metadata_edit_does_not_mutate_the_existing_draft() {
    let draft = draft(vec![scope("app", &["."])]);
    let inventory = inventory(&["a.rs"]);
    assert!(draft
        .edited(
            ScanScopeEdit::Rename {
                scope_id: "app".into(),
                name: "".into()
            },
            &inventory
        )
        .is_err());
    assert_eq!(draft.scopes[0].name, "app");
    assert!(draft
        .edited(
            ScanScopeEdit::SetSharedDiscovery { enabled: true },
            &inventory
        )
        .is_err());
    assert!(!draft.shared_discovery);
}

#[test]
fn explicit_inclusion_removes_one_rule_and_keeps_other_exclusions() {
    let mut original = draft(vec![scope("repository", &["."])]);
    original.exclusions = vec![
        ScanScopeExclusion {
            path: "app".into(),
            reason: "Defer component".into(),
        },
        ScanScopeExclusion {
            path: "app/a.rs".into(),
            reason: "Retain specific omission".into(),
        },
    ];
    let inventory = inventory(&["app/a.rs", "app/b.rs", "README.md"]);
    let (included, coverage) = original
        .edited(
            ScanScopeEdit::IncludePath { path: "app".into() },
            &inventory,
        )
        .unwrap();
    assert_eq!(original.exclusions.len(), 2);
    assert_eq!(included.exclusions, vec![original.exclusions[1].clone()]);
    assert_eq!(coverage.excluded_files.files, vec!["app/a.rs"]);
    assert_eq!(
        coverage.discovery_members["repository"].files,
        vec!["README.md", "app/b.rs"]
    );
    assert!(coverage
        .ensure_acceptable(&ScopeCoverageApproval::default())
        .is_err());
    assert!(original
        .edited(
            ScanScopeEdit::IncludePath {
                path: "unknown".into()
            },
            &inventory
        )
        .is_err());
    assert_eq!(original.exclusions.len(), 2);
}

#[test]
fn single_path_exclusion_keeps_other_members_and_rejects_unknown_or_escaping_paths() {
    let inventory = inventory(&["app/a.rs", "app/b.rs", "README.md"]);
    let original = draft(vec![scope("root", &["."])]);
    let (edited, coverage) = original
        .edited(
            ScanScopeEdit::ExcludePath {
                path: "app/a.rs".into(),
                reason: "Operator excluded one file".into(),
            },
            &inventory,
        )
        .unwrap();
    assert_eq!(coverage.excluded_files.files, vec!["app/a.rs"]);
    assert_eq!(coverage.discovery_members["root"].total, 2);
    assert!(coverage
        .ensure_acceptable(&ScopeCoverageApproval::default())
        .is_err());
    for path in ["missing.rs", "../app/a.rs", "/app/a.rs"] {
        assert!(edited
            .edited(
                ScanScopeEdit::ExcludePath {
                    path: path.into(),
                    reason: "invalid boundary".into()
                },
                &inventory
            )
            .is_err());
    }
    assert!(original.exclusions.is_empty());
}
