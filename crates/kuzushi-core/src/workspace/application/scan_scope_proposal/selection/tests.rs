use super::*;

fn scope(id: &str, paths: &[&str]) -> ProposedScanScope {
    ProposedScanScope {
        id: id.into(),
        name: id.into(),
        paths: paths.iter().map(|path| path.to_string()).collect(),
        rationale: "Operator-selected boundary".into(),
        shared_dependencies: Vec::new(),
        open_questions: Vec::new(),
    }
}

fn fixture() -> (tempfile::TempDir, WorkspaceTarget, crate::V2Config) {
    let root = tempfile::tempdir().unwrap();
    for directory in ["app/[route]", "shared"] {
        std::fs::create_dir_all(root.path().join(directory)).unwrap();
    }
    for file in [
        "app/[route]/reader.rs",
        "app/excluded.rs",
        "shared/context.rs",
        "README.md",
    ] {
        std::fs::write(root.path().join(file), "pub fn source() {}\n").unwrap();
    }
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    (root, workspace, crate::V2Config::default())
}

fn ctx<'a>(
    workspace: &'a WorkspaceTarget,
    config: &'a crate::V2Config,
) -> ToolExecutionContext<'a> {
    ToolExecutionContext {
        config,
        workspace: Some(workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    }
}

#[test]
fn edited_shared_context_copy_is_inherited_but_cannot_be_selected_for_discovery() {
    let (_root, workspace, config) = fixture();
    let context = ctx(&workspace, &config);
    let initial = create_scan_scope_proposal(
        &context,
        Some(ScanScopeDraft {
            schema_version: 1,
            scopes: vec![
                scope("app", &["app"]),
                scope("common-source", &["shared"]),
                scope("docs", &["README.md"]),
            ],
            shared_scope: None,
            shared_discovery: false,
            exclusions: vec![],
        }),
    )
    .unwrap();
    let edited = edit_scan_scope_proposal(
        &context,
        &initial.reference,
        ScanScopeEdit::CreateSharedContext {
            scope_id: "common-source".into(),
            shared_scope_id: "common-context".into(),
        },
    )
    .unwrap();
    let accepted = accept_scan_scope_proposal(
        &context,
        &edited.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        },
    )
    .unwrap();
    let reference = ScanScopeRef {
        proposal: accepted.reference.clone(),
        scope_id: "app".into(),
    };
    let selected = resolve_accepted_scan_scope_selection(&context, &reference).unwrap();
    assert_eq!(
        selected.discovery_files,
        vec!["app/[route]/reader.rs", "app/excluded.rs"]
    );
    assert_eq!(selected.context_files, vec!["shared/context.rs"]);
    let context_only = ScanScopeRef {
        scope_id: "common-context".into(),
        ..reference
    };
    assert!(resolve_accepted_scan_scope_selection(&context, &context_only).is_err());
    assert!(load_scan_scope_proposal(&workspace, &initial.reference)
        .unwrap()
        .record
        .draft
        .shared_scope
        .is_none());
    assert!(!workspace.state_dir().join("campaigns").exists());
}

#[test]
fn exact_membership_preserves_literal_files_exclusions_and_shared_context_without_recursion() {
    let (_root, workspace, config) = fixture();
    let draft = ScanScopeDraft {
        schema_version: 1,
        scopes: vec![
            scope("app", &["app"]),
            scope("docs", &["README.md"]),
            scope("integration", &["shared"]),
        ],
        shared_scope: Some(scope("shared", &["shared"])),
        shared_discovery: false,
        exclusions: vec![ScanScopeExclusion {
            path: "app/excluded.rs".into(),
            reason: "Operator excluded this file".into(),
        }],
    };
    let initial = create_scan_scope_proposal(&ctx(&workspace, &config), Some(draft)).unwrap();
    let accepted = accept_scan_scope_proposal(
        &ctx(&workspace, &config),
        &initial.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            exclusions: true,
            overlapping_discovery: false,
        },
    )
    .unwrap();
    let reference = ScanScopeRef {
        proposal: accepted.reference.clone(),
        scope_id: "app".into(),
    };
    let selected =
        resolve_accepted_scan_scope_selection(&ctx(&workspace, &config), &reference).unwrap();
    assert_eq!(selected.discovery_files, vec!["app/[route]/reader.rs"]);
    assert_eq!(selected.context_files, vec!["shared/context.rs"]);
    let docs = ScanScopeRef {
        scope_id: "docs".into(),
        ..reference.clone()
    };
    assert_eq!(
        resolve_accepted_scan_scope_selection(&ctx(&workspace, &config), &docs)
            .unwrap()
            .discovery_files,
        vec!["README.md"]
    );
    for id in ["shared", "missing"] {
        assert!(resolve_accepted_scan_scope_selection(
            &ctx(&workspace, &config),
            &ScanScopeRef {
                scope_id: id.into(),
                ..reference.clone()
            }
        )
        .is_err());
    }
}

#[test]
fn selection_requires_committed_acceptance_and_current_source() {
    let (root, workspace, config) = fixture();
    let draft = create_scan_scope_proposal(&ctx(&workspace, &config), None).unwrap();
    let mut reference = ScanScopeRef {
        proposal: draft.reference.clone(),
        scope_id: "repository".into(),
    };
    assert!(resolve_accepted_scan_scope_selection(&ctx(&workspace, &config), &reference).is_err());
    reference.proposal = accept_scan_scope_proposal(
        &ctx(&workspace, &config),
        &draft.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        },
    )
    .unwrap()
    .reference;
    let selected =
        resolve_accepted_scan_scope_selection(&ctx(&workspace, &config), &reference).unwrap();
    assert_eq!(selected.discovery_files.len(), 4);
    std::fs::write(root.path().join("README.md"), "source changed\n").unwrap();
    assert!(resolve_accepted_scan_scope_selection(&ctx(&workspace, &config), &reference).is_err());
}

#[test]
fn selected_discovery_reads_beyond_the_coverage_preview_without_inventing_members() {
    let root = tempfile::tempdir().unwrap();
    for index in 0..150 {
        std::fs::write(
            root.path().join(format!("file-{index}.rs")),
            "pub fn source() {}\n",
        )
        .unwrap();
    }
    let workspace = WorkspaceTarget::new(root.path()).unwrap();
    let config = crate::V2Config::default();
    let draft = create_scan_scope_proposal(&ctx(&workspace, &config), None).unwrap();
    assert_eq!(
        draft.coverage.discovery_members["repository"].files.len(),
        128
    );
    let accepted = accept_scan_scope_proposal(
        &ctx(&workspace, &config),
        &draft.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        },
    )
    .unwrap();
    let reference = ScanScopeRef {
        proposal: accepted.reference,
        scope_id: "repository".into(),
    };
    assert_eq!(
        resolve_accepted_scan_scope_selection(&ctx(&workspace, &config), &reference)
            .unwrap()
            .discovery_files
            .len(),
        150
    );
}
