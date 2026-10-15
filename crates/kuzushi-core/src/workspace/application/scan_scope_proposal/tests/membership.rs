use super::*;

fn git(root: &std::path::Path, arguments: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=Owned fixture",
            "-c",
            "user.email=fixture@example.invalid",
        ])
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

fn owned_git() -> (tempfile::TempDir, WorkspaceTarget, crate::V2Config) {
    let (root, workspace, config) = target();
    git(root.path(), &["init", "--quiet", "--initial-branch=main"]);
    git(root.path(), &["add", "root.rs", "app/lib.rs"]);
    let tree = git(root.path(), &["write-tree"]);
    let commit = git(
        root.path(),
        &[
            "commit-tree",
            &tree,
            "-m",
            "fixture: record owned membership",
        ],
    );
    git(root.path(), &["update-ref", "refs/heads/main", &commit]);
    fs::write(
        root.path().join("new.rs"),
        "// Owned source. Never executed.\n",
    )
    .unwrap();
    (root, workspace, config)
}

#[test]
fn staging_existing_untracked_source_changes_inventory_without_changing_content_identity() {
    let (root, workspace, config) = owned_git();
    let ctx = context(&workspace, &config);
    let original = create_scan_scope_proposal(&ctx, None).unwrap();
    assert_eq!(original.coverage.enumerated_files, 2);
    git(root.path(), &["add", "new.rs"]);
    let updated = create_scan_scope_proposal(&ctx, None).unwrap();
    assert_eq!(updated.coverage.enumerated_files, 3);
    assert_eq!(
        updated.record.source.tree_hash,
        original.record.source.tree_hash
    );
    assert_eq!(
        updated.record.source.snapshot_hash,
        original.record.source.snapshot_hash
    );
    assert_eq!(
        updated.record.source.git_revision,
        original.record.source.git_revision
    );
    assert_ne!(
        updated.record.source.enumeration_hash,
        original.record.source.enumeration_hash
    );
    assert_ne!(
        updated.record.inventory_hash,
        original.record.inventory_hash
    );
    assert!(updated.coverage.discovery_members["repository"]
        .files
        .contains(&"new.rs".into()));
}

#[test]
fn changed_membership_refuses_old_acceptance_and_current_use_but_keeps_history() {
    let (root, workspace, config) = owned_git();
    let ctx = context(&workspace, &config);
    let draft = create_scan_scope_proposal(&ctx, None).unwrap();
    let accepted = accept_scan_scope_proposal(&ctx, &draft.reference, Default::default()).unwrap();
    git(root.path(), &["add", "new.rs"]);
    let error =
        accept_scan_scope_proposal(&ctx, &accepted.reference, Default::default()).unwrap_err();
    assert!(
        error.to_string().contains("inventory membership changed"),
        "{error:#}"
    );
    let error = load_accepted_scan_scope_proposal(&ctx, &accepted.reference).unwrap_err();
    assert!(
        error.to_string().contains("inventory membership changed"),
        "{error:#}"
    );
    let history = load_scan_scope_proposal(&workspace, &accepted.reference).unwrap();
    assert_eq!(history, accepted);
    assert!(!workspace.state_dir().join("campaigns").exists());
}

#[test]
fn staging_existing_modified_files_keeps_equivalent_membership_reusable() {
    let (root, workspace, config) = owned_git();
    fs::write(
        root.path().join("root.rs"),
        "// Owned changed bytes. Never executed.\n",
    )
    .unwrap();
    let ctx = context(&workspace, &config);
    let original = create_scan_scope_proposal(&ctx, None).unwrap();
    git(root.path(), &["add", "root.rs"]);
    let updated = create_scan_scope_proposal(&ctx, None).unwrap();
    assert_eq!(updated.record.source, original.record.source);
    assert_eq!(
        updated.record.inventory_hash,
        original.record.inventory_hash
    );
}

#[test]
fn filesystem_membership_receipt_ignores_inspection_bytes_and_preserves_cache_reuse() {
    let (_root, workspace, config) = target();
    let ctx = context(&workspace, &config);
    let original = create_scan_scope_proposal(&ctx, None).unwrap();
    let updated = create_scan_scope_proposal(&ctx, None).unwrap();
    assert_eq!(updated.record.source, original.record.source);
    assert_eq!(
        updated.record.inventory_hash,
        original.record.inventory_hash
    );
    assert!(original.record.source.enumeration_hash.is_some());
    accept_scan_scope_proposal(
        &ctx,
        &updated.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        },
    )
    .unwrap();
}

#[test]
fn legacy_scope_history_remains_readable_while_new_work_requires_membership_binding() {
    let (_root, workspace, config) = owned_git();
    let ctx = context(&workspace, &config);
    let draft = create_scan_scope_proposal(&ctx, None).unwrap();
    let mut record = revision::next(&draft).unwrap();
    record.source.enumeration_hash = None;
    record.acceptance = Some(Default::default());
    let legacy = persistence::save_revision(&workspace, record, draft.coverage.clone()).unwrap();
    let mut queue = load_strategy_queue_unlocked(&workspace).unwrap();
    bind_queue_head(
        revision::current_head(&mut queue, &draft.reference).unwrap(),
        &legacy,
    );
    save_strategy_queue_unlocked(&workspace, &queue).unwrap();
    assert_eq!(
        load_scan_scope_proposal(&workspace, &legacy.reference).unwrap(),
        legacy
    );
    let error = load_accepted_scan_scope_proposal(&ctx, &legacy.reference).unwrap_err();
    assert!(
        error.to_string().contains("predates membership binding"),
        "{error:#}"
    );
    let source_json = serde_json::to_value(&legacy.record.source).unwrap();
    assert!(source_json.get("enumerationHash").is_none());
}

#[test]
fn captured_git_membership_drives_inspection_when_the_live_index_changes() {
    let (root, workspace, config) = owned_git();
    let ctx = context(&workspace, &config);
    let captured = super::super::membership::capture(&ctx).unwrap();
    git(root.path(), &["add", "new.rs"]);
    let inventory = crate::workspace::inventory::build_repository_inventory_from_enumeration(
        root.path(),
        &mut |_| {},
        &|| false,
        captured.enumeration,
        crate::workspace::inventory::MAX_REPOSITORY_INSPECTED_BYTES,
    )
    .unwrap();
    assert_eq!(
        inventory.inspection.unwrap().files,
        ["app/lib.rs", "root.rs"]
    );
}

#[test]
fn valid_cached_objects_cannot_replace_the_authenticated_membership_with_a_subset() {
    let (_root, workspace, config) = owned_git();
    let ctx = context(&workspace, &config);
    let original = create_scan_scope_proposal(&ctx, None).unwrap();
    let mut inventory =
        persistence::load_inventory(&workspace, &original.record.inventory_hash).unwrap();
    inventory.inspection.as_mut().unwrap().files.remove(0);
    let substituted = persistence::save_inventory(&workspace, &inventory).unwrap();
    persistence::cache_inventory_hash(&workspace, &original.record.source, &substituted).unwrap();
    let error = create_scan_scope_proposal(&ctx, None).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match its captured enumeration"),
        "{error:#}"
    );
    assert_eq!(
        load_scan_scope_proposal(&workspace, &original.reference).unwrap(),
        original
    );
}
