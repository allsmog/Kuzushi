use super::*;
use std::fs;
mod additions;
mod membership;

fn context<'a>(
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

fn target() -> (tempfile::TempDir, WorkspaceTarget, crate::V2Config) {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("root.rs"), "fn main() {}\n").unwrap();
    fs::create_dir(dir.path().join("app")).unwrap();
    fs::write(dir.path().join("app/lib.rs"), "pub fn run() {}\n").unwrap();
    let workspace = WorkspaceTarget::new(dir.path()).unwrap();
    (dir, workspace, crate::V2Config::default())
}

#[test]
fn durable_scope_edits_keep_history_and_acceptance_never_starts_work() {
    let (_dir, workspace, config) = target();
    let ctx = context(&workspace, &config);
    let original = create_scan_scope_proposal(&ctx, None).unwrap();
    assert_eq!(original.coverage.enumerated_files, 2);
    assert_eq!(original.coverage.uncovered_files.total, 0);
    assert!(original.record.acceptance.is_none());
    let edited = edit_scan_scope_proposal(
        &ctx,
        &original.reference,
        ScanScopeEdit::Rename {
            scope_id: "repository".into(),
            name: "Application".into(),
        },
    )
    .unwrap();
    assert_eq!(edited.reference.revision, 2);
    assert_eq!(edited.record.previous.as_ref(), Some(&original.reference));
    assert_eq!(
        load_scan_scope_proposal(&workspace, &original.reference).unwrap(),
        original
    );
    assert!(accept_scan_scope_proposal(
        &ctx,
        &original.reference,
        ScopeCoverageApproval::default()
    )
    .unwrap_err()
    .to_string()
    .contains("draft changed"));
    let accepted = accept_scan_scope_proposal(
        &ctx,
        &edited.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(accepted.record.acceptance.is_some());
    let queue = crate::strategy::load_strategy_queue(&workspace).unwrap();
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].status, StrategyProposalStatus::Done);
    assert!(queue[0].tool.is_none());
    assert!(queue[0].next_input.is_none());
    assert_eq!(
        queue[0].scope_proposal_ref.as_ref(),
        Some(&accepted.reference)
    );
    assert!(queue[0].result_run_id.is_none());
    assert!(!workspace.state_dir().join("campaigns").exists());
    let revised =
        edit_scan_scope_proposal(&ctx, &accepted.reference, ScanScopeEdit::WholeRepository)
            .unwrap();
    assert!(revised.record.acceptance.is_none());
    assert_eq!(
        load_accepted_scan_scope_proposal(&ctx, &accepted.reference).unwrap(),
        accepted
    );
    assert!(load_scan_scope_proposal(&workspace, &accepted.reference)
        .unwrap()
        .record
        .acceptance
        .is_some());
}

#[test]
fn source_content_change_keeps_old_evidence_readable_but_refuses_acceptance() {
    let (dir, workspace, config) = target();
    let ctx = context(&workspace, &config);
    let review = create_scan_scope_proposal(&ctx, None).unwrap();
    fs::write(dir.path().join("root.rs"), "fn changed() {}\n").unwrap();
    let error =
        accept_scan_scope_proposal(&ctx, &review.reference, ScopeCoverageApproval::default())
            .unwrap_err();
    assert!(error.to_string().contains("source content changed"));
    assert_eq!(
        load_scan_scope_proposal(&workspace, &review.reference).unwrap(),
        review
    );
    let new = create_scan_scope_proposal(&ctx, None).unwrap();
    assert_ne!(new.record.source.tree_hash, review.record.source.tree_hash);
    assert_ne!(new.reference.proposal_id, review.reference.proposal_id);
}

#[test]
fn inventory_is_reused_and_tampered_saved_membership_fails_closed() {
    let (_dir, workspace, config) = target();
    let ctx = context(&workspace, &config);
    let first = create_scan_scope_proposal(&ctx, None).unwrap();
    let second = create_scan_scope_proposal(&ctx, None).unwrap();
    assert_eq!(first.record.inventory_hash, second.record.inventory_hash);
    assert_eq!(first.record.source, second.record.source);
    let path = workspace
        .state_dir()
        .join("scan-scopes/inventories")
        .join(format!("{}.json", first.record.inventory_hash));
    fs::write(path, "{}").unwrap();
    assert!(load_scan_scope_proposal(&workspace, &first.reference)
        .unwrap_err()
        .to_string()
        .contains("digest"));
    assert!(create_scan_scope_proposal(&ctx, None)
        .unwrap_err()
        .to_string()
        .contains("digest"));
}

#[test]
fn invalid_references_and_missing_objects_do_not_advance_the_queue() {
    let (_dir, workspace, config) = target();
    let ctx = context(&workspace, &config);
    let review = create_scan_scope_proposal(&ctx, None).unwrap();
    let mut wrong = review.reference.clone();
    wrong.record_hash = "../../outside".into();
    assert!(load_scan_scope_proposal(&workspace, &wrong).is_err());
    wrong = review.reference.clone();
    wrong.revision += 1;
    assert!(load_scan_scope_proposal(&workspace, &wrong)
        .unwrap_err()
        .to_string()
        .contains("not committed"));
    let path = workspace
        .state_dir()
        .join("scan-scopes/revisions")
        .join(format!("{}.json", review.reference.record_hash));
    fs::remove_file(path).unwrap();
    assert!(
        accept_scan_scope_proposal(&ctx, &review.reference, ScopeCoverageApproval::default())
            .is_err()
    );
    let queue = crate::strategy::load_strategy_queue(&workspace).unwrap();
    assert_eq!(
        queue[0].scope_proposal_ref.as_ref(),
        Some(&review.reference)
    );
}

#[test]
fn two_reviewers_cannot_overwrite_the_same_revision() {
    let (_dir, workspace, config) = target();
    let review = create_scan_scope_proposal(&context(&workspace, &config), None).unwrap();
    let reference = review.reference;
    let results = std::thread::scope(|scope| {
        let handles = ["First", "Second"].map(|name| {
            let workspace = &workspace;
            let config = &config;
            let reference = &reference;
            scope.spawn(move || {
                edit_scan_scope_proposal(
                    &context(workspace, config),
                    reference,
                    ScanScopeEdit::Rename {
                        scope_id: "repository".into(),
                        name: name.into(),
                    },
                )
            })
        });
        handles.map(|handle| handle.join().unwrap())
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results
        .iter()
        .find_map(|result| result.as_ref().err())
        .unwrap()
        .to_string()
        .contains("draft changed"));
    assert_eq!(
        crate::strategy::load_strategy_queue(&workspace)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn canceled_scope_work_does_not_publish_a_proposal_or_an_accepted_revision() {
    let (_dir, workspace, config) = target();
    let review = create_scan_scope_proposal(&context(&workspace, &config), None).unwrap();
    let cancellation = crate::scan::ScanCancellation::default();
    cancellation.cancel();
    let mut ctx = context(&workspace, &config);
    ctx.cancellation = Some(&cancellation);
    assert!(create_scan_scope_proposal(&ctx, None).is_err());
    assert!(accept_scan_scope_proposal(
        &ctx,
        &review.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        }
    )
    .is_err());
    assert_eq!(
        crate::strategy::load_strategy_queue(&workspace)
            .unwrap()
            .len(),
        1
    );
    assert!(load_scan_scope_proposal(&workspace, &review.reference)
        .unwrap()
        .record
        .acceptance
        .is_none());
}

#[test]
fn new_git_sha_with_identical_files_cannot_accept_the_old_scope_draft() {
    let (dir, workspace, config) = target();
    git(dir.path(), &["init", "--quiet"]);
    git(dir.path(), &["add", "root.rs", "app/lib.rs"]);
    git(dir.path(), &["commit", "--quiet", "-m", "fixture source"]);
    let ctx = context(&workspace, &config);
    let review = create_scan_scope_proposal(&ctx, None).unwrap();
    assert!(review.record.source.git_revision.is_some());
    git(
        dir.path(),
        &[
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "fixture revision",
        ],
    );
    assert_eq!(
        crate::incremental_index::current_workspace_tree_hash(dir.path()).unwrap(),
        review.record.source.tree_hash
    );
    let error = accept_scan_scope_proposal(
        &ctx,
        &review.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("Git revision changed"));
    assert!(load_scan_scope_proposal(&workspace, &review.reference)
        .unwrap()
        .record
        .acceptance
        .is_none());
}

fn git(root: &std::path::Path, args: &[&str]) {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn study_consumers_require_the_current_accepted_revision_and_current_source() {
    let (dir, workspace, config) = target();
    let ctx = context(&workspace, &config);
    let draft = create_scan_scope_proposal(&ctx, None).unwrap();
    assert!(load_accepted_scan_scope_proposal(&ctx, &draft.reference).is_err());
    assert!(crate::strategy::set_strategy_proposal_status(
        &workspace,
        &draft.reference.proposal_id,
        StrategyProposalStatus::Approved
    )
    .is_err());
    let accepted = accept_scan_scope_proposal(
        &ctx,
        &draft.reference,
        ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        load_accepted_scan_scope_proposal(&ctx, &accepted.reference).unwrap(),
        accepted
    );
    assert!(load_accepted_scan_scope_proposal(&ctx, &draft.reference).is_err());
    fs::write(dir.path().join("root.rs"), "fn changed() {}\n").unwrap();
    assert!(load_accepted_scan_scope_proposal(&ctx, &accepted.reference).is_err());
    assert_eq!(
        load_scan_scope_proposal(&workspace, &accepted.reference).unwrap(),
        accepted
    );
}

#[test]
fn failed_queue_publication_keeps_the_old_head_and_orphans_can_be_reused() {
    let (_dir, workspace, config) = target();
    let ctx = context(&workspace, &config);
    let draft = create_scan_scope_proposal(&ctx, None).unwrap();
    let queue_path = crate::strategy::strategy_queue_path(&workspace);
    let backup = workspace.state_dir().join("queue-backup.jsonl");
    let mut record = revision::next(&draft).unwrap();
    record.acceptance = Some(ScopeCoverageApproval {
        inventory_limitations: true,
        ..Default::default()
    });
    let orphan = ScanScopeProposalRef {
        proposal_id: record.proposal_id.clone(),
        revision: record.revision,
        record_hash: blake3::hash(&serde_json::to_vec(&record).unwrap())
            .to_hex()
            .to_string(),
    };
    let failed = update_proposal(&ctx, &draft.reference, |review, _| {
        fs::rename(&queue_path, &backup)?;
        fs::create_dir(&queue_path)?;
        Ok((record.clone(), review.coverage.clone()))
    });
    assert!(failed.is_err());
    fs::remove_dir(&queue_path).unwrap();
    fs::rename(backup, queue_path).unwrap();
    assert!(load_accepted_scan_scope_proposal(&ctx, &orphan)
        .unwrap_err()
        .to_string()
        .contains("not committed"));
    assert_eq!(
        crate::strategy::load_strategy_queue(&workspace).unwrap()[0]
            .scope_proposal_ref
            .as_ref(),
        Some(&draft.reference)
    );
    let next = update_proposal(&ctx, &draft.reference, |review, _| {
        Ok((record.clone(), review.coverage.clone()))
    })
    .unwrap();
    assert_eq!(next.reference.revision, 2);
    assert_eq!(
        load_accepted_scan_scope_proposal(&ctx, &orphan).unwrap(),
        next
    );
    assert_eq!(
        load_scan_scope_proposal(&workspace, &draft.reference).unwrap(),
        draft
    );
}

#[cfg(unix)]
#[test]
fn symlinked_scope_objects_are_rejected_without_reading_outside_the_target() {
    let (_dir, workspace, config) = target();
    let review = create_scan_scope_proposal(&context(&workspace, &config), None).unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let path = workspace
        .state_dir()
        .join("scan-scopes/revisions")
        .join(format!("{}.json", review.reference.record_hash));
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(outside.path(), path).unwrap();
    assert!(load_scan_scope_proposal(&workspace, &review.reference).is_err());
}

#[test]
fn identity_omissions_block_acceptance_until_the_operator_excludes_the_unbound_file() {
    let (dir, workspace, config) = target();
    let huge = fs::File::create(dir.path().join("large.bin")).unwrap();
    huge.set_len(crate::incremental_index::MAX_INDEXED_FILE_BYTES + 1)
        .unwrap();
    let ctx = context(&workspace, &config);
    let draft = create_scan_scope_proposal(&ctx, None).unwrap();
    assert_eq!(draft.identity_omissions.total, 1);
    assert_eq!(draft.identity_omissions.files, vec!["large.bin"]);
    let ack = ScopeCoverageApproval {
        inventory_limitations: true,
        exclusions: true,
        ..Default::default()
    };
    assert!(
        accept_scan_scope_proposal(&ctx, &draft.reference, ack.clone())
            .unwrap_err()
            .to_string()
            .contains("outside content identity coverage")
    );
    let mut excluded = draft.record.draft;
    excluded.exclusions.push(ScanScopeExclusion {
        path: "large.bin".into(),
        reason: "File exceeds content identity limits".into(),
    });
    let revised = create_scan_scope_proposal(&ctx, Some(excluded)).unwrap();
    assert_eq!(revised.identity_omissions.total, 0);
    let accepted = accept_scan_scope_proposal(&ctx, &revised.reference, ack).unwrap();
    assert_eq!(accepted.coverage.excluded_files.total, 1);
    assert_eq!(
        load_accepted_scan_scope_proposal(&ctx, &accepted.reference).unwrap(),
        accepted
    );
}

#[test]
fn modified_content_tree_cannot_forge_membership_in_the_saved_scope_review() {
    let (_dir, workspace, config) = target();
    let review = create_scan_scope_proposal(&context(&workspace, &config), None).unwrap();
    let store = crate::content_store::ContentStore::open(workspace.objects_dir()).unwrap();
    let hash = crate::identity::Blake3Hash::new(review.record.source.tree_hash).unwrap();
    fs::write(store.object_path(&hash), "{\"entries\":[]}").unwrap();
    assert!(load_scan_scope_proposal(&workspace, &review.reference)
        .unwrap_err()
        .to_string()
        .contains("integrity check"));
}

#[test]
fn canceled_scope_lock_waits_preserve_existing_draft_and_acceptance() {
    let (_root, workspace, config) = target();
    let reference = create_scan_scope_proposal(&context(&workspace, &config), None)
        .unwrap()
        .reference;
    let owner = crate::file_lock::ExclusiveFileLock::acquire(
        &workspace.state_dir().join(".strategy-ledger.lock"),
    )
    .unwrap();
    let checks = std::cell::Cell::new(0);
    let error = load_scan_scope_proposal_cancellable(&workspace, &reference, &|| {
        checks.set(checks.get() + 1);
        checks.get() >= 4
    })
    .unwrap_err();
    assert!(error.to_string().contains("canceled"));
    assert_eq!(checks.get(), 4);
    drop(owner);
    let review = load_scan_scope_proposal(&workspace, &reference).unwrap();
    assert_eq!(review.reference, reference);
    assert!(review.record.acceptance.is_none());
}

#[test]
fn canceled_inventory_lock_wait_publishes_no_proposal_or_source_identity() {
    let (_root, workspace, config) = target();
    workspace.ensure_state_dir().unwrap();
    let owner = crate::file_lock::ExclusiveFileLock::acquire(
        &workspace.state_dir().join(".scope-inventory.lock"),
    )
    .unwrap();
    let cancellation = crate::scan::ScanCancellation::default();
    let signal = cancellation.clone();
    let releaser = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(30));
        signal.cancel();
        std::thread::sleep(std::time::Duration::from_millis(400));
        drop(owner);
    });
    let mut ctx = context(&workspace, &config);
    ctx.cancellation = Some(&cancellation);
    let started = std::time::Instant::now();
    let error = create_scan_scope_proposal(&ctx, None).unwrap_err();
    assert!(error.to_string().contains("canceled"));
    assert!(started.elapsed() < std::time::Duration::from_millis(300));
    releaser.join().unwrap();
    assert!(crate::strategy::load_strategy_queue(&workspace)
        .unwrap()
        .is_empty());
    assert!(!workspace.findings_db_path().exists());
}

#[test]
fn latest_scope_reader_is_empty_without_inventing_work_and_preserves_accepted_history() {
    let (_root, workspace, config) = target();
    let ctx = context(&workspace, &config);
    assert!(load_latest_scan_scope_proposal(&ctx).unwrap().is_none());
    let first = create_scan_scope_proposal(&ctx, None).unwrap();
    assert_eq!(
        load_latest_scan_scope_proposal(&ctx)
            .unwrap()
            .unwrap()
            .reference,
        first.reference
    );
    let second = edit_scan_scope_proposal(
        &ctx,
        &first.reference,
        ScanScopeEdit::Rename {
            scope_id: "repository".into(),
            name: "Renamed".into(),
        },
    )
    .unwrap();
    assert_eq!(
        load_latest_scan_scope_proposal(&ctx)
            .unwrap()
            .unwrap()
            .reference,
        second.reference
    );
    assert_eq!(
        load_scan_scope_proposal(&workspace, &first.reference)
            .unwrap()
            .reference,
        first.reference
    );
}
