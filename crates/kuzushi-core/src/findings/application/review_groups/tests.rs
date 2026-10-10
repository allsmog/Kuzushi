use super::*;
use crate::findings::{FindingRelationshipKind, FindingRelationshipState, FindingStore, Severity};

mod run_selection;

fn fixture() -> (
    tempfile::TempDir,
    crate::WorkspaceTarget,
    FindingStore,
    Vec<Finding>,
) {
    let root = tempfile::tempdir().unwrap();
    let workspace = crate::WorkspaceTarget::new(root.path()).unwrap();
    let store = FindingStore::open(workspace.findings_db_path()).unwrap();
    store
        .record_run_started("owned", root.path(), "completed")
        .unwrap();
    for rule in ["a", "b", "c", "d"] {
        store
            .insert_finding(
                "owned",
                &Finding::new_tool(
                    "owned-fixture",
                    rule,
                    "hello.txt",
                    1,
                    None,
                    Severity::Info,
                    "Labeled group observation",
                ),
            )
            .unwrap();
    }
    let rows = store.list_all_findings().unwrap();
    (root, workspace, store, rows)
}

fn accept(
    store: &FindingStore,
    rows: &[Finding],
    from: usize,
    to: usize,
    kind: FindingRelationshipKind,
) -> FindingRelationship {
    let proposal = store
        .propose_finding_relationship(
            rows[from].id.unwrap(),
            rows[to].id.unwrap(),
            kind,
            "Labeled relationship",
            None,
        )
        .unwrap();
    store
        .review_finding_relationship(
            &proposal.id,
            FindingRelationshipState::Accepted,
            "Reviewed exact recorded observations",
            1,
        )
        .unwrap()
}

#[test]
fn accepted_cycles_form_one_group_without_collapsing_variants_or_changing_findings() {
    let (_root, workspace, store, rows) = fixture();
    for (a, b) in [(0, 1), (1, 2), (2, 0)] {
        accept(&store, &rows, a, b, FindingRelationshipKind::Duplicate);
    }
    accept(&store, &rows, 2, 3, FindingRelationshipKind::RelatedVariant);
    accept(&store, &rows, 0, 3, FindingRelationshipKind::Uncertain);
    let page =
        read_finding_groups(&store, &workspace, &FindingGroupsRequest::first_page()).unwrap();
    assert_eq!((page.total_findings, page.total_groups), (4, 2));
    assert_eq!(page.diagnostics.related_variant_links, 1);
    assert_eq!(page.diagnostics.uncertain_links, 1);
    assert_eq!(store.list_all_findings().unwrap(), rows);
    assert!(store.list_all_review_decisions().unwrap().is_empty());
}

#[test]
fn complete_components_are_built_before_group_and_member_paging() {
    let (_root, workspace, store, rows) = fixture();
    accept(&store, &rows, 0, 3, FindingRelationshipKind::Duplicate);
    let first = read_finding_groups(
        &store,
        &workspace,
        &FindingGroupsRequest {
            limit: 1,
            ..FindingGroupsRequest::first_page()
        },
    )
    .unwrap();
    assert_eq!((first.total_findings, first.total_groups), (4, 3));
    assert!(first.has_more);
    let groups =
        read_finding_groups(&store, &workspace, &FindingGroupsRequest::first_page()).unwrap();
    let group = groups
        .groups
        .iter()
        .find(|group| group.member_count == 2)
        .unwrap();
    let request = FindingGroupsRequest {
        group_id: Some(group.id.clone()),
        expected_revision: Some(groups.revision.clone()),
        limit: 1,
        ..FindingGroupsRequest::first_page()
    };
    let one = read_finding_groups(&store, &workspace, &request).unwrap();
    let two = read_finding_groups(
        &store,
        &workspace,
        &FindingGroupsRequest {
            offset: 1,
            ..request
        },
    )
    .unwrap();
    assert_eq!(one.total_members, 2);
    assert!(one.has_more);
    assert!(!two.has_more);
    assert_ne!(one.members[0].finding_id, two.members[0].finding_id);
}

#[test]
fn undo_and_new_observations_invalidate_group_pages_without_forging_resolution() {
    let (root, workspace, store, rows) = fixture();
    let relation = accept(&store, &rows, 0, 1, FindingRelationshipKind::Duplicate);
    let before =
        read_finding_groups(&store, &workspace, &FindingGroupsRequest::first_page()).unwrap();
    store
        .review_finding_relationship(
            &relation.id,
            FindingRelationshipState::Removed,
            "Keep separate",
            2,
        )
        .unwrap();
    assert!(read_finding_groups(
        &store,
        &workspace,
        &FindingGroupsRequest {
            expected_revision: Some(before.revision.clone()),
            ..FindingGroupsRequest::first_page()
        }
    )
    .is_err());
    assert_eq!(
        read_finding_groups(&store, &workspace, &FindingGroupsRequest::first_page())
            .unwrap()
            .total_groups,
        4
    );
    accept(&store, &rows, 1, 2, FindingRelationshipKind::Duplicate);
    store
        .record_run_started("later", root.path(), "completed")
        .unwrap();
    store.insert_finding("later", &rows[1]).unwrap();
    let after =
        read_finding_groups(&store, &workspace, &FindingGroupsRequest::first_page()).unwrap();
    assert_eq!(after.total_groups, 4);
    assert_eq!(after.diagnostics.inactive_duplicate_links, 1);
    assert!(store.list_all_review_decisions().unwrap().is_empty());
}

#[test]
fn grouping_cancels_honestly_and_refuses_missing_member_watermarks() {
    let (_root, workspace, store, _) = fixture();
    assert!(read_finding_groups_cancellable(
        &store,
        &workspace,
        &FindingGroupsRequest::first_page(),
        || anyhow::bail!("Canceled")
    )
    .is_err());
    assert!(read_finding_groups(
        &store,
        &workspace,
        &FindingGroupsRequest {
            group_id: Some("unknown".into()),
            ..FindingGroupsRequest::first_page()
        }
    )
    .is_err());
}

#[test]
fn group_content_revisions_ignore_read_receipts_but_bind_the_target() {
    let (root, workspace, store, _) = fixture();
    let first =
        read_finding_groups(&store, &workspace, &FindingGroupsRequest::first_page()).unwrap();
    store
        .record_run_started("read-receipt", root.path(), "completed")
        .unwrap();
    let request = FindingGroupsRequest {
        expected_revision: Some(first.revision.clone()),
        ..FindingGroupsRequest::first_page()
    };
    let next = read_finding_groups(&store, &workspace, &request).unwrap();
    assert_eq!(first.revision, next.revision);
    assert_ne!(first.ledger_watermark, next.ledger_watermark);
    let other = tempfile::tempdir().unwrap();
    let other = crate::WorkspaceTarget::new(other.path()).unwrap();
    assert!(read_finding_groups(&store, &other, &request).is_err());
}

#[test]
fn deep_duplicate_components_are_iterative_and_keep_all_members() {
    let mut rows = Vec::new();
    for index in 0..6000 {
        let mut finding = Finding::new_tool(
            "owned-fixture",
            &format!("labeled-{index}"),
            "hello.txt",
            1,
            None,
            Severity::Info,
            "Labeled observation",
        );
        finding.id = Some(index + 1);
        finding.scan_id = Some("owned".into());
        rows.push(finding);
    }
    let relations = rows
        .windows(2)
        .map(|pair| {
            FindingRelationship::new(
                recorded_endpoint(&pair[0]).unwrap(),
                recorded_endpoint(&pair[1]).unwrap(),
                FindingRelationshipKind::Duplicate,
                "Labeled accepted grouping".into(),
                "model".into(),
            )
            .unwrap()
            .review(
                FindingRelationshipState::Accepted,
                "Reviewed fixture pair".into(),
                1,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let (groups, _) = graph::components(&rows, &relations).unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].len(), 6000);
}

#[test]
fn generation_references_open_the_recorded_observation_instead_of_rebinding_to_new_source() {
    let (root, _workspace, store, rows) = fixture();
    let old_id = rows[0].id.unwrap();
    store
        .record_run_started("later", root.path(), "completed")
        .unwrap();
    let current_id = store.insert_finding("later", &rows[0]).unwrap();
    assert_ne!(current_id, old_id);
    let old = store
        .get_finding_by_reference(&format!("generation:{old_id}"))
        .unwrap()
        .unwrap();
    let current = store
        .get_finding_by_reference(&format!("generation:{current_id}"))
        .unwrap()
        .unwrap();
    assert_eq!(old.id, Some(old_id));
    assert_eq!(old.scan_id.as_deref(), Some("owned"));
    assert_eq!(current.scan_id.as_deref(), Some("later"));
    assert!(store.get_finding_by_reference("generation:-1").is_err());
    assert!(store
        .get_finding_by_reference("generation:invalid")
        .is_err());
}
