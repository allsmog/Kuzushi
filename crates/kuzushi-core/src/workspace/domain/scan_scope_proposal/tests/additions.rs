use super::*;

#[test]
fn adding_primary_membership_covers_a_gap_without_changing_shared_context() {
    let mut original = draft(vec![scope("app", &["app"])]);
    original.shared_scope = Some(scope("common", &["lib"]));
    let inventory = inventory(&["app/main.rs", "lib/shared.rs", "root.rs"]);
    let (edited, coverage) = original
        .edited(
            ScanScopeEdit::AddScope {
                scope: scope("integration", &["lib", "root.rs"]),
            },
            &inventory,
        )
        .unwrap();
    assert_eq!(edited.scopes[0], original.scopes[0]);
    assert_eq!(edited.shared_scope, original.shared_scope);
    assert!(!edited.shared_discovery);
    assert_eq!(coverage.uncovered_files.total, 0);
    assert_eq!(coverage.overlaps.total, 0);
    assert_eq!(
        coverage.context_members["common"].files,
        vec!["lib/shared.rs"]
    );
    assert_eq!(coverage.discovery_members["integration"].total, 2);
    assert_eq!(original.scopes.len(), 1);
}

#[test]
fn invalid_new_scopes_and_a_ninth_primary_leave_the_original_intact() {
    let inventory = inventory(&["app/main.rs"]);
    let original = draft(vec![scope("app", &["app"])]);
    for candidate in [
        scope("app", &["app"]),
        scope("new", &["../outside"]),
        scope("new", &["missing"]),
    ] {
        assert!(original
            .edited(ScanScopeEdit::AddScope { scope: candidate }, &inventory)
            .is_err());
        assert_eq!(original.scopes.len(), 1);
    }
    let full = draft(
        (0..8)
            .map(|id| scope(&format!("scope-{id}"), &["app"]))
            .collect(),
    );
    assert!(full
        .edited(
            ScanScopeEdit::AddScope {
                scope: scope("ninth", &["app"])
            },
            &inventory
        )
        .is_err());
    assert_eq!(full.scopes.len(), 8);
}

#[test]
fn added_overlap_is_reported_and_cannot_be_accepted_without_acknowledgement() {
    let original = draft(vec![scope("app", &["app"])]);
    let (_, coverage) = original
        .edited(
            ScanScopeEdit::AddScope {
                scope: scope("integration", &["."]),
            },
            &inventory(&["app/main.rs", "root.rs"]),
        )
        .unwrap();
    assert_eq!(coverage.overlaps.total, 1);
    assert!(coverage
        .ensure_acceptable(&ScopeCoverageApproval::default())
        .is_err());
}
