use super::*;

#[test]
fn complete_enumeration_with_content_prefixes_still_requires_inventory_acknowledgement() {
    let mut inventory = inventory(&["large.rs"]);
    inventory.inspection.as_mut().unwrap().truncated_files = vec!["large.rs".into()];
    inventory.truncation = Some(crate::workspace::InventoryTruncation {
        reason: "per-file content prefix".into(),
    });
    let coverage = draft(vec![scope("all", &["."])])
        .evaluate(&inventory)
        .unwrap();
    assert!(coverage.enumeration_complete);
    assert!(coverage.inventory_limited);
    assert!(coverage
        .ensure_acceptable(&ScopeCoverageApproval::default())
        .is_err());
    assert!(coverage
        .ensure_acceptable(&ScopeCoverageApproval {
            inventory_limitations: true,
            ..Default::default()
        })
        .is_ok());
}

#[test]
fn stopped_or_unrecorded_enumeration_is_limited_even_without_an_old_truncation_marker() {
    for recorded in [Some(false), None] {
        let mut inventory = inventory(&["root.rs"]);
        inventory.inspection.as_mut().unwrap().enumeration_complete = recorded;
        let coverage = draft(vec![scope("all", &["."])])
            .evaluate(&inventory)
            .unwrap();
        assert!(!coverage.enumeration_complete);
        assert!(coverage.inventory_limited);
        assert!(coverage
            .ensure_acceptable(&ScopeCoverageApproval::default())
            .is_err());
        if recorded.is_none() {
            assert!(coverage
                .limitations
                .iter()
                .any(|line| line.contains("not recorded")));
        }
    }
}

#[test]
fn known_complete_unlimited_inventory_needs_no_partial_acknowledgement() {
    let coverage = draft(vec![scope("all", &["."])])
        .evaluate(&inventory(&["root.rs"]))
        .unwrap();
    assert!(coverage.enumeration_complete);
    assert!(!coverage.inventory_limited);
    assert!(coverage
        .ensure_acceptable(&ScopeCoverageApproval::default())
        .is_ok());
}
