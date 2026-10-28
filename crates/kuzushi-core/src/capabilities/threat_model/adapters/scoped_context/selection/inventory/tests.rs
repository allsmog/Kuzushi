use super::*;
use crate::workspace::inventory::build_repository_inventory_with_limits;

fn inventory(limit: usize) -> RepositoryInventory {
    let root = tempfile::tempdir().unwrap();
    for name in ["a.rs", "b.rs", "c.rs"] {
        std::fs::write(root.path().join(name), "// Owned inert source\n").unwrap();
    }
    build_repository_inventory_with_limits(root.path(), limit, 1024, &mut |_| {}, &|| false)
        .unwrap()
}

#[test]
fn partial_inventory_accepts_known_members_and_discloses_its_extent() {
    let inventory = inventory(2);
    let known = inventory.inspection.as_ref().unwrap().files[0].clone();
    let result = selected_membership(&[known], &inventory).unwrap();
    assert_eq!(result["selectedMembershipKnown"], true);
    assert_eq!(result["enumerationComplete"], false);
    assert_eq!(result["enumeratedFiles"], 2);
    assert_eq!(result["maxEntries"], 2);
    assert!(result["truncation"]["reason"]
        .as_str()
        .unwrap()
        .contains("entry cap"));
    assert_eq!(result["completeRepositoryCoverage"], false);
}

#[test]
fn partial_inventory_never_assumes_an_unenumerated_file_is_a_member() {
    let inventory = inventory(2);
    let files = &inventory.inspection.as_ref().unwrap().files;
    let omitted = ["a.rs", "b.rs", "c.rs"]
        .into_iter()
        .find(|name| !files.iter().any(|path| path == *name))
        .expect("the two-entry limit must omit one owned fixture file");
    let error = selected_membership(&[omitted.into()], &inventory)
        .unwrap_err()
        .to_string();
    assert!(error.contains("absent from the bounded inventory"));
    assert!(error.contains(&format!("{omitted:?}")));
}

#[test]
fn complete_enumeration_still_has_selected_file_coverage_only() {
    let inventory = inventory(10);
    let result = selected_membership(&["a.rs".into()], &inventory).unwrap();
    assert_eq!(result["enumerationComplete"], true);
    assert_eq!(result["enumeratedFiles"], 3);
    assert_eq!(result["completeRepositoryCoverage"], false);
}

#[test]
fn unknown_inventory_extent_requires_a_fresh_authenticated_inventory() {
    let mut inventory = inventory(10);
    inventory.inspection.as_mut().unwrap().enumeration_complete = None;
    assert!(selected_membership(&["a.rs".into()], &inventory).is_err());
    inventory.inspection = None;
    assert!(selected_membership(&["a.rs".into()], &inventory).is_err());
}

#[test]
fn inventory_receipt_bounds_path_details_without_hiding_their_counts() {
    let mut inventory = inventory(10);
    let inspection = inventory.inspection.as_mut().unwrap();
    inspection.truncated_files = (0..100).map(|i| format!("large-{i}.rs")).collect();
    let result = selected_membership(&["a.rs".into()], &inventory).unwrap();
    assert_eq!(result["truncatedFileCount"], 100);
    assert_eq!(result["truncatedFiles"].as_array().unwrap().len(), 16);
    assert_eq!(result["additionalTruncatedFiles"], 84);
}
