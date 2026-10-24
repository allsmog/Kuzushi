use super::*;

fn bundle() -> (tempfile::TempDir, ThreatModelSourceBundle) {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("owned.rs"), "// Owned static source text.").unwrap();
    let inventory = crate::repository_inventory::build_repository_inventory(root.path()).unwrap();
    let inventory = PromptRepositoryInventory::from_inventory(inventory, 40).unwrap();
    (
        root,
        ThreatModelSourceBundle {
            records: Vec::new(),
            inventory: Some(inventory),
        },
    )
}

#[test]
fn recorded_inventory_replaces_model_receipt_and_preserves_other_coverage() {
    let (_root, bundle) = bundle();
    let mut document = json!({"coverage":{"grounded":3},"provenance":{"repositoryInventory":{"completeRepositoryCoverage":true}}});
    bundle.stamp_inventory(&mut document).unwrap();
    assert_eq!(document["coverage"]["grounded"], 3);
    assert_eq!(
        document["provenance"]["repositoryInventory"],
        bundle.inventory_receipt().unwrap().clone()
    );
    assert_eq!(
        document["provenance"]["repositoryInventory"]["completeRepositoryCoverage"],
        false
    );
}

#[test]
fn invalid_provenance_shape_fails_without_silently_replacing_it() {
    let (_root, bundle) = bundle();
    let mut document = json!({"provenance":"unsupported claim"});
    let before = document.clone();
    assert!(bundle
        .stamp_inventory(&mut document)
        .unwrap_err()
        .to_string()
        .contains("provenance is not an object"));
    assert_eq!(document, before);
}
