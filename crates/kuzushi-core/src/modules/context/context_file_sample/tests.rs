use super::*;

fn inventory() -> (tempfile::TempDir, RepositoryInventory) {
    let root = tempfile::tempdir().unwrap();
    for path in ["root.rs", "alpha/deep/file.py", "zeta/file.rs"] {
        let file = root.path().join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, "// Owned sample fixture; never executed.\n").unwrap();
    }
    let inventory = crate::repository_inventory::build_repository_inventory(root.path()).unwrap();
    (root, inventory)
}

#[test]
fn sampling_reuses_inventory_membership_and_preserves_loose_root_and_shallow_files() {
    let (_root, inventory) = inventory();
    let sample = inventory_file_sample(&inventory, 2).unwrap();
    assert_eq!(sample.files_indexed, 3);
    assert_eq!(sample.files_sample, ["root.rs", "zeta/file.rs"]);
    assert!(!sample.walk_truncated);
    let all = inventory_file_sample(&inventory, 20).unwrap();
    assert_eq!(all.files_sample, ["root.rs", "zeta/file.rs", "alpha/deep/file.py"]);
}

#[test]
fn truncated_inventory_is_not_presented_as_complete_and_missing_receipts_fail() {
    let (_root, mut inventory) = inventory();
    inventory.truncation = Some(crate::repository_inventory::InventoryTruncation { reason: "Owned partial prefix".into() });
    assert!(inventory_file_sample(&inventory, 2).unwrap().walk_truncated);
    inventory.inspection = None;
    assert!(inventory_file_sample(&inventory, 2).unwrap_err().to_string().contains("inspection receipt"));
}

#[cfg(unix)]
#[test]
fn sample_does_not_reintroduce_symlinks_or_ignored_material() {
    let (root, _) = inventory();
    std::os::unix::fs::symlink(root.path(), root.path().join("cycle")).unwrap();
    std::fs::create_dir(root.path().join("node_modules")).unwrap();
    std::fs::write(root.path().join("node_modules/omitted.rs"), "// ignored\n").unwrap();
    let inventory = crate::repository_inventory::build_repository_inventory(root.path()).unwrap();
    let sample = inventory_file_sample(&inventory, 200).unwrap();
    assert_eq!(sample.files_indexed, 3);
    assert!(sample.files_sample.iter().all(|path| !path.contains("cycle") && !path.contains("node_modules")));
    assert!(!inventory.inspection.unwrap().omitted_paths.is_empty());
}
