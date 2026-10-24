use super::*;
use crate::config::V2Config;
use tempfile::tempdir;

#[test]
fn complete_file_enumeration_keeps_content_truncation_distinct() {
    let root = tempdir().unwrap();
    std::fs::write(
        root.path().join("large.rs"),
        "// owned fixture\n".repeat(20_000),
    )
    .unwrap();
    let inventory = crate::workspace::build_repository_inventory(root.path()).unwrap();
    let inspection = require_complete_enumeration(&inventory).unwrap();
    let bytes = inventory_artifact(&inventory).unwrap();
    let receipt = inventory_receipt("scope/inventory.json", &bytes, inspection, &inventory);

    assert_eq!(receipt["enumerationComplete"], true);
    assert_eq!(receipt["enumeratedFiles"], 1);
    assert_eq!(receipt["truncatedFiles"], 1);
    assert!(receipt["inspectionTruncation"].is_object());
    assert_eq!(receipt["maxEntries"], 100_000);
    assert_eq!(receipt["maxInspectedBytes"], 512 * 1024 * 1024);
    assert_eq!(receipt["maxFileInspectionBytes"], 256 * 1024);
    assert_eq!(
        receipt["sha256"],
        crate::worker_protocol::sha256_digest(&bytes).0
    );
}

#[test]
fn incomplete_or_legacy_unknown_enumeration_cannot_become_scope_files() {
    let root = tempdir().unwrap();
    std::fs::write(root.path().join("one.rs"), "// one\n").unwrap();
    std::fs::write(root.path().join("two.rs"), "// two\n").unwrap();
    let mut inventory = crate::workspace::inventory::build_repository_inventory_with_limits(
        root.path(),
        1,
        1024,
        &mut |_| {},
        &|| false,
    )
    .unwrap();
    assert!(require_complete_enumeration(&inventory)
        .unwrap_err()
        .to_string()
        .contains("entry cap"));
    inventory.inspection.as_mut().unwrap().enumeration_complete = None;
    assert!(require_complete_enumeration(&inventory).is_err());
    inventory.inspection = None;
    assert!(require_complete_enumeration(&inventory).is_err());
}

#[test]
fn overlapping_scope_materialization_has_one_total_membership_limit() {
    let root = tempdir().unwrap();
    let mut inventory = crate::workspace::build_repository_inventory(root.path()).unwrap();
    let inspection = inventory.inspection.as_mut().unwrap();
    inspection.files = (0..50_001).map(|i| format!("file-{i}.rs")).collect();
    let left = CampaignShard {
        name: "left".into(),
        paths: vec![".".into()],
    };
    let right = CampaignShard {
        name: "right".into(),
        paths: vec![".".into()],
    };
    let shards = BTreeMap::from([("left".into(), &left), ("right".into(), &right)]);
    let config = V2Config::default();
    let ctx = ToolExecutionContext {
        config: &config,
        workspace: None,
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };

    let error = membership::collect(inspection, &shards, &ctx).unwrap_err();

    assert!(
        error.to_string().contains("memberships exceed 100000"),
        "{error:#}"
    );
}
