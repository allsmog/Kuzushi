use super::super::*;
use serde_json::{json, Value};

fn evidence(root: &std::path::Path, name: &str) -> AttachmentInput {
    std::fs::write(root.join(name), "Owned document marker α.\n").unwrap();
    AttachmentInput {
        source: name.into(),
        title: None,
        kind: "policy".into(),
        scope_update: ScopeUpdate::default(),
    }
}

#[test]
fn inspecting_and_generating_packets_preserve_saved_scope_bytes_and_profile() {
    let root = tempfile::tempdir().unwrap();
    scope(
        root.path(),
        ScopeUpdate {
            profile: Some("operator-profile".into()),
            ..Default::default()
        },
        false,
    )
    .unwrap();
    let path = root.path().join(".kuzushi/vendor-assessment/scope.json");
    let before = std::fs::read(&path).unwrap();
    scope(root.path(), ScopeUpdate::default(), false).unwrap();
    let packet = prompts(
        root.path(),
        ScopeUpdate::default(),
        Some("owned-packet".into()),
    )
    .unwrap();
    assert!(packet["data"]["prompts"][0]["content"]
        .as_str()
        .unwrap()
        .contains("operator-profile"));
    assert_eq!(before, std::fs::read(path).unwrap());
}

#[test]
fn failed_capture_does_not_apply_proposed_metadata() {
    let root = tempfile::tempdir().unwrap();
    scope(
        root.path(),
        ScopeUpdate {
            vendor_name: Some("Owned vendor".into()),
            ..Default::default()
        },
        false,
    )
    .unwrap();
    let path = root.path().join(".kuzushi/vendor-assessment/scope.json");
    let before = std::fs::read(&path).unwrap();
    let input = AttachmentInput {
        source: "missing.txt".into(),
        title: None,
        kind: "policy".into(),
        scope_update: ScopeUpdate {
            vendor_name: Some("Must not replace".into()),
            ..Default::default()
        },
    };
    assert!(attach(root.path(), input).is_err());
    assert_eq!(before, std::fs::read(path).unwrap());
}

#[test]
fn partial_unicode_capture_discloses_extent_and_keeps_distinct_document_ids() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("large.txt");
    let text = "α".repeat(128_001);
    std::fs::write(&path, &text).unwrap();
    let input = || AttachmentInput {
        source: "large.txt".into(),
        title: None,
        kind: "policy".into(),
        scope_update: ScopeUpdate::default(),
    };
    let first = attach(root.path(), input()).unwrap();
    let second = attach(root.path(), input()).unwrap();
    let doc = &first["data"]["document"];
    assert_eq!(doc["sourceBytes"], text.len());
    assert_eq!(doc["capturedBytes"], 256_000);
    assert_eq!(doc["textTruncated"], true);
    assert!(!doc["text"].as_str().unwrap().contains('�'));
    assert_eq!(
        doc["sourceDigest"],
        crate::run_lifecycle::sha256_content_digest(text.as_bytes())
    );
    assert!(first["output"]
        .as_str()
        .unwrap()
        .contains("Text capture is partial"));
    assert_ne!(doc["id"], second["data"]["document"]["id"]);
}

#[test]
fn malformed_or_oversized_scope_preserves_the_original_state() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join(".kuzushi/vendor-assessment/scope.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    for state in [json!([]), json!({"documents":{}}), json!({"profile":42})] {
        let before = serde_json::to_vec(&state).unwrap();
        std::fs::write(&path, &before).unwrap();
        assert!(scope(root.path(), ScopeUpdate::default(), false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    scope(root.path(), ScopeUpdate::default(), true).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(scope(
        root.path(),
        ScopeUpdate {
            profile: Some("x".repeat(8 * 1024 * 1024)),
            ..Default::default()
        },
        false
    )
    .is_err());
    assert_eq!(std::fs::read(path).unwrap(), before);
}

#[test]
fn clear_conflicting_with_updates_is_rejected_without_losing_evidence() {
    let root = tempfile::tempdir().unwrap();
    attach(root.path(), evidence(root.path(), "owned.txt")).unwrap();
    assert!(scope(
        root.path(),
        ScopeUpdate {
            vendor_name: Some("conflict".into()),
            ..Default::default()
        },
        true
    )
    .is_err());
    assert_eq!(
        scope(root.path(), ScopeUpdate::default(), false).unwrap()["data"]["scope"]["documents"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn oversized_model_context_refuses_before_model_resolution_or_scope_update() {
    let root = tempfile::tempdir().unwrap();
    attach(root.path(), evidence(root.path(), "owned.txt")).unwrap();
    let path = root.path().join(".kuzushi/vendor-assessment/scope.json");
    let before = std::fs::read(&path).unwrap();
    let error = assess(
        root.path(),
        ScopeUpdate {
            use_case: Some("x".repeat(512 * 1024)),
            ..Default::default()
        },
        Some("too-large".into()),
        None,
        || panic!("No model resolution permitted"),
    )
    .unwrap_err();
    assert!(error.to_string().contains("512 KiB"));
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert!(!root
        .path()
        .join(".kuzushi/vendor-assessment/runs/too-large/report.json")
        .exists());
}

#[test]
fn url_reference_has_unknown_source_size_and_is_not_parsed_evidence() {
    let root = tempfile::tempdir().unwrap();
    let value = attach(
        root.path(),
        AttachmentInput {
            source: "https://example.invalid/owned-policy".into(),
            kind: "policy".into(),
            title: None,
            scope_update: ScopeUpdate::default(),
        },
    )
    .unwrap();
    assert_eq!(value["data"]["document"]["sourceBytes"], Value::Null);
    assert!(value["output"].as_str().unwrap().contains("does not fetch"));
    assert!(
        assess(root.path(), ScopeUpdate::default(), None, None, || panic!(
            "No model resolution permitted"
        ))
        .is_err()
    );
}
