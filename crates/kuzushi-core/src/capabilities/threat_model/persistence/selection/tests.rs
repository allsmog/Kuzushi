use super::*;
use crate::capabilities::threat_model::{
    commit_threat_model_revision, load_active_threat_model, threat_model_object_path, ScopeRef,
    ThreatModelCommit, ThreatModelRevisionSource,
};
use serde_json::json;

pub(crate) fn commit_test_model(root: &Path, marker: &str) -> ThreatModelRef {
    commit_threat_model_revision(root, &json!({
        "version": "1", "methodology": "stride", "title": marker,
        "dfd": {"nodes": [{"id": "app", "type": "process", "name": marker,
            "description": marker, "trustZone": "internal"}], "flows": [], "trustBoundaries": []},
        "threats": [{"id": "t1", "title": marker, "severity": "high", "targetElementIds": ["app"]}], "summary": {}
    }), ThreatModelCommit {
        model_id: None, new_model: true, label: marker.to_string(),
        scope: ScopeRef::legacy_root(root, &format!("sha256:{}", "1".repeat(64))),
        methodology: "stride".to_string(), source: ThreatModelRevisionSource::Build,
        source_revision_id: None, run_id: None, activate: Some(true), actor: "context-test".to_string(),
    }).unwrap().model_ref
}

#[test]
fn selected_revision_and_explicit_absence_ignore_later_activation() {
    let root = tempfile::tempdir().unwrap();
    let first = commit_test_model(root.path(), "accepted-a");
    let second = commit_test_model(root.path(), "accepted-b");
    let selected = ThreatModelSelection::from_input(&json!({"threatModelRef": first})).unwrap();
    assert_eq!(
        load_selected_threat_model(root.path(), &selected)
            .unwrap()
            .unwrap()["title"],
        "accepted-a"
    );
    let none = ThreatModelSelection::from_input(&json!({"threatModelRef": null})).unwrap();
    assert!(load_selected_threat_model(root.path(), &none)
        .unwrap()
        .is_none());
    assert_eq!(
        load_active_threat_model(root.path())
            .unwrap()
            .unwrap()
            .model_ref,
        second
    );
}

#[test]
fn explicit_reference_never_falls_back_after_missing_or_corrupt_objects() {
    let root = tempfile::tempdir().unwrap();
    let first = commit_test_model(root.path(), "accepted-a");
    commit_test_model(root.path(), "accepted-b");
    let path = threat_model_object_path(root.path(), &first.sha256).unwrap();
    std::fs::write(&path, b"{}").unwrap();
    assert!(load_exact_threat_model(root.path(), &first)
        .unwrap_err()
        .to_string()
        .contains("SHA verification"));
    std::fs::remove_file(path).unwrap();
    assert!(load_exact_threat_model(root.path(), &first).is_err());
}

#[test]
fn reference_digest_must_match_the_recorded_revision() {
    let root = tempfile::tempdir().unwrap();
    let mut first = commit_test_model(root.path(), "accepted-a");
    first.sha256 = format!("sha256:{}", "0".repeat(64));
    assert!(load_exact_threat_model(root.path(), &first)
        .unwrap_err()
        .to_string()
        .contains("immutable object verification"));
}

#[test]
fn malformed_and_conflicting_references_are_errors() {
    assert!(ThreatModelSelection::from_input(&json!({"threatModelRef": "active"})).is_err());
    assert!(ThreatModelSelection::from_input(
        &json!({"threatModelRef": null, "threat_model_ref": {}})
    )
    .is_err());
    assert!(matches!(
        ThreatModelSelection::from_input(&json!({"threat_model_ref": null})).unwrap(),
        ThreatModelSelection::None
    ));
    assert!(matches!(
        ThreatModelSelection::from_input(&json!({})).unwrap(),
        ThreatModelSelection::Active
    ));
}
