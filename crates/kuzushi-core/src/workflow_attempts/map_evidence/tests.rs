use super::*;
use serde_json::json;
use std::fs;

#[test]
fn empty_repository_scope_is_inadequate() {
    let facts = facts_from_documents(
        Some(&json!({"filesIndexed": 0})),
        Some(&json!({"total": 0})),
        Some(&scope_only_document()),
    );

    assert_eq!(assess_map_evidence(&facts), MapEvidenceAdequacy::Inadequate);
    assert!(!threat_model_has_concrete_dfd(&scope_only_document()));
    assert!(threat_model_is_scope_placeholder_only(
        &scope_only_document()
    ));
}

#[test]
fn deterministic_repository_skeleton_is_not_analysis_evidence() {
    let document = json!({
        "dfd": {
            "nodes": [
                {
                    "id": "actor-external",
                    "name": "External actor",
                    "description": "Repository user or caller",
                    "trustZone": "external"
                },
                {
                    "id": "app",
                    "name": "Application",
                    "description": "Repository application boundary",
                    "trustZone": "internal"
                }
            ],
            "flows": []
        },
        "threats": []
    });
    let facts = facts_from_documents(
        Some(&json!({"filesIndexed": 0})),
        Some(&json!({"total": 0})),
        Some(&document),
    );

    assert_eq!(assess_map_evidence(&facts), MapEvidenceAdequacy::Inadequate);
    assert!(threat_model_is_scope_placeholder_only(&document));
    assert!(!threat_model_has_concrete_dfd(&document));
}

#[test]
fn source_inventory_or_entry_points_are_adequate() {
    for facts in [
        MapEvidenceFacts {
            files_indexed: 1,
            ..Default::default()
        },
        MapEvidenceFacts {
            entry_points: 1,
            ..Default::default()
        },
    ] {
        assert_eq!(assess_map_evidence(&facts), MapEvidenceAdequacy::Adequate);
    }
}

#[test]
fn imported_design_requires_concrete_topology_or_threats() {
    let placeholder = MapEvidenceFacts {
        explicit_import: true,
        ..Default::default()
    };
    let topology = MapEvidenceFacts {
        explicit_import: true,
        concrete_nodes: 2,
        ..Default::default()
    };

    assert_eq!(
        assess_map_evidence(&placeholder),
        MapEvidenceAdequacy::Inadequate
    );
    assert_eq!(
        assess_map_evidence(&topology),
        MapEvidenceAdequacy::Adequate
    );
}

#[test]
fn imported_design_provenance_requires_a_loaded_operator_source() {
    assert!(result_sources_include_operator_input(&json!({
        "data": {"sources": [{"kind": "operator", "status": "loaded"}]}
    })));
    for result in [
        json!({"data": {"sources": [{"kind": "context", "status": "loaded"}]}}),
        json!({"data": {"sources": [{"kind": "operator", "status": "skipped"}]}}),
    ] {
        assert!(!result_sources_include_operator_input(&result));
    }
}

#[test]
fn concrete_flow_or_threat_is_meaningful_model_evidence() {
    for facts in [
        MapEvidenceFacts {
            flows: 1,
            ..Default::default()
        },
        MapEvidenceFacts {
            threats: 1,
            ..Default::default()
        },
    ] {
        assert_eq!(assess_map_evidence(&facts), MapEvidenceAdequacy::Adequate);
    }
}

#[test]
fn referenced_runs_do_not_inherit_mutable_target_evidence() {
    let target = tempfile::tempdir().unwrap();
    write_json(
        &crate::context::context_snapshot_path(target.path()),
        &json!({"filesIndexed": 99}),
    );
    write_run_result(
        target.path(),
        "run-empty",
        &json!({"data": {"snapshot": {"filesIndexed": 0}}}),
    );

    let facts = collect_map_evidence(target.path(), &["run-empty".to_string()]);

    assert_eq!(facts.files_indexed, 0);
    assert_eq!(assess_map_evidence(&facts), MapEvidenceAdequacy::Inadequate);
}

#[test]
fn referenced_run_results_supply_each_map_evidence_kind() {
    let target = tempfile::tempdir().unwrap();
    write_run_result(
        target.path(),
        "run-context",
        &json!({"data": {"snapshot": {"filesIndexed": 3}}}),
    );
    write_run_result(
        target.path(),
        "run-entry-points",
        &json!({"data": {"total": 2, "entryPoints": [{}, {}]}}),
    );
    write_run_result(
        target.path(),
        "run-threat-model",
        &json!({"data": {"document": concrete_threat_model()}}),
    );
    let refs = ["run-context", "run-entry-points", "run-threat-model"].map(str::to_string);

    let facts = collect_map_evidence(target.path(), &refs);

    assert_eq!(facts.files_indexed, 3);
    assert_eq!(facts.entry_points, 2);
    assert_eq!(facts.concrete_nodes, 2);
    assert_eq!(facts.flows, 1);
    assert_eq!(facts.threats, 1);
}

#[test]
fn empty_run_refs_use_the_documented_legacy_fallback() {
    let target = tempfile::tempdir().unwrap();
    write_json(
        &crate::context::context_snapshot_path(target.path()),
        &json!({"filesIndexed": 1}),
    );

    assert_eq!(collect_map_evidence(target.path(), &[]).files_indexed, 1);
}

#[test]
fn message_names_the_empty_attempt_not_the_target_when_workspace_has_evidence() {
    let target = tempfile::tempdir().unwrap();
    write_json(
        &crate::context::context_snapshot_path(target.path()),
        &json!({"filesIndexed": 42}),
    );

    let message = insufficient_map_evidence_message(target.path());

    assert!(message.contains("This attempt carried no map evidence"), "{message}");
    assert!(message.contains("42 file(s) indexed"), "{message}");
    assert!(
        !message.contains("select another target"),
        "a healthy workspace must never be blamed on the target: {message}"
    );
}

#[test]
fn message_steers_toward_building_evidence_when_workspace_is_empty_too() {
    let target = tempfile::tempdir().unwrap();

    let message = insufficient_map_evidence_message(target.path());

    assert!(message.contains("no durable map artifacts yet"), "{message}");
    assert!(message.contains("context build"), "{message}");
    assert!(!message.contains("select another target"), "{message}");
}

fn write_run_result(target: &Path, run_id: &str, result: &Value) {
    write_json(&crate::run_dir(target, run_id).join("result.json"), result);
}

fn write_json(path: &Path, value: &Value) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

fn concrete_threat_model() -> Value {
    json!({
        "dfd": {
            "nodes": [
                {"id": "user", "name": "User"},
                {"id": "api", "name": "API"}
            ],
            "flows": [{"id": "flow-1"}]
        },
        "threats": [{"id": "threat-1"}]
    })
}

fn scope_only_document() -> Value {
    json!({
        "dfd": {
            "nodes": [{
                "id": "n1",
                "name": "fixture repository scope",
                "trustZone": "analysis-scope",
                "type": "process"
            }],
            "flows": []
        },
        "threats": []
    })
}
