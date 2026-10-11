use super::*;
use kuzushi_core::workspace::{
    save_project_model_document, ProjectModelDocument, ProjectModelSection,
    ProjectModelSectionOrigin, PROJECT_MODEL_SCHEMA_VERSION, ROOT_SCOPE_ID,
};
use kuzushi_core::V2Config;

#[test]
fn project_model_without_target_projects_missing_state() {
    let app = ShellApp::new(V2Config::default(), None);

    let model = project_model(&app);

    assert_eq!(model.scope_label, "no target selected");
    assert_eq!(model.revision_label, "rev:unknown");
    assert!(model
        .rows
        .iter()
        .any(|row| row.section == "review surface" && row.origin == ProjectModelOrigin::Missing));
}

#[test]
fn threat_model_row_without_an_artifact_counts_no_assumptions() {
    let temp = tempfile::tempdir().unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));

    let model = project_model(&app);
    let row = model
        .rows
        .iter()
        .find(|row| row.section == "threat model")
        .expect("threat model row");

    assert_eq!(row.state, "missing");
    assert!(
        row.summary.ends_with("assumptions —"),
        "guidance copy must not read as a measured count: {}",
        row.summary
    );
}

#[test]
fn project_model_origin_labels_are_stable() {
    assert_eq!(ProjectModelOrigin::Local.glyph(), "◆");
    assert_eq!(ProjectModelOrigin::Local.label(), "local");
    assert_eq!(ProjectModelOrigin::Inherited.glyph(), "⤓");
    assert_eq!(ProjectModelOrigin::Inherited.label(), "inherited");
    assert_eq!(ProjectModelOrigin::Missing.glyph(), "○");
    assert_eq!(ProjectModelOrigin::Missing.label(), "missing");
    assert_eq!(ProjectModelOrigin::Stale.glyph(), "⚠");
    assert_eq!(ProjectModelOrigin::Stale.label(), "stale");
}

#[test]
fn project_model_aggregates_context_threat_dfd_and_findings() {
    let temp = tempfile::tempdir().unwrap();
    crate::test_support::write_current_context_snapshot(
        temp.path(),
        serde_json::json!({
            "discovery": "auto",
            "filesIndexed": 2,
            "fileIndex": { "totalFiles": 3 },
            "repoContext": {
                "languages": ["Rust"],
                "frameworks": ["Cargo"]
            },
            "generatedSlices": ["repo"]
        }),
    );
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.domain_mut()
        .set_context_view(crate::app::ContextSnapshotView {
            snapshot_path: Some(kuzushi_core::context_snapshot_path(temp.path())),
            exists: true,
            freshness: Some(kuzushi_core::context::ContextSnapshotFreshness::Current),
            status: "snapshot present; 2 indexed file(s)".to_string(),
            target: Some(temp.path().display().to_string()),
            discovery: Some("auto".to_string()),
            files_indexed: Some(2),
            total_files: Some(3),
            languages: vec!["Rust".to_string()],
            frameworks: vec!["Cargo".to_string()],
            generated_slices: vec!["repo".to_string()],
            stale_slices: Vec::new(),
            enrichment_claims: 0,
            enrichment_model: None,
            inspection: None,
        });
    write_threat_model(temp.path());
    *app.findings_mut() = vec![kuzushi_core::Finding::new_tool(
        "demo",
        "demo.rule",
        "src/auth/login.rs",
        88,
        None,
        kuzushi_core::Severity::High,
        "Unvalidated input path",
    )];
    app.hydrate_all_view_data_for_test();

    let model = project_model(&app);

    assert!(model.scope_label.contains(
        temp.path()
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
    ));
    assert!(
        model.rows.iter().any(|row| {
            row.section == "inventory"
                && row.origin == ProjectModelOrigin::Local
                && row.summary.contains("Rust")
                && row.summary.contains("Cargo")
        }),
        "{model:?}"
    );
    assert!(model.rows.iter().any(|row| {
        row.section == "threat model"
            && row.origin == ProjectModelOrigin::Local
            && row.summary.contains("demo summary")
            && row.summary.ends_with("assumptions 1")
    }));
    assert!(model.rows.iter().any(|row| {
        row.section == "data flow"
            && row.state == "present"
            && row.summary.contains("2 nodes")
            && row.summary.contains("1 flows")
    }));
    assert!(model
        .rows
        .iter()
        .any(|row| row.section == "review surface" && row.summary.contains("1 items")));
}

#[test]
fn project_model_renders_persisted_nested_scope_tree() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("libs/parser/.git")).unwrap();
    std::fs::write(
        temp.path().join(".gitmodules"),
        r#"
        [submodule "libs/parser"]
            path = libs/parser
        "#,
    )
    .unwrap();
    let tree = kuzushi_core::discover_nested_project_scopes(temp.path());
    kuzushi_core::save_nested_project_scopes(temp.path(), &tree).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.set_active_scope(Some(crate::app::TargetCandidateScope {
        id: "submodule-libs-parser".to_string(),
        kind: kuzushi_core::NestedProjectKind::Submodule,
        rel_path: "libs/parser".to_string(),
    }));
    app.hydrate_all_view_data_for_test();

    let model = project_model(&app);

    assert!(model.scope_label.contains("libs/parser"));
    let scope_row = model
        .rows
        .iter()
        .find(|row| row.section == "scope tree")
        .expect("scope tree row");
    assert_eq!(scope_row.origin, ProjectModelOrigin::Local);
    assert_eq!(scope_row.state, "present");
    assert!(scope_row.summary.contains("1 nested scope"));
    assert!(scope_row.summary.contains("submodule libs/parser"));
}

#[test]
fn project_model_does_not_discover_unpersisted_scope_tree_during_render() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(temp.path().join("vendor")).unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();

    let model = project_model(&app);

    let scope_row = model
        .rows
        .iter()
        .find(|row| row.section == "scope tree")
        .expect("scope tree row");
    assert_eq!(scope_row.origin, ProjectModelOrigin::Missing);
    assert_eq!(scope_row.state, "root only");
    assert!(scope_row.summary.contains("run `next`"));
}

#[test]
fn project_model_prefers_persisted_scope_document_rows() {
    let temp = tempfile::tempdir().unwrap();
    let context_path = kuzushi_core::context_snapshot_path(temp.path());
    std::fs::create_dir_all(context_path.parent().unwrap()).unwrap();
    std::fs::write(&context_path, "{\"old\":true}\n").unwrap();
    let old_hash = kuzushi_core::static_evidence::static_content_hash("{\"old\":true}\n");
    let document = ProjectModelDocument {
        schema_version: PROJECT_MODEL_SCHEMA_VERSION,
        scope_id: ROOT_SCOPE_ID.to_string(),
        scope_path: ".".to_string(),
        built_at_revision: None,
        sections: vec![
            ProjectModelSection {
                key: "context-feed".to_string(),
                origin: ProjectModelSectionOrigin::Local,
                summary: "context snapshot present".to_string(),
                source_path: Some(".kuzushi/context-snapshot.json".to_string()),
                content_hash: Some(old_hash),
                built_at_revision: None,
                stale: false,
            },
            ProjectModelSection {
                key: "inventory".to_string(),
                origin: ProjectModelSectionOrigin::Inherited,
                summary: "inherited inventory summary".to_string(),
                source_path: None,
                content_hash: None,
                built_at_revision: None,
                stale: false,
            },
        ],
    };
    save_project_model_document(temp.path(), &document).unwrap();
    std::fs::write(&context_path, "{\"new\":true}\n").unwrap();
    let mut app = ShellApp::new(V2Config::default(), None);
    app.set_target(Some(temp.path().to_path_buf()));
    app.hydrate_all_view_data_for_test();

    let model = project_model(&app);

    assert!(model.rows.iter().any(|row| {
        row.section == "context feed"
            && row.origin == ProjectModelOrigin::Stale
            && row.state == "stale"
    }));
    assert!(model.rows.iter().any(|row| {
        row.section == "inventory"
            && row.origin == ProjectModelOrigin::Inherited
            && row.state == "inherited"
            && row.summary.contains("inherited inventory")
    }));
}

fn write_threat_model(root: &std::path::Path) {
    let path = kuzushi_core::capabilities::persistent_threat_model_path(root);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        path,
        serde_json::json!({
            "summary": {"text": "demo summary"},
            "threats": [{"id": "T1"}],
            "assumptions": ["operator supplied scope"],
            "dfd": {
                "nodes": [
                    {"id": "user", "name": "Browser", "type": "actor", "trustZone": "internet"},
                    {"id": "api", "name": "API", "type": "process", "trustZone": "app"}
                ],
                "flows": [
                    {"id": "f1", "sourceId": "user", "targetId": "api", "description": "HTTPS"}
                ],
                "trustBoundaries": [{"id": "tb1"}]
            }
        })
        .to_string(),
    )
    .unwrap();
}
