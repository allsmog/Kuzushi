use super::*;

fn touch_dir(root: &Path, rel: &str) {
    fs::create_dir_all(root.join(rel)).expect("create dir");
}

fn write_source(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, body).unwrap();
}

#[test]
fn project_model_document_builds_root_sections_and_round_trips() {
    let temp = tempfile::tempdir().unwrap();
    write_source(temp.path(), "src/lib.rs", "fn main() {}\n");
    write_source(temp.path(), ".kuzushi/context-snapshot.json", "{}\n");
    write_source(
        temp.path(),
        ".kuzushi/threat-model.json",
        "{\"summary\":{}}\n",
    );
    let tree = discover_nested_project_scopes(temp.path());
    save_nested_project_scopes(temp.path(), &tree).unwrap();

    let document =
        build_project_model_document(temp.path(), ROOT_SCOPE_ID, Some("abc123".to_string()))
            .unwrap();
    let path = save_project_model_document(temp.path(), &document).unwrap();
    let loaded = load_project_model_document(temp.path(), ROOT_SCOPE_ID, Some("abc123"))
        .unwrap()
        .unwrap();

    assert_eq!(
        path,
        temp.path().join(".kuzushi/v3/project-model/root.json")
    );
    assert_eq!(loaded.scope_id, ROOT_SCOPE_ID);
    assert!(loaded.sections.iter().any(|section| {
        section.key == "inventory" && section.origin == ProjectModelSectionOrigin::Local
    }));
    assert!(loaded.sections.iter().any(|section| {
        section.key == "threat-model" && section.origin == ProjectModelSectionOrigin::Local
    }));
}

#[test]
fn nested_project_model_inherits_parent_context_and_threat_model() {
    let temp = tempfile::tempdir().unwrap();
    touch_dir(temp.path(), "libs/parser/.git");
    write_source(temp.path(), "libs/parser/src/lib.rs", "pub fn parse() {}\n");
    write_source(temp.path(), ".kuzushi/context-snapshot.json", "{}\n");
    write_source(
        temp.path(),
        ".kuzushi/threat-model.json",
        "{\"summary\":{}}\n",
    );
    fs::write(
        temp.path().join(".gitmodules"),
        r#"
        [submodule "libs/parser"]
            path = libs/parser
        "#,
    )
    .unwrap();
    let tree = discover_nested_project_scopes(temp.path());
    save_nested_project_scopes(temp.path(), &tree).unwrap();

    let document = build_project_model_document(
        temp.path(),
        "submodule-libs-parser",
        Some("abc123".to_string()),
    )
    .unwrap();

    assert!(document.sections.iter().any(|section| {
        section.key == "context-feed" && section.origin == ProjectModelSectionOrigin::Inherited
    }));
    assert!(document.sections.iter().any(|section| {
        section.key == "threat-model" && section.origin == ProjectModelSectionOrigin::Inherited
    }));
    assert!(document.sections.iter().any(|section| {
        section.key == "inventory" && section.origin == ProjectModelSectionOrigin::Local
    }));
}

#[test]
fn loaded_project_model_marks_revision_and_hash_staleness() {
    let temp = tempfile::tempdir().unwrap();
    write_source(
        temp.path(),
        ".kuzushi/context-snapshot.json",
        "{\"old\":true}\n",
    );
    let document = ProjectModelDocument {
        schema_version: PROJECT_MODEL_SCHEMA_VERSION,
        scope_id: ROOT_SCOPE_ID.to_string(),
        scope_path: ".".to_string(),
        built_at_revision: Some("oldrev".to_string()),
        sections: vec![source_file_section(
            "context-feed",
            temp.path(),
            &crate::context::context_snapshot_path(temp.path()),
            "context snapshot",
            Some("oldrev"),
        )],
    };
    save_project_model_document(temp.path(), &document).unwrap();
    write_source(
        temp.path(),
        ".kuzushi/context-snapshot.json",
        "{\"new\":true}\n",
    );

    let loaded = load_project_model_document(temp.path(), ROOT_SCOPE_ID, Some("newrev"))
        .unwrap()
        .unwrap();

    assert!(loaded.sections[0].stale);
}

#[test]
fn cyclic_project_scope_parent_chain_returns_error() {
    let temp = tempfile::tempdir().unwrap();
    let tree = NestedProjectScopeTree {
        schema_version: 1,
        root: "scope-a".to_string(),
        scopes: vec![
            NestedProjectScope {
                id: "scope-a".to_string(),
                parent: Some("scope-b".to_string()),
                kind: NestedProjectKind::Root,
                rel_path: ".".to_string(),
                inherited_sections: vec!["context-feed".to_string()],
            },
            NestedProjectScope {
                id: "scope-b".to_string(),
                parent: Some("scope-a".to_string()),
                kind: NestedProjectKind::Submodule,
                rel_path: "libs/parser".to_string(),
                inherited_sections: vec!["context-feed".to_string()],
            },
        ],
    };

    let error =
        build_project_model_document_from_tree(temp.path(), &tree, "scope-a", None).unwrap_err();

    assert!(error
        .to_string()
        .contains("cyclic project scope parent chain"));
}
