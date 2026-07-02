use super::*;
use std::fs;
use std::path::Path;

fn touch_dir(root: &Path, rel: &str) {
    fs::create_dir_all(root.join(rel)).expect("create dir");
}

#[test]
fn discovers_root_and_gitmodule_submodule_scope() {
    let temp = tempfile::tempdir().unwrap();
    touch_dir(temp.path(), "libs/parser/.git");
    fs::write(
        temp.path().join(".gitmodules"),
        r#"
            [submodule "libs/parser"]
                path = "libs/parser"
                url = https://example.invalid/parser.git
            "#,
    )
    .unwrap();

    let tree = discover_nested_project_scopes(temp.path());

    assert_eq!(tree.root_scope().unwrap().id, ROOT_SCOPE_ID);
    let submodule = tree
        .non_root_scopes()
        .find(|scope| scope.rel_path == "libs/parser")
        .expect("submodule scope");
    assert_eq!(submodule.kind, NestedProjectKind::Submodule);
    assert_eq!(submodule.id, "submodule-libs-parser");
    assert_eq!(submodule.parent.as_deref(), Some(ROOT_SCOPE_ID));
    assert_eq!(
        submodule.inherited_sections,
        vec!["context-feed".to_string(), "threat-model".to_string()]
    );
}

#[test]
fn discovers_vendored_and_dependency_roots() {
    let temp = tempfile::tempdir().unwrap();
    touch_dir(temp.path(), "vendor");
    touch_dir(temp.path(), "node_modules");
    touch_dir(temp.path(), "__pycache__");

    let tree = discover_nested_project_scopes(temp.path());

    assert!(tree
        .scopes
        .iter()
        .any(|scope| scope.rel_path == "vendor" && scope.kind == NestedProjectKind::VendoredRoot));
    assert!(tree.scopes.iter().any(|scope| {
        scope.rel_path == "node_modules" && scope.kind == NestedProjectKind::DependencyRoot
    }));
    assert!(!tree.scopes.iter().any(|scope| scope.rel_path == "__pycache__"));
}

#[test]
fn scope_tree_round_trips_scopes_json() {
    let temp = tempfile::tempdir().unwrap();
    touch_dir(temp.path(), "third_party");
    let tree = discover_nested_project_scopes(temp.path());

    let path = save_nested_project_scopes(temp.path(), &tree).unwrap();
    let loaded = load_nested_project_scopes(temp.path()).unwrap().unwrap();

    assert_eq!(path, temp.path().join(".kuzushi/v2/project-model/scopes.json"));
    assert_eq!(loaded, tree);
}
