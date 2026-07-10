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
    assert!(!tree
        .scopes
        .iter()
        .any(|scope| scope.rel_path == "__pycache__"));
}

#[test]
fn discovers_manifest_backed_package_roots_with_source() {
    let temp = tempfile::tempdir().unwrap();
    touch_dir(temp.path(), "api/cmd");
    touch_dir(temp.path(), "web/src");
    touch_dir(temp.path(), "docs");
    touch_dir(temp.path(), "node_modules/pkg/src");
    fs::write(temp.path().join("package.json"), r#"{"name":"root"}"#).unwrap();
    fs::write(temp.path().join("api/go.mod"), "module example/api\n").unwrap();
    fs::write(temp.path().join("api/cmd/main.go"), "package main\n").unwrap();
    fs::write(temp.path().join("web/package.json"), r#"{"name":"web"}"#).unwrap();
    fs::write(
        temp.path().join("web/src/app.ts"),
        "export const app = 1;\n",
    )
    .unwrap();
    fs::write(temp.path().join("docs/package.json"), r#"{"name":"docs"}"#).unwrap();
    fs::write(
        temp.path().join("node_modules/pkg/package.json"),
        r#"{"name":"pkg"}"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("node_modules/pkg/src/index.js"),
        "module.exports = {};",
    )
    .unwrap();

    let tree = discover_nested_project_scopes(temp.path());

    let package_paths = tree
        .scopes
        .iter()
        .filter(|scope| scope.kind == NestedProjectKind::PackageRoot)
        .map(|scope| scope.rel_path.as_str())
        .collect::<Vec<_>>();
    assert!(package_paths.contains(&"api"), "{package_paths:?}");
    assert!(package_paths.contains(&"web"), "{package_paths:?}");
    assert!(!package_paths.contains(&"."), "{package_paths:?}");
    assert!(!package_paths.contains(&"docs"), "{package_paths:?}");
    assert!(
        !package_paths
            .iter()
            .any(|path| path.starts_with("node_modules")),
        "{package_paths:?}"
    );

    let api = tree
        .scopes
        .iter()
        .find(|scope| scope.rel_path == "api")
        .expect("api package scope");
    assert_eq!(api.id, "package-api");
    assert_eq!(api.kind.label(), "package");
    assert_eq!(api.parent.as_deref(), Some(ROOT_SCOPE_ID));
}

#[test]
fn discovers_declared_workspace_members_from_go_cargo_and_node_manifests() {
    let temp = tempfile::tempdir().unwrap();
    touch_dir(temp.path(), "cmd/proxy");
    touch_dir(temp.path(), "crates/core/src");
    touch_dir(temp.path(), "web/src");
    touch_dir(temp.path(), "packages/api/src");
    touch_dir(temp.path(), "ignored/missing");
    fs::write(
        temp.path().join("go.work"),
        "go 1.22\nuse (\n  ./cmd/proxy\n  ./missing\n)\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*\"]\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"workspaces":["web","packages/*","missing-node"]}"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("pnpm-workspace.yaml"),
        "packages:\n  - web\n  - packages/*\n",
    )
    .unwrap();

    let tree = discover_nested_project_scopes(temp.path());
    let package_paths = package_scope_paths(&tree);

    assert!(package_paths.contains(&"cmd/proxy"), "{package_paths:?}");
    assert!(package_paths.contains(&"crates/core"), "{package_paths:?}");
    assert!(package_paths.contains(&"web"), "{package_paths:?}");
    assert!(package_paths.contains(&"packages/api"), "{package_paths:?}");
    assert!(!package_paths.contains(&"missing"), "{package_paths:?}");
    assert!(
        !package_paths.contains(&"missing-node"),
        "{package_paths:?}"
    );
}

#[test]
fn discovers_entrypoint_clusters_without_their_own_manifest() {
    let temp = tempfile::tempdir().unwrap();
    touch_dir(temp.path(), "cmd/agent");
    touch_dir(temp.path(), "cmd/proxy");
    touch_dir(temp.path(), "pkg/transport");
    fs::write(temp.path().join("go.mod"), "module example/root\n").unwrap();
    fs::write(
        temp.path().join("cmd/agent/main.go"),
        "package main\nfunc main() {}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("cmd/proxy/main.go"),
        "package main\nfunc main() {}\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("pkg/transport/lib.go"),
        "package transport\n",
    )
    .unwrap();

    let tree = discover_nested_project_scopes(temp.path());
    let entrypoints = tree
        .scopes
        .iter()
        .filter(|scope| scope.kind == NestedProjectKind::EntrypointCluster)
        .map(|scope| scope.rel_path.as_str())
        .collect::<Vec<_>>();

    assert!(entrypoints.contains(&"cmd/agent"), "{entrypoints:?}");
    assert!(entrypoints.contains(&"cmd/proxy"), "{entrypoints:?}");
    assert!(!entrypoints.contains(&"pkg/transport"), "{entrypoints:?}");
}

#[test]
fn entrypoint_cluster_discovery_is_bounded_to_known_roots() {
    let temp = tempfile::tempdir().unwrap();
    for index in 0..(ENTRYPOINT_CLUSTER_BUDGET + 80) {
        touch_dir(temp.path(), &format!("apps/service-{index:04}"));
    }
    touch_dir(temp.path(), "unrelated/deep/tree");

    let tree = discover_nested_project_scopes(temp.path());
    let entrypoints = tree
        .scopes
        .iter()
        .filter(|scope| scope.kind == NestedProjectKind::EntrypointCluster)
        .collect::<Vec<_>>();

    assert_eq!(entrypoints.len(), ENTRYPOINT_CLUSTER_BUDGET);
    assert!(entrypoints
        .iter()
        .all(|scope| scope.rel_path.starts_with("apps/")));
    assert!(!entrypoints
        .iter()
        .any(|scope| scope.rel_path.starts_with("unrelated/")));
}

fn package_scope_paths(tree: &NestedProjectScopeTree) -> Vec<&str> {
    tree.scopes
        .iter()
        .filter(|scope| scope.kind == NestedProjectKind::PackageRoot)
        .map(|scope| scope.rel_path.as_str())
        .collect()
}

#[test]
fn scope_tree_round_trips_scopes_json() {
    let temp = tempfile::tempdir().unwrap();
    touch_dir(temp.path(), "third_party");
    let tree = discover_nested_project_scopes(temp.path());

    let path = save_nested_project_scopes(temp.path(), &tree).unwrap();
    let loaded = load_nested_project_scopes(temp.path()).unwrap().unwrap();

    assert_eq!(
        path,
        temp.path().join(".kuzushi/v3/project-model/scopes.json")
    );
    assert_eq!(loaded, tree);
}
