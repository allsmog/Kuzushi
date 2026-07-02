use super::*;

fn scope(kind: NestedProjectKind, rel_path: &str) -> NestedProjectScope {
    NestedProjectScope {
        id: format!("scope-{rel_path}"),
        parent: Some(crate::workspace::ROOT_SCOPE_ID.to_string()),
        kind,
        rel_path: rel_path.to_string(),
        inherited_sections: Vec::new(),
    }
}

#[test]
fn classifies_entrypoint_clusters_as_cli_binaries() {
    let scope = scope(NestedProjectKind::EntrypointCluster, "cmd/proxy");
    let signals = ComponentSignals {
        entrypoints: 1,
        source_files: 1,
        ..ComponentSignals::default()
    };

    assert_eq!(classify(&scope, &signals), ComponentClass::CliBinary);
}

#[test]
fn classifies_js_routes_as_web_apps() {
    let scope = scope(NestedProjectKind::PackageRoot, "web");
    let mut signals = ComponentSignals {
        routes: 2,
        source_files: 4,
        ..ComponentSignals::default()
    };
    signals.languages.insert("TypeScript".to_string());

    assert_eq!(classify(&scope, &signals), ComponentClass::WebApp);
}

#[test]
fn scoped_scan_input_keeps_component_paths_under_parent_target() {
    let scope = scope(NestedProjectKind::PackageRoot, "web");
    let input = scoped_scan_input(
        Path::new("/repo"),
        &scope,
        ComponentClass::WebApp,
        &["semgrep".to_string(), "secret-scan".to_string()],
    );

    assert_eq!(input["target"], "/repo");
    assert_eq!(input["paths"][0], "web");
    assert_eq!(input["tasks"][0], "semgrep");
    assert_eq!(input["component"]["class"], "web-app");
}
