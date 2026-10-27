use kuzushi_core::{
    ModuleRegistry, SbomComponent, SbomDependencyEdge, SbomScanReport, ToolExecutionContext,
    V2Config, WorkspaceTarget,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

pub(super) fn component(name: &str, version: &str, source: &str) -> SbomComponent {
    SbomComponent {
        name: name.into(),
        version: Some(version.into()),
        package_url: Some(format!("pkg:npm/{name}@{version}")),
        ecosystem: "npm".into(),
        manifest_path: source.into(),
        scope: "lockfile".into(),
    }
}

pub(super) fn edge(from: &str, to: &str, source: &str) -> SbomDependencyEdge {
    SbomDependencyEdge {
        from: from.into(),
        to: to.into(),
        source: source.into(),
    }
}

pub(super) fn report(
    components: Vec<SbomComponent>,
    dependencies: Vec<SbomDependencyEdge>,
) -> SbomScanReport {
    SbomScanReport {
        target: "/owned/source".into(),
        manifests_scanned: 0,
        lockfiles: vec![],
        by_ecosystem: BTreeMap::new(),
        components,
        dependencies,
    }
}

pub(super) fn dispatch(root: &Path, input: Value) -> Value {
    let registry = ModuleRegistry::with_v2_builtins_without_optional_adapters();
    let workspace = WorkspaceTarget::new(root).unwrap();
    let config = V2Config::default();
    let context = ToolExecutionContext {
        config: &config,
        workspace: Some(&workspace),
        findings_store: None,
        trace: None,
        cancellation: None,
        authorization: Default::default(),
    };
    let input = registry
        .prepare_dispatch_input("sbom-scan:scan", input, &context, None)
        .unwrap()
        .authorize_explicit_headless();
    registry
        .dispatch_prepared_input_with_runtime(input, &context, None)
        .unwrap()
}
