use super::*;

#[test]
fn experimental_routes_use_actual_catalog_maturity_including_the_taint_alias() {
    let registry = ModuleRegistry::with_v2_builtins();
    for (task, tool, native) in [
        ("codeql", "codeql:scan", true),
        ("govulncheck", "govulncheck:scan", true),
        ("offense-review", "offense-review:threat-hunt", false),
        ("taint-iris", "taint-iris-next:hunt", false),
        ("taint-iris-next", "taint-iris-next:hunt", false),
    ] {
        let preview = registry.scan_task_preview(task, &json!({})).unwrap();
        assert_eq!(preview.tool, tool);
        assert_eq!(preview.maturity, ModuleMaturity::Labs, "{task}");
        assert_eq!(preview.native, native);
        assert_eq!(preview.runtime_required, !native);
    }
}

#[test]
fn native_presence_preview_uses_canonical_scanner_settings_without_running_them() {
    let registry = ModuleRegistry::with_v2_builtins();
    for (task, key, binary) in [
        ("semgrep", "semgrepBinary", "/absent/owned scanner "),
        ("cargo-audit", "cargoAuditBinary", "/absent/audit "),
    ] {
        let preview = registry
            .scan_task_preview(
                task,
                &json!({key:binary,"semgrepConfig":["first.yml","second.yml"],"semgrepJobs":2}),
            )
            .unwrap();
        assert_eq!(preview.executables[0].command, binary);
        assert_eq!(preview.maturity, ModuleMaturity::Core);
        assert!(!preview.runtime_required);
    }
    assert!(registry
        .scan_task_preview("codeql", &json!({}))
        .unwrap()
        .executables
        .is_empty());
}

#[test]
fn preview_retains_exact_opt_in_and_never_expands_standalone_stages() {
    let registry = ModuleRegistry::with_v2_builtins();
    for task in ["systems-hunt:deep-semantic-hunt", "unknown", ""] {
        assert!(
            registry.scan_task_preview(task, &json!({})).is_err(),
            "{task}"
        );
    }
    let preview = registry
        .scan_task_preview("systems-hunt", &json!({}))
        .unwrap();
    assert_eq!(preview.tool, "systems-hunt:systems-hunt");
    assert!(preview.runtime_required);
    assert!(!preview.deferred_checks.is_empty());
}
