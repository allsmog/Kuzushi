use super::*;

#[test]
fn metadata_import_does_not_publish_a_scan_attempt() {
    let registry = ModuleRegistry::with_v2_builtins();
    for name in [
        "taint-iris-next:import-sinks",
        "taint-iris-next:dataflow-plan",
        "taint-iris-next:source-sink-trace",
        "taint-iris-next:finding-review",
        "variant:lift-pattern",
        "variant:hunt",
        "offense-review:threat-hunt",
        "carlini-threat-hunt:run",
        "ndiff:hunt-variants",
        "android-apk:scan",
        "codeql:scan",
    ] {
        assert_eq!(
            background_tool_origin_phase(&registry, name, Some(WorkflowPhase::Scan), Some(name)),
            None
        );
    }
}

#[test]
fn mapping_preparation_cannot_replace_a_context_result_even_in_a_map_plan() {
    let registry = ModuleRegistry::with_v2_builtins();
    for name in [
        "context:build",
        "context-lite:index",
        "entry-points:extract",
    ] {
        assert_eq!(
            background_tool_origin_phase(&registry, name, Some(WorkflowPhase::Map), Some(name)),
            None,
            "{name}"
        );
    }
    assert_eq!(
        background_tool_origin_phase(
            &registry,
            "threat-model:build",
            Some(WorkflowPhase::Map),
            Some("threat-model:build")
        ),
        Some(WorkflowPhase::Map)
    );
}

#[test]
fn trace_expansion_does_not_own_a_phase_result_even_inside_a_prove_plan() {
    assert_eq!(
        background_tool_origin_phase(
            &ModuleRegistry::with_v2_builtins(),
            "trace:expand",
            Some(WorkflowPhase::Prove),
            Some("trace:expand"),
        ),
        None
    );
}

#[test]
fn auxiliary_review_writes_never_replace_the_review_phase_result() {
    let registry = ModuleRegistry::with_v2_builtins();
    for name in [
        "triage:chain-hunt",
        "suppress:add",
        "suppress:list",
        "suppress:remove",
        "findings:dismiss",
        "findings:ground",
        "findings:chains",
        "workspace:import-findings",
    ] {
        assert_eq!(
            background_tool_origin_phase(&registry, name, Some(WorkflowPhase::Review), Some(name),),
            None,
            "{name}"
        );
    }
}

#[test]
fn context_management_never_replaces_the_mapping_phase_result() {
    let registry = ModuleRegistry::with_v2_builtins();
    for name in [
        "threat-model:activate",
        "threat-model:restore",
        "threat-model:adopt",
        "threat-model:revise",
        "threat-model:regenerate",
    ] {
        assert_eq!(
            background_tool_origin_phase(&registry, name, Some(WorkflowPhase::Map), Some(name)),
            None,
            "{name}"
        );
    }
}

#[test]
fn operational_inspection_and_legacy_metadata_never_own_a_map_result() {
    let registry = ModuleRegistry::with_v2_builtins();
    for name in [
        "config:show",
        "router:show",
        "workspace:status",
        "threat-model:methodologies",
        "engagement:aim",
        "coverage:baselines",
        "coverage:recommend",
        "coverage:sweep",
        "module-recommender:recommend",
        "threat-intel:apply",
        "ndiff:fetch-cve",
        "ndiff:extract-fix-pattern",
        "threat-intel:harvest",
        "threat-intel:research",
        "recon:nmap",
        "recon:subdomain",
        "recon:http-fingerprint",
        "codeql:create-db",
    ] {
        assert_eq!(
            background_tool_origin_phase(&registry, name, Some(WorkflowPhase::Map), Some(name)),
            None,
            "{name}"
        );
    }
}
