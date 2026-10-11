use super::*;

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
        "suppress:add",
        "suppress:list",
        "suppress:remove",
        "findings:dismiss",
        "findings:ground",
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
    ] {
        assert_eq!(
            background_tool_origin_phase(&registry, name, Some(WorkflowPhase::Map), Some(name)),
            None,
            "{name}"
        );
    }
}
