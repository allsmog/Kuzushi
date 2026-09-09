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
