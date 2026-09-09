use super::*;

pub(crate) fn trace_module() -> BuiltinModule {
    builtin_module(
        "trace",
        "Trace",
        ModuleKind::Offense,
        "Operator-requested data-flow trace expansion that appends static evidence around a finding.",
        vec![tool_with_options(
            "trace:expand",
            "Read source to expand a finding's recorded data flow and save supporting evidence.",
            trace_expand_options(),
        )
        .with_policy(workspace_policy(
            ToolPhase::Prove,
            RuntimeRequirement::Always,
            FindingStoreRequirement::Required,
        ))
        .without_phase_result()],
        vec![],
    )
}

fn trace_expand_options() -> Vec<OptionSpec> {
    vec![
        fingerprint_option(),
        trace_instruction_option(),
        trace_node_ids_option(),
        model_option(),
    ]
}

fn trace_instruction_option() -> OptionSpec {
    opt(
        "instruction",
        OptionType::String,
        "Operator instruction describing where the trace should deepen.",
    )
    .aliases(&["operatorInstruction"])
}

fn trace_node_ids_option() -> OptionSpec {
    opt(
        "nodeIds",
        OptionType::StringList,
        "Node ids of the currently rendered path, so the expansion extends rather than restates it.",
    )
    .aliases(&["currentPathNodeIds"])
    .advanced()
}
