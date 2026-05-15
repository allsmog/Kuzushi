use super::*;

pub(crate) fn offense_review_module() -> BuiltinModule {
    builtin_module(
        "offense-review",
        "Offense Review",
        ModuleKind::Offense,
        "Model-backed offensive review tools over existing threat-model artifacts.",
        vec![threat_hunt_tool()],
        vec![dag(
            "offense-review:threat-hunt",
            "findings",
            &["threat-model:build"],
        )],
    )
}

fn threat_hunt_tool() -> ToolDescriptor {
    tool_with_options(
        "offense-review:threat-hunt",
        "Run threat-model-scoped offensive review agents.",
        carlini_threat_hunt_options(),
    )
}
