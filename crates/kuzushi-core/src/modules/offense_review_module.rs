use super::*;

pub(crate) fn offense_review_module() -> BuiltinModule {
    builtin_module(
        "offense-review",
        "Offense Review",
        ModuleKind::Offense,
        "Model-backed offensive review tools over existing threat-model artifacts.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Hunt,
                RuntimeRequirement::Always,
                FindingStoreRequirement::Required,
            ),
            vec![threat_hunt_tool()],
        ),
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
        "Run bounded offensive review agents over selected actors and threats from the active threat model.",
        carlini_threat_hunt_options(),
    )
}
