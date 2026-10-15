use super::*;

pub(crate) fn offense_review_module() -> BuiltinModule {
    builtin_module(
        "offense-review",
        "Offense Review",
        ModuleKind::Offense,
        "Model-backed offensive review tools over existing threat-model artifacts.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Scan,
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
        "Experimental actor-guided source observations from threat-model context. Snippet coverage, immutable discovery scope and useful outcomes remain unqualified; this action does not complete Scan.",
        carlini_threat_hunt_options(),
    )
    .with_discovery_maturity(ModuleMaturity::Labs)
    .without_phase_result()
    .with_continuation(ContinuationSupport::Staged)
    .with_prompt(editable_prompt(
        "offensive review mission",
        "offense-review",
        "threat-hunt",
        "CARLINI_THREAT_HUNT_PROMPT",
        crate::capabilities::carlini_threat_hunt::DEFAULT_CARLINI_MISSION.to_string(),
    ))
}
