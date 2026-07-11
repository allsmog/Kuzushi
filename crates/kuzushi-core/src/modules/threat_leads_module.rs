use super::*;

pub(crate) fn threat_leads_module() -> BuiltinModule {
    builtin_module(
        "threat-leads",
        "Threat Leads",
        ModuleKind::Intel,
        "Build threat-to-code lead cards from threat-model, X-Ray, and bounded source evidence.",
        vec![
            tool_with_options(
                "threat-leads:build",
                "Build threat-to-code lead cards for downstream hunt modules.",
                vec![target_option()],
            )
            .with_policy(workspace_policy(
                ToolPhase::Confirm,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            )),
            tool_with_options(
                "threat-leads:read",
                "Read the current threat-leads artifact.",
                vec![target_option()],
            )
            .with_policy(tool_policy(
                ToolPhase::Confirm,
                RuntimeRequirement::Never,
                ToolEffect::Read,
                WorkspaceRequirement::Required,
                FindingStoreRequirement::Optional,
            )),
        ],
        vec![dag(
            "threat-leads:build",
            "threat-leads",
            &["threat-model:build", "x-ray:x-ray"],
        )],
    )
}
