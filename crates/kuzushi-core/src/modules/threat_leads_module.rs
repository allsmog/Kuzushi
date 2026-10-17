use super::*;

pub(crate) fn threat_leads_module() -> BuiltinModule {
    builtin_module(
        "threat-leads",
        "Threat Leads",
        ModuleKind::Intel,
        "Experimental keyword-based context hints from a legacy threat model and bounded repository prefixes.",
        vec![
            tool_with_options(
                "threat-leads:build",
                "Build experimental context hints with disclosed source limits. Creates no accepted Map, scan jobs or findings.",
                vec![target_option(),
                    opt("repairSummary", OptionType::Bool,
                        "Regenerate only Markdown from saved JSON cards. No rescan, context change or model call.").default(json!(false))],
            )
            .with_policy(workspace_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            )).without_phase_result(),
            tool_with_options(
                "threat-leads:read",
                "Read saved experimental context hints and their inspection limits. Current source equivalence is not verified.",
                vec![target_option()],
            )
            .with_policy(tool_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                ToolEffect::Read,
                WorkspaceRequirement::Required,
                FindingStoreRequirement::Optional,
            )).without_phase_result(),
        ],
        vec![dag(
            "threat-leads:build",
            "threat-leads",
            &["threat-model:build"],
        )],
    )
    .labs()
}
