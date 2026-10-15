use super::*;

/// Recorded HAR and Burp request evidence for operator inspection. Imports
/// preserve external observations without claiming local scan coverage.
pub(crate) fn bounty_module() -> BuiltinModule {
    builtin_module(
        "bounty",
        "Bounty",
        ModuleKind::Intel,
        "Bug-bounty intake: import Burp Suite XML and HAR captures into the findings ledger as http-request evidence.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Scan,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            ),
            vec![
            tool_with_options(
                "bounty:import-har",
                "Import a HAR capture (Burp/Chrome DevTools/Charles) as Finding evidence.",
                vec![opt("path", OptionType::Path, "Path to the .har file.")
                    .external_read()
                    .required()],
            ),
            tool_with_options(
                "bounty:import-burp",
                "Import a Burp Suite proxy/sitemap XML export as Finding evidence.",
                vec![opt("path", OptionType::Path, "Path to the Burp XML file.")
                    .external_read()
                    .required()],
            ),
            ],
        ).into_iter().map(ToolDescriptor::without_phase_result).collect(),
        vec![],
    )
}
