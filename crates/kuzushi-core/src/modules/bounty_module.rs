use super::*;

/// Bug-bounty workflow surface (M2 §2.3). Two tools: import HAR and
/// import Burp Suite XML, both of which materialise into the findings
/// table with `http-request` evidence so the rest of the triage/verify
/// pipeline can see them.
pub(crate) fn bounty_module() -> BuiltinModule {
    builtin_module(
        "bounty",
        "Bounty",
        ModuleKind::Intel,
        "Bug-bounty intake: import Burp Suite XML and HAR captures into the findings ledger as http-request evidence.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Map,
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
        ),
        vec![],
    )
}
