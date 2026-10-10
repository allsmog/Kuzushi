use super::*;

pub(crate) fn engagement_module() -> BuiltinModule {
    builtin_module(
        "engagement",
        "Engagement",
        ModuleKind::Intel,
        "Retain legacy target-scoped harness metadata. Use campaign:study for finite investigation plans.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Operate,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            ),
            vec![tool_with_options(
                "engagement:aim",
                "Write legacy engagement/harness.toml metadata. Recorded budget is not enforced and approves no scan work. Use campaign:study for finite work and allowance approval.",
                vec![
                opt(
                    "focus",
                    OptionType::String,
                    "Typed focus intent such as sqli, xss, ssrf, idor, or secrets.",
                ),
                opt(
                    "engines",
                    OptionType::StringList,
                    "Engine/tool ids to include in the harness.",
                ),
                opt(
                    "budget",
                    OptionType::Float,
                    "Legacy USD budget metadata only; this does not enforce a spending limit or approve work.",
                )
                .aliases(&["budgetUsd", "budget_usd"]),
                ],
            ).without_phase_result().with_discovery_maturity(ModuleMaturity::Compatibility)],
        ),
        vec![],
    )
}
