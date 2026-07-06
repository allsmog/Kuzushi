use super::*;

pub(crate) fn engagement_module() -> BuiltinModule {
    builtin_module(
        "engagement",
        "Engagement",
        ModuleKind::Intel,
        "Seed target-scoped engagement planning artifacts.",
        vec![tool_with_options(
            "engagement:aim",
            "Seed engagement/harness.toml with focus, engine, and budget metadata.",
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
                    "Optional USD budget for the engagement harness.",
                )
                .aliases(&["budgetUsd", "budget_usd"]),
            ],
        )],
        vec![],
    )
}
