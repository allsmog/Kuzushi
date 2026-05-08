use super::*;

pub(in crate::modules) fn module() -> BuiltinModule {
    builtin_module(
        "prompt-armor",
        "PromptArmor",
        ModuleKind::Offense,
        "LLM red-team wrapper around promptarmor-plugin attack suites and mutations.",
        vec![
            tool_with_options(
                "prompt-armor:scan",
                "Run a full LLM red-team scan.",
                vec![
                    target_option(),
                    opt(
                        "authorized",
                        OptionType::Bool,
                        "Confirm authorization to test.",
                    )
                    .default(json!(false)),
                    opt(
                        "payload",
                        OptionType::String,
                        "Single attack payload to test.",
                    )
                    .evasion(),
                    model_option(),
                ],
            ),
            tool_with_options(
                "prompt-armor:analyze",
                "Statically analyze prompt-injection surface.",
                vec![target_option(), model_option()],
            ),
            tool_with_options(
                "prompt-armor:attack",
                "Send a single authorized attack payload and judge the response.",
                vec![
                    target_option(),
                    opt(
                        "authorized",
                        OptionType::Bool,
                        "Confirm authorization to test.",
                    )
                    .default(json!(false)),
                    opt(
                        "payload",
                        OptionType::String,
                        "Single attack payload to test.",
                    )
                    .evasion(),
                    model_option(),
                ],
            ),
            tool_with_options(
                "prompt-armor:diff",
                "Diff two prior red-team runs.",
                vec![
                    opt("runA", OptionType::Path, "Baseline prompt-armor run path.").required(),
                    opt(
                        "runB",
                        OptionType::Path,
                        "Comparison prompt-armor run path.",
                    )
                    .required(),
                ],
            ),
            tool_with_options(
                "prompt-armor:report",
                "Generate a consolidated red-team report.",
                vec![target_option()],
            ),
            tool_with_options(
                "prompt-armor:config",
                "Inspect or scaffold promptarmor.yaml.",
                vec![target_option()],
            ),
        ],
        vec![dag("prompt-armor:scan", "findings", &["context:build"])],
    )
}
