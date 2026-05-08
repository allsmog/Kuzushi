use super::prelude::*;
use super::*;

pub(crate) fn workspace_module() -> BuiltinModule {
    builtin_module(
        "workspace",
        "Workspace",
        ModuleKind::Intel,
        "Report target and state paths.",
        vec![
            tool(
                "workspace:status",
                "Show current target and state paths.",
            ),
            tool_with_options(
                "workspace:export-findings",
                "Export persisted workspace findings to a local JSON or JSONL file.",
                vec![
                    opt(
                        "output",
                        OptionType::Path,
                        "Output path for exported findings. Relative paths resolve under the workspace root.",
                    )
                    .required(),
                    opt("format", OptionType::Enum, "Export format.")
                        .choices(&["json", "jsonl"]),
                ],
            ),
        ],
        vec![],
    )
}

pub(crate) fn sast_module() -> BuiltinModule {
    builtin_module(
        "sast",
        "SAST Pipeline",
        ModuleKind::Defense,
        "Full SAST pipeline: context, scanners, AI triage, verification, patch, and report.",
        vec![tool_with_options(
            "sast:scan",
            "Run the full SAST pipeline for the current target.",
            vec![
                opt("mode", OptionType::Enum, "Analysis mode or preset.")
                    .choices(&["standard", "whitebox-static"])
                    .default(json!("standard")),
                opt("taskMode", OptionType::Enum, "Task-selection mode.")
                    .choices(&["auto", "manual"])
                    .default(json!("auto")),
                opt(
                    "tasks",
                    OptionType::StringList,
                    "Manual task allowlist. Use /tasks to edit.",
                ),
                opt(
                    "disabledTasks",
                    OptionType::StringList,
                    "Auto-mode task denylist. Use /tasks to edit.",
                ),
                opt(
                    "severity",
                    OptionType::StringList,
                    "Optional severity filter: critical, high, medium, low, or info.",
                ),
                opt(
                    "diffBase",
                    OptionType::String,
                    "Git revision for whitebox-static PR diff scope.",
                )
                .advanced(),
                opt(
                    "triage",
                    OptionType::Bool,
                    "Run model-backed triage after static scanners.",
                )
                .default(json!(false)),
                opt(
                    "verify",
                    OptionType::Bool,
                    "Run exploitability verification after triage.",
                )
                .default(json!(false))
                .advanced(),
                opt(
                    "autoPatch",
                    OptionType::Bool,
                    "Generate patches for verified true positives.",
                )
                .default(json!(false))
                .advanced(),
                model_option(),
            ],
        )],
        vec![dag("sast:scan", "report", &["context:build"])],
    )
}

pub(crate) fn agentic_sast_module() -> BuiltinModule {
    builtin_module(
        "agentic-sast",
        "Agentic SAST",
        ModuleKind::Defense,
        "LLM-driven detectors that reason about data flow and intent rather than pattern-match.",
        vec![tool_with_options(
            "agentic-sast:scan",
            "Run agentic SAST detectors for the current target.",
            vec![
                target_option(),
                max_findings_option(40),
                opt("passes", OptionType::Int, "Agentic review pass count.").default(json!(1)),
                model_option(),
            ],
        )],
        vec![dag("agentic-sast:scan", "findings", &["context:build"])],
    )
}
