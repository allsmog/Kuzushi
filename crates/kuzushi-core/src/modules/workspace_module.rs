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
                    .aliases(&["path"])
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
                    .aliases(&["preset"])
                    .choices(&["standard", "whitebox-static"])
                    .default(json!("standard")),
                opt("taskMode", OptionType::Enum, "Task-selection mode.")
                    .aliases(&["task_mode"])
                    .choices(&["auto", "manual"])
                    .default(json!("auto")),
                opt(
                    "tasks",
                    OptionType::StringList,
                    "Manual task allowlist. Use /tasks to edit.",
                )
                .aliases(&["taskIds", "task_ids"]),
                opt(
                    "disabledTasks",
                    OptionType::StringList,
                    "Auto-mode task denylist. Use /tasks to edit.",
                )
                .aliases(&["disabled_tasks"]),
                opt(
                    "severity",
                    OptionType::StringList,
                    "Optional severity filter: critical, high, medium, low, or info.",
                ),
                max_findings_option(40).advanced(),
                opt(
                    "diffBase",
                    OptionType::String,
                    "Git revision for whitebox-static PR diff scope.",
                )
                .aliases(&["diff_base"])
                .advanced(),
                opt(
                    "whiteboxStatic",
                    OptionType::Json,
                    "Enable whitebox-static mode.",
                )
                .aliases(&["whitebox_static"])
                .advanced(),
                opt(
                    "staticProofState",
                    OptionType::String,
                    "Default static proof state for whitebox-static findings.",
                )
                .aliases(&["static_proof_state"])
                .advanced(),
                opt(
                    "proofState",
                    OptionType::String,
                    "Proof state hint rewritten in whitebox-static mode.",
                )
                .aliases(&["proof_state"])
                .advanced(),
                opt(
                    "proofStates",
                    OptionType::StringList,
                    "Proof state hints rewritten in whitebox-static mode.",
                )
                .aliases(&["proof_states"])
                .advanced(),
                opt(
                    "triage",
                    OptionType::Bool,
                    "Run model-backed triage after static scanners.",
                )
                .aliases(&["aiTriage", "ai_triage"])
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
                .aliases(&["auto_patch"])
                .default(json!(false))
                .advanced(),
                opt("patch", OptionType::Bool, "Legacy patch enable flag.")
                    .default(json!(false))
                    .advanced(),
                opt("patching", OptionType::Bool, "Legacy patching enable flag.")
                    .default(json!(false))
                    .advanced(),
                opt("poc", OptionType::Bool, "Legacy PoC enable flag.")
                    .default(json!(false))
                    .advanced(),
                opt("pocHarness", OptionType::Bool, "Generate PoC harnesses.")
                    .aliases(&["poc_harness"])
                    .default(json!(false))
                    .advanced(),
                opt("pocExecution", OptionType::Bool, "Execute generated PoCs.")
                    .aliases(&["poc_execution"])
                    .default(json!(false))
                    .advanced(),
                opt(
                    "dynamicAnalysis",
                    OptionType::Bool,
                    "Allow dynamic analysis.",
                )
                .aliases(&["dynamic_analysis"])
                .default(json!(false))
                .advanced(),
                opt(
                    "cryptoBehavioralTesting",
                    OptionType::Bool,
                    "Allow crypto behavioral testing.",
                )
                .aliases(&["crypto_behavioral_testing"])
                .default(json!(false))
                .advanced(),
                opt(
                    "runtimeExploitabilityClaims",
                    OptionType::Bool,
                    "Allow runtime exploitability claims.",
                )
                .aliases(&["runtime_exploitability_claims"])
                .default(json!(false))
                .advanced(),
                opt(
                    "executionProofStates",
                    OptionType::Bool,
                    "Allow execution proof states.",
                )
                .aliases(&["execution_proof_states"])
                .default(json!(false))
                .advanced(),
                opt("maxIterations", OptionType::Int, "Maximum patch attempts.")
                    .aliases(&["max_iterations"])
                    .default(json!(3))
                    .advanced(),
                opt(
                    "buildCmd",
                    OptionType::String,
                    "Build command used for patch validation.",
                )
                .aliases(&["build_cmd"])
                .advanced(),
                opt(
                    "testCmd",
                    OptionType::String,
                    "Test command used for patch validation.",
                )
                .aliases(&["test_cmd"])
                .advanced(),
                opt(
                    "backend",
                    OptionType::Enum,
                    "Taint IRIS Next backend selector.",
                )
                .choices(&[
                    "auto",
                    "structural",
                    "semgrep",
                    "codeql",
                    "joern",
                    "language",
                ])
                .advanced(),
                opt(
                    "languages",
                    OptionType::StringList,
                    "Language filters for agentic SAST tasks.",
                )
                .advanced(),
                opt(
                    "thinkingLevel",
                    OptionType::String,
                    "Runtime reasoning effort hint.",
                )
                .aliases(&[
                    "thinking_level",
                    "reasoningEffort",
                    "reasoning_effort",
                    "effort",
                ])
                .advanced(),
                opt(
                    "maxCatalogEntries",
                    OptionType::Int,
                    "Maximum taint catalog entries.",
                )
                .aliases(&["maxCwes", "max_catalog_entries", "max_cwes"])
                .advanced(),
                opt(
                    "maxCandidatesPerCwe",
                    OptionType::Int,
                    "Maximum taint candidates per CWE.",
                )
                .aliases(&["max_candidates_per_cwe"])
                .advanced(),
                opt(
                    "maxEvidencePerCwe",
                    OptionType::Int,
                    "Maximum taint evidence items per CWE.",
                )
                .aliases(&["max_evidence_per_cwe"])
                .advanced(),
                opt(
                    "maxFilesPerQuery",
                    OptionType::Int,
                    "Maximum files per taint query.",
                )
                .aliases(&["max_files_per_query"])
                .advanced(),
                opt(
                    "maxSpecsPerCwe",
                    OptionType::Int,
                    "Maximum taint specs per CWE.",
                )
                .aliases(&["max_specs_per_cwe"])
                .advanced(),
                opt(
                    "maxAgentFindings",
                    OptionType::Int,
                    "Maximum agent findings.",
                )
                .aliases(&["max_agent_findings"])
                .advanced(),
                opt(
                    "minEvidenceLevel",
                    OptionType::Enum,
                    "Minimum taint evidence level.",
                )
                .aliases(&["min_evidence_level"])
                .choices(&["path", "linked", "candidate"])
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
                opt(
                    "severity",
                    OptionType::StringList,
                    "Agentic severities to include.",
                )
                .advanced(),
                opt(
                    "excludePatterns",
                    OptionType::StringList,
                    "Repo-relative patterns to exclude from agentic analysis.",
                )
                .aliases(&["exclude_patterns"])
                .advanced(),
                model_option(),
            ],
        )],
        vec![dag("agentic-sast:scan", "findings", &["context:build"])],
    )
}
