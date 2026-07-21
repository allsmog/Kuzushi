use super::*;

pub(crate) fn workspace_module() -> BuiltinModule {
    builtin_module(
        "workspace",
        "Workspace",
        ModuleKind::Intel,
        "Report target and state paths.",
        vec![
            workspace_status_tool().with_policy(read_policy(
                ToolPhase::Map,
                WorkspaceRequirement::Optional,
            )),
            workspace_export_findings_tool().with_policy(target_write_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            )),
            workspace_import_findings_tool().with_policy(target_write_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            )),
        ],
        vec![],
    )
}

fn workspace_import_findings_tool() -> ToolDescriptor {
    tool_with_options(
        "workspace:import-findings",
        "Backfill the findings ledger from an external findings JSONL export \
         (one row per finding: file/line/title plus optional severity, class, \
         CWE, and verdict) so dedupe and triage see prior history.",
        vec![
            opt("path", OptionType::Path, "Path to the findings JSONL file.")
                .external_read()
                .required()
                .aliases(&["findingsPath", "findings_path", "ledger", "corpus"]),
            opt(
                "tool",
                OptionType::String,
                "Tool label recorded on each imported finding.",
            )
            .default(json!("external-ledger")),
        ],
    )
}

fn workspace_status_tool() -> ToolDescriptor {
    tool(
        "workspace:status",
        "Show current target and state paths.",
    )
}

fn workspace_export_findings_tool() -> ToolDescriptor {
    tool_with_options(
        "workspace:export-findings",
        "Export persisted workspace findings to a local file or markdown bundle directory. \
         Supports JSON, JSONL, SARIF 2.1.0, CSV, and a multi-file markdown bundle.",
        workspace_export_findings_options(),
    )
}

fn workspace_export_findings_options() -> Vec<OptionSpec> {
    vec![
        workspace_export_output_option(),
        opt("format", OptionType::Enum, "Export format.")
            .choices(&["json", "jsonl", "sarif", "csv", "markdown-bundle"]),
        opt(
            "completeness",
            OptionType::Enum,
            "Findings to include by review completeness.",
        )
        .aliases(&["reviewCompleteness", "review_completeness"])
        .choices(&["all", "open", "complete"])
        .default(json!("all")),
        opt(
            "allowEmpty",
            OptionType::Bool,
            "Permit writing a valid metadata-only export when no findings match.",
        )
        .aliases(&["allow_empty"])
        .default(json!(false)),
    ]
}

fn workspace_export_output_option() -> OptionSpec {
    opt(
        "output",
        OptionType::Path,
        "Output path for exported findings. Relative paths resolve under the workspace root. \
         Use a directory path when format=markdown-bundle.",
    )
    .aliases(&["path"])
    .target_write()
    .required()
}

pub(crate) fn sast_module() -> BuiltinModule {
    builtin_module(
        "sast",
        "SAST Pipeline",
        ModuleKind::Defense,
        "Full SAST pipeline: context, scanners, AI triage, verification, patch, and report.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Scan,
                RuntimeRequirement::InputAware,
                FindingStoreRequirement::Required,
            ),
            vec![sast_scan_tool()],
        ),
        vec![dag("sast:scan", "report", &["context:build"])],
    )
}

fn sast_scan_tool() -> ToolDescriptor {
    tool_with_options(
        "sast:scan",
        "Run the full SAST pipeline for the current target.",
        sast_scan_options(),
    )
    .with_prompt(editable_prompt(
        "triage instructions",
        "sast",
        "triage",
        "TRIAGE_PROMPT",
        crate::runtime::DEFAULT_TRIAGE_PROMPT.to_string(),
    ))
    .with_prompt(editable_prompt(
        "verification instructions",
        "sast",
        "verify",
        "VERIFY_PROMPT",
        crate::verification::DEFAULT_VERIFY_PROMPT.to_string(),
    ))
}

fn sast_scan_options() -> Vec<OptionSpec> {
    let mut options = Vec::new();
    options.extend(sast_selection_options());
    options.extend(sast_whitebox_options());
    options.extend(sast_post_processing_options());
    options.extend(sast_patch_options());
    options.extend(sast_agent_policy_options());
    options.extend(sast_agent_runtime_options());
    options.extend(sast_taint_backend_options());
    options.extend(sast_taint_cwe_limit_options());
    options.extend(sast_taint_output_limit_options());
    options.push(mcps_option());
    options.push(model_option());
    options
}

fn sast_selection_options() -> Vec<OptionSpec> {
    let mut options = vec![
        opt("mode", OptionType::Enum, "Analysis mode or preset.")
            .aliases(&["preset"])
            .choices(&["standard", "whitebox-static"])
            .default(json!("standard")),
        opt("taskMode", OptionType::Enum, "Task-selection mode.")
            .aliases(&["task_mode"])
            .choices(&["auto", "manual"])
            .default(json!("auto")),
    ];
    options.extend(sast_manual_task_options());
    options.extend(sast_run_filter_options());
    options.push(max_findings_option(40).advanced());
    options
}

fn sast_manual_task_options() -> Vec<OptionSpec> {
    vec![
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
    ]
}

fn sast_run_filter_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "runId",
            OptionType::String,
            "Internal run artifact id supplied by scan-mode dispatch.",
        )
        .aliases(&["run_id"])
        .advanced(),
        opt(
            "severity",
            OptionType::StringList,
            "Optional severity filter: critical, high, medium, low, or info.",
        ),
        opt(
            "paths",
            OptionType::StringList,
            "Optional workspace-relative path roots to scan.",
        )
        .aliases(&["includePaths", "include_paths"]),
        opt(
            "shard",
            OptionType::String,
            "Shard-manifest name that resolved this scan's `paths` scope \
             (set by `kuzushi scan --shard`); recorded in run provenance.",
        )
        .advanced(),
    ]
}

fn sast_whitebox_options() -> Vec<OptionSpec> {
    vec![
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
    ]
}

fn sast_post_processing_options() -> Vec<OptionSpec> {
    let mut options = sast_triage_options();
    options.extend(sast_verification_options());
    options.extend(sast_auto_patch_options());
    options
}

fn sast_triage_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "triage",
            OptionType::Bool,
            "Run model-backed triage after static scanners.",
        )
        .aliases(&["aiTriage", "ai_triage"])
        .default(json!(false)),
        opt(
            "TRIAGE_PROMPT",
            OptionType::String,
            "Prompt text or path override forwarded to scan triage.",
        )
        .inline_or_workspace_file()
        .advanced(),
    ]
}

fn sast_verification_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "verify",
            OptionType::Bool,
            "Run exploitability verification after triage.",
        )
        .default(json!(false))
        .advanced(),
        opt(
            "verifyWhen",
            OptionType::String,
            "Verification filter such as severity>=high or all.",
        )
        .aliases(&["verify_when"])
        .advanced(),
        opt(
            "verifyMax",
            OptionType::Int,
            "Maximum number of triaged findings to verify.",
        )
        .aliases(&["verify_max"])
        .advanced(),
        opt(
            "verifyVotes",
            OptionType::Int,
            "Minimum corroborating source count required before verification.",
        )
        .aliases(&["verify_votes"])
        .advanced(),
        opt(
            "VERIFY_PROMPT",
            OptionType::String,
            "Prompt text or path override forwarded to scan verification.",
        )
        .inline_or_workspace_file()
        .advanced(),
    ]
}

fn sast_auto_patch_options() -> Vec<OptionSpec> {
    vec![opt(
        "autoPatch",
        OptionType::Bool,
        "Generate patches for verified true positives.",
    )
    .aliases(&["auto_patch"])
    .default(json!(false))
    .advanced()]
}

fn sast_patch_options() -> Vec<OptionSpec> {
    vec![
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
    ]
}

fn sast_agent_policy_options() -> Vec<OptionSpec> {
    vec![
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
    ]
}

fn sast_agent_runtime_options() -> Vec<OptionSpec> {
    vec![
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
    ]
}

fn sast_taint_backend_options() -> Vec<OptionSpec> {
    vec![opt(
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
    .advanced()]
}

fn sast_taint_cwe_limit_options() -> Vec<OptionSpec> {
    vec![
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
    ]
}

fn sast_taint_output_limit_options() -> Vec<OptionSpec> {
    vec![
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
    ]
}

pub(crate) fn agentic_sast_module() -> BuiltinModule {
    builtin_module(
        "agentic-sast",
        "Agentic SAST",
        ModuleKind::Defense,
        "LLM-driven detectors that reason about data flow and intent rather than pattern-match.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Scan,
                RuntimeRequirement::Always,
                FindingStoreRequirement::Required,
            ),
            vec![agentic_sast_scan_tool()],
        ),
        vec![dag("agentic-sast:scan", "findings", &["context:build"])],
    )
}

fn agentic_sast_scan_tool() -> ToolDescriptor {
    tool_with_options(
        "agentic-sast:scan",
        "Run agentic SAST detectors for the current target.",
        agentic_sast_scan_options(),
    )
    .with_prompt(editable_prompt(
        "scan instructions",
        "agentic-sast",
        "scan",
        "AGENTIC_SAST_PROMPT",
        crate::capabilities::agentic_sast::agentic_sast_system_prompt_text(),
    ))
}

fn agentic_sast_scan_options() -> Vec<OptionSpec> {
    let mut options = vec![
        target_option(),
        max_findings_option(40),
        opt("passes", OptionType::Int, "Agentic review pass count.").default(json!(1)),
        agentic_sast_mode_option(),
        opt(
            "AGENTIC_SAST_PROMPT",
            OptionType::String,
            "Agentic SAST instruction template or workspace file.",
        )
        .inline_or_workspace_file()
        .advanced(),
    ];
    options.extend(sast_whitebox_options());
    options.extend(agentic_sast_filter_options());
    options.extend(agentic_sast_chunk_options());
    options.extend(agentic_sast_auto_triage_options());
    options.push(model_option());
    options
}

fn agentic_sast_mode_option() -> OptionSpec {
    opt("mode", OptionType::Enum, "Agentic SAST analysis mode.")
        .aliases(&["preset"])
        .choices(&["standard", "whitebox-static"])
        .default(json!("standard"))
        .advanced()
}

fn agentic_sast_filter_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "severity",
            OptionType::StringList,
            "Agentic severities to include.",
        )
        .advanced(),
        opt(
            "includePatterns",
            OptionType::StringList,
            "Repo-relative patterns to include in agentic analysis.",
        )
        .aliases(&["include_patterns"])
        .advanced(),
        opt(
            "excludePatterns",
            OptionType::StringList,
            "Repo-relative patterns to exclude from agentic analysis.",
        )
        .aliases(&["exclude_patterns"])
        .advanced(),
    ]
}

fn agentic_sast_chunk_options() -> Vec<OptionSpec> {
    let mut options = vec![
        opt("strategy", OptionType::Enum, "Agentic SAST strategy.")
            .choices(&["standard", "chunked"])
            .default(json!("standard"))
            .advanced(),
        opt(
            "language",
            OptionType::Enum,
            "Chunked strategy language prompt.",
        )
        .choices(&["c", "unknown"])
        .advanced(),
        opt(
            "maxTokensPerChunk",
            OptionType::Int,
            "Chunked strategy token budget per chunk.",
        )
        .advanced(),
        opt(
            "depositUsdPerChunk",
            OptionType::Float,
            "Chunked strategy spend deposit per chunk.",
        )
        .advanced(),
    ];
    options.extend(agentic_sast_chunk_execution_options());
    options
}

fn agentic_sast_chunk_execution_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "dryRun",
            OptionType::Bool,
            "Plan chunked strategy cost without model calls.",
        )
        .advanced(),
        opt("scopeFile", OptionType::Path, "Chunked strategy scope file.")
            .workspace_read()
            .advanced(),
        opt(
            "failedChunkIds",
            OptionType::String,
            "Chunked strategy retry filter.",
        )
        .advanced(),
        opt(
            "budgetUsd",
            OptionType::Float,
            "Chunked strategy per-run USD ceiling; stops dispatching new \
             chunks gracefully and keeps completed-chunk findings.",
        )
        .advanced(),
    ]
}

fn agentic_sast_auto_triage_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "autoTriage",
            OptionType::Bool,
            "Run deep triage on HIGH+CRITICAL chunked findings.",
        )
        .advanced(),
        opt(
            "autoTriageMaxSteps",
            OptionType::Int,
            "Step budget per chunked auto-triage pass.",
        )
        .advanced(),
        opt(
            "autoTriageDepositUsd",
            OptionType::Float,
            "Spend deposit per chunked auto-triage pass.",
        )
        .advanced(),
    ]
}
