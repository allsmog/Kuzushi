use super::*;

pub(crate) fn carlini_threat_hunt_module() -> BuiltinModule {
    builtin_module(
        "carlini-threat-hunt",
        "Carlini Threat Hunt",
        ModuleKind::Offense,
        "Hunt threats from the active threat-model document via parallel scoped agents.",
        vec![tool_with_options(
            "carlini-threat-hunt:run",
            "Run threat-model-scoped offensive hunting agents.",
            vec![
                target_option(),
                max_findings_option(20),
                opt(
                    "maxActors",
                    OptionType::Int,
                    "Maximum threat-model actors to hunt.",
                )
                .aliases(&["max_actors"])
                .default(json!(5))
                .advanced(),
                opt("runsPerActor", OptionType::Int, "Runs per selected actor.")
                    .aliases(&["runs_per_actor"])
                    .default(json!(1))
                    .advanced(),
                opt(
                    "promptContext",
                    OptionType::Enum,
                    "Actor prompt context variant.",
                )
                .aliases(&["prompt_context"])
                .choices(&["actor-flows", "actor-flows-threat-titles"])
                .default(json!("actor-flows"))
                .advanced(),
                opt(
                    "debugInlineThreats",
                    OptionType::Bool,
                    "Inline raw threat-model details in actor prompts.",
                )
                .aliases(&["debug_inline_threats"])
                .default(json!(false))
                .advanced(),
                opt(
                    "CARLINI_THREAT_HUNT_PROMPT",
                    OptionType::String,
                    "Prompt text or path override for Carlini threat hunt.",
                )
                .advanced(),
                model_option(),
            ],
        )],
        vec![dag(
            "carlini-threat-hunt:run",
            "findings",
            &["threat-model:build"],
        )],
    )
}

pub(crate) fn taint_iris_module() -> BuiltinModule {
    builtin_module(
        "taint-iris",
        "Taint IRIS",
        ModuleKind::Defense,
        "LLM-driven taint analysis selecting relevant CWEs then tracing source to sink.",
        vec![tool_with_options(
            "taint-iris:hunt",
            "Run IRIS-style taint hunting over the current target.",
            vec![
                target_option(),
                max_findings_option(20),
                opt("maxCwes", OptionType::Int, "Maximum CWEs to select.")
                    .aliases(&["max_cwes"])
                    .advanced(),
                opt(
                    "maxBudgetUsd",
                    OptionType::Float,
                    "Maximum runtime budget for this hunt.",
                )
                .aliases(&["max_budget_usd"])
                .advanced(),
                opt(
                    "TAINT_IRIS_PROMPT",
                    OptionType::String,
                    "Prompt text or path override for taint IRIS.",
                )
                .advanced(),
                opt("cwe", OptionType::StringList, "Explicit CWE(s) to hunt.").advanced(),
                model_option(),
            ],
        )],
        vec![dag("taint-iris:hunt", "findings", &["context:build"])],
    )
}

pub(crate) fn taint_iris_next_module() -> BuiltinModule {
    builtin_module(
        "taint-iris-next",
        "Taint IRIS Next",
        ModuleKind::Defense,
        "Bounded IRIS-style taint analysis with deterministic evidence extraction and agent review.",
        vec![
            tool_with_options(
                "taint-iris-next:hunt",
                "Run the next-generation bounded taint hunting pipeline.",
                vec![
                    target_option(),
                    max_findings_option(20),
                    model_option(),
                    opt("mode", OptionType::Enum, "Taint IRIS Next run mode.")
                        .choices(&["plan", "hunt"])
                        .default(json!("plan")),
                    opt("backend", OptionType::Enum, "Evidence backend selector.")
                        .choices(&["auto", "structural", "semgrep", "codeql", "joern", "language"])
                        .default(json!("auto"))
                        .advanced(),
                    opt(
                        "languages",
                        OptionType::StringList,
                        "Language filters for catalog ranking.",
                    )
                    .advanced(),
                    opt(
                        "maxBudgetUsd",
                        OptionType::Float,
                        "Maximum runtime budget for this hunt.",
                    )
                    .aliases(&["max_budget_usd"])
                    .advanced(),
                    opt("maxCatalogEntries", OptionType::Int, "Maximum catalog entries.")
                        .aliases(&["maxCwes", "max_catalog_entries", "max_cwes"])
                        .default(json!(24))
                        .advanced(),
                    opt(
                        "maxCandidatesPerCwe",
                        OptionType::Int,
                        "Maximum candidates per CWE.",
                    )
                    .aliases(&["max_candidates_per_cwe"])
                    .default(json!(2000))
                    .advanced(),
                    opt("maxEvidencePerCwe", OptionType::Int, "Maximum evidence items per CWE.")
                        .aliases(&["max_evidence_per_cwe"])
                        .default(json!(12))
                        .advanced(),
                    opt("maxFilesPerQuery", OptionType::Int, "Maximum files per query.")
                        .aliases(&["max_files_per_query"])
                        .default(json!(120))
                        .advanced(),
                    opt("maxSpecsPerCwe", OptionType::Int, "Maximum specs per CWE.")
                        .aliases(&["max_specs_per_cwe"])
                        .default(json!(16))
                        .advanced(),
                    opt("maxAgentFindings", OptionType::Int, "Maximum agent findings.")
                        .aliases(&["max_agent_findings"])
                        .advanced(),
                    opt(
                        "codeqlAnalyzeTimeoutMs",
                        OptionType::Int,
                        "CodeQL analyze timeout in milliseconds.",
                    )
                    .aliases(&["codeql_analyze_timeout_ms"])
                    .default(json!(180000))
                    .advanced(),
                    opt("minEvidenceLevel", OptionType::Enum, "Minimum evidence level.")
                        .aliases(&["min_evidence_level"])
                        .choices(&["path", "linked", "candidate"])
                        .default(json!("linked"))
                        .advanced(),
                    mcps_option(),
                    cwe_focus_option(),
                    discover_signals_option(),
                    target_subdir_option(),
                    allow_deterministic_fallback_option(),
                    joern_cpg_option(),
                    joern_per_cwe_timeout_ms_option(),
                    codeql_prewarm_option(),
                    codeql_cache_dir_option(),
                    mcp_tool_timeout_ms_option(),
                    bridge_verbose_option(),
                    bridge_log_path_option(),
                ],
            ),
            tool_with_options(
                "taint-iris-next:catalog",
                "Generate a target-specific CWE catalog tailored to this codebase. \
Persists to <target>/.kuzushi/taint-iris-next-catalog.json; subsequent \
taint-iris-next:hunt runs prefer it over the static built-in catalog.",
                vec![target_option(), model_option()],
            ),
            tool_with_options(
                "taint-iris-next:codeql-db",
                "Build the CodeQL database for the target codebase. The agent \
inspects manifests/build files, picks the correct CodeQL language and \
build command (e.g. `./configure ... && make` for postgres), then runs \
`codeql database create` with tracing. Persists to \
<target>/.kuzushi/codeql-db so subsequent taint-iris-next:hunt runs \
with backend=codeql can immediately consume it.",
                vec![target_option(), model_option()],
            ),
        ],
        vec![
            dag("taint-iris-next:hunt", "findings", &["context:build"]),
            dag("taint-iris-next:catalog", "catalog", &["context:build"]),
            dag("taint-iris-next:codeql-db", "codeql-db", &["context:build"]),
        ],
    )
}

pub(crate) fn systems_hunt_module() -> BuiltinModule {
    hidden_module(
        "systems-hunt",
        "Systems Hunt",
        ModuleKind::Internal,
        "Internal DAG nodes for memory-safety and low-level protocol bug hunting.",
        vec![],
        vec![
            dag(
                "systems-hunt:systems-context-gatherer",
                "context",
                &["context:build"],
            ),
            dag(
                "systems-hunt:systems-invariant-extract",
                "invariants",
                &["systems-hunt:systems-context-gatherer"],
            ),
            dag(
                "systems-hunt:systems-trigger-synth",
                "triggers",
                &["systems-hunt:systems-invariant-extract"],
            ),
            dag(
                "systems-hunt:systems-hunt",
                "findings",
                &["systems-hunt:systems-trigger-synth"],
            ),
            dag(
                "systems-hunt:deep-semantic-cwe-select",
                "cwe-selection",
                &["context:build"],
            ),
            dag(
                "systems-hunt:deep-semantic-hunt",
                "findings",
                &["systems-hunt:deep-semantic-cwe-select"],
            ),
        ],
    )
}
