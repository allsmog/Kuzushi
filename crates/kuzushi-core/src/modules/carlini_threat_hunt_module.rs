use super::*;

pub(crate) fn carlini_threat_hunt_module() -> BuiltinModule {
    builtin_module(
        "carlini-threat-hunt",
        "Carlini Threat Hunt",
        ModuleKind::Offense,
        "Hunt threats from the active threat-model document via parallel scoped agents.",
        vec![carlini_threat_hunt_tool()],
        vec![dag(
            "carlini-threat-hunt:run",
            "findings",
            &["threat-model:build"],
        )],
    )
}

fn carlini_threat_hunt_tool() -> ToolDescriptor {
    tool_with_options(
        "carlini-threat-hunt:run",
        "Run threat-model-scoped offensive hunting agents.",
        carlini_threat_hunt_options(),
    )
}

pub(in crate::modules) fn carlini_threat_hunt_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        max_findings_option(20),
        carlini_max_actors_option(),
        carlini_runs_per_actor_option(),
        carlini_prompt_context_option(),
        carlini_debug_inline_threats_option(),
        opt(
            "CARLINI_THREAT_HUNT_PROMPT",
            OptionType::String,
            "Prompt text or path override for Carlini threat hunt.",
        )
        .advanced(),
        model_option(),
    ]
}

fn carlini_max_actors_option() -> OptionSpec {
    opt("maxActors", OptionType::Int, "Maximum threat-model actors to hunt.")
        .aliases(&["max_actors"])
        .default(json!(5))
        .advanced()
}

fn carlini_runs_per_actor_option() -> OptionSpec {
    opt("runsPerActor", OptionType::Int, "Runs per selected actor.")
        .aliases(&["runs_per_actor"])
        .default(json!(1))
        .advanced()
}

fn carlini_prompt_context_option() -> OptionSpec {
    opt("promptContext", OptionType::Enum, "Actor prompt context variant.")
        .aliases(&["prompt_context"])
        .choices(&["actor-flows", "actor-flows-threat-titles"])
        .default(json!("actor-flows"))
        .advanced()
}

fn carlini_debug_inline_threats_option() -> OptionSpec {
    opt(
        "debugInlineThreats",
        OptionType::Bool,
        "Inline raw threat-model details in actor prompts.",
    )
        .aliases(&["debug_inline_threats"])
        .default(json!(false))
        .advanced()
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
        taint_iris_next_tools(),
        vec![
            dag("taint-iris-next:hunt", "findings", &["context:build"]),
            dag("taint-iris-next:catalog", "catalog", &["context:build"]),
            dag("taint-iris-next:codeql-db", "codeql-db", &["context:build"]),
        ],
    )
}

fn taint_iris_next_tools() -> Vec<ToolDescriptor> {
    vec![
        taint_iris_next_hunt_tool(),
        taint_iris_next_dataflow_plan_tool(),
        taint_iris_next_source_sink_trace_tool(),
        taint_iris_next_finding_review_tool(),
        taint_iris_next_catalog_tool(),
        taint_iris_next_codeql_db_tool(),
    ]
}

fn taint_iris_next_hunt_tool() -> ToolDescriptor {
    let mut options = taint_iris_next_review_options();
    options.push(
        opt("mode", OptionType::Enum, "Taint IRIS Next run mode.")
            .choices(&["plan", "hunt"])
            .default(json!("plan")),
    );
    hidden_tool_with_options(
        "taint-iris-next:hunt",
        "Run the legacy bundled plan-or-hunt pipeline.",
        options,
    )
}

fn taint_iris_next_dataflow_plan_tool() -> ToolDescriptor {
    tool_with_options(
        "taint-iris-next:dataflow-plan",
        "Build a deterministic CWE and dataflow evidence plan without agent review.",
        taint_iris_next_planning_options(),
    )
}

fn taint_iris_next_source_sink_trace_tool() -> ToolDescriptor {
    tool_with_options(
        "taint-iris-next:source-sink-trace",
        "Extract deterministic source/sink candidates and linked stories.",
        taint_iris_next_planning_options(),
    )
}

fn taint_iris_next_finding_review_tool() -> ToolDescriptor {
    tool_with_options(
        "taint-iris-next:finding-review",
        "Review deterministic source/sink evidence with one scoped agent session.",
        taint_iris_next_review_options(),
    )
}

fn taint_iris_next_catalog_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "taint-iris-next:catalog",
        "Generate a target-specific CWE catalog tailored to this codebase.",
        vec![target_option(), model_option()],
    )
}

fn taint_iris_next_codeql_db_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "taint-iris-next:codeql-db",
        "Build the CodeQL database for taint-iris-next dataflow evidence.",
        vec![target_option(), model_option()],
    )
}

fn taint_iris_next_review_options() -> Vec<OptionSpec> {
    let mut options = vec![target_option(), max_findings_option(20), model_option()];
    options.extend(taint_iris_next_planning_knobs());
    options.extend(taint_iris_next_agent_knobs());
    options
}

fn taint_iris_next_planning_options() -> Vec<OptionSpec> {
    let mut options = vec![target_option()];
    options.extend(taint_iris_next_planning_knobs());
    options
}

fn taint_iris_next_planning_knobs() -> Vec<OptionSpec> {
    let mut options = taint_iris_next_backend_knobs();
    options.extend(taint_iris_next_limit_knobs());
    options.extend(vec![cwe_focus_option(), discover_signals_option(), target_subdir_option()]);
    options
}

fn taint_iris_next_backend_knobs() -> Vec<OptionSpec> {
    vec![
        opt("backend", OptionType::Enum, "Evidence backend selector.")
            .choices(&["auto", "structural", "semgrep", "codeql", "joern", "language"])
            .default(json!("auto"))
            .advanced(),
        opt("languages", OptionType::StringList, "Language filters for catalog ranking.")
            .advanced(),
        opt("maxBudgetUsd", OptionType::Float, "Maximum runtime budget for this hunt.")
            .aliases(&["max_budget_usd"])
            .advanced(),
        opt("codeqlAnalyzeTimeoutMs", OptionType::Int, "CodeQL analyze timeout in milliseconds.")
            .aliases(&["codeql_analyze_timeout_ms"])
            .default(json!(180000))
            .advanced(),
        opt("minEvidenceLevel", OptionType::Enum, "Minimum evidence level.")
            .aliases(&["min_evidence_level"])
            .choices(&["path", "linked", "candidate"])
            .default(json!("linked"))
            .advanced(),
    ]
}

fn taint_iris_next_limit_knobs() -> Vec<OptionSpec> {
    vec![
        opt("maxCatalogEntries", OptionType::Int, "Maximum catalog entries.")
            .aliases(&["maxCwes", "max_catalog_entries", "max_cwes"])
            .default(json!(24))
            .advanced(),
        opt("maxCandidatesPerCwe", OptionType::Int, "Maximum candidates per CWE.")
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
    ]
}

fn taint_iris_next_agent_knobs() -> Vec<OptionSpec> {
    vec![
        mcps_option(),
        allow_deterministic_fallback_option(),
        joern_cpg_option(),
        joern_per_cwe_timeout_ms_option(),
        codeql_prewarm_option(),
        codeql_cache_dir_option(),
        mcp_tool_timeout_ms_option(),
        bridge_verbose_option(),
        bridge_log_path_option(),
    ]
}

pub(crate) fn systems_hunt_module() -> BuiltinModule {
    hidden_module(
        "systems-hunt",
        "Systems Hunt",
        ModuleKind::Internal,
        "Internal DAG nodes for memory-safety and low-level protocol bug hunting.",
        vec![],
        systems_hunt_dag_nodes(),
    )
}

fn systems_hunt_dag_nodes() -> Vec<DagNodeDescriptor> {
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
    ]
}
