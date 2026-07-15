use super::*;

pub(crate) fn carlini_threat_hunt_module() -> BuiltinModule {
    builtin_module(
        "carlini-threat-hunt",
        "Carlini Threat Hunt",
        ModuleKind::Offense,
        "Compatibility alias for the offense-review threat-model hunt executor.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Scan,
                RuntimeRequirement::Always,
                FindingStoreRequirement::Required,
            ),
            vec![carlini_threat_hunt_tool()],
        ),
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
        "Compatibility alias for offense-review:threat-hunt; runs scoped agents over the active threat model.",
        carlini_threat_hunt_options(),
    )
    .with_prompt(editable_prompt(
        "offensive review mission",
        "carlini-threat-hunt",
        "run",
        "CARLINI_THREAT_HUNT_PROMPT",
        crate::capabilities::carlini_threat_hunt::DEFAULT_CARLINI_MISSION.to_string(),
    ))
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
        .inline_or_workspace_file()
        .advanced(),
        model_option(),
    ]
}

fn carlini_max_actors_option() -> OptionSpec {
    opt(
        "maxActors",
        OptionType::Int,
        "Maximum threat-model actors to hunt.",
    )
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
    opt(
        "promptContext",
        OptionType::Enum,
        "Actor prompt context variant.",
    )
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
        vec![taint_iris_tool()],
        vec![dag("taint-iris:hunt", "findings", &["context:build"])],
    )
}

fn taint_iris_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "taint-iris:hunt",
        "Compatibility alias for taint-iris-next:hunt in hunt mode.",
        taint_iris_legacy_options(),
    )
    .with_prompt(editable_prompt(
        "taint review instructions",
        "taint-iris",
        "hunt",
        "TAINT_IRIS_PROMPT",
        crate::capabilities::taint_iris_next::taint_iris_next_system_prompt(),
    ))
    .with_policy(workspace_policy(
        ToolPhase::Scan,
        RuntimeRequirement::Always,
        FindingStoreRequirement::Required,
    ))
}

fn taint_iris_legacy_options() -> Vec<OptionSpec> {
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
        .inline_or_workspace_file()
        .advanced(),
        opt("cwe", OptionType::StringList, "Explicit CWE(s) to hunt.").advanced(),
        mcps_option(),
        model_option(),
    ]
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
        taint_iris_next_hunt_tool().with_policy(workspace_policy(
            ToolPhase::Scan,
            RuntimeRequirement::Always,
            FindingStoreRequirement::Required,
        )),
        taint_iris_next_dataflow_plan_tool().with_policy(workspace_policy(
            ToolPhase::Scan,
            RuntimeRequirement::Never,
            FindingStoreRequirement::Optional,
        )),
        taint_iris_next_source_sink_trace_tool().with_policy(workspace_policy(
            ToolPhase::Scan,
            RuntimeRequirement::Never,
            FindingStoreRequirement::Optional,
        )),
        taint_iris_next_finding_review_tool().with_policy(workspace_policy(
            ToolPhase::Scan,
            RuntimeRequirement::Always,
            FindingStoreRequirement::Required,
        )),
        taint_iris_next_catalog_tool().with_policy(ToolPolicy::new(
            ToolPhase::Scan,
            RuntimeRequirement::Always,
            ToolEffect::Read,
            WorkspaceRequirement::Required,
            FindingStoreRequirement::Optional,
        )),
        taint_iris_next_codeql_db_tool().with_policy(workspace_policy(
            ToolPhase::Scan,
            RuntimeRequirement::Always,
            FindingStoreRequirement::Optional,
        )),
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
        "Run the bundled plan-or-hunt taint evidence pipeline.",
        options,
    )
    .with_prompt(editable_prompt(
        "taint review instructions",
        "taint-iris-next",
        "hunt",
        "TAINT_IRIS_NEXT_PROMPT",
        crate::capabilities::taint_iris_next::taint_iris_next_system_prompt(),
    ))
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
    .with_prompt(editable_prompt(
        "taint review instructions",
        "taint-iris-next",
        "finding-review",
        "TAINT_IRIS_NEXT_PROMPT",
        crate::capabilities::taint_iris_next::taint_iris_next_system_prompt(),
    ))
}

fn taint_iris_next_catalog_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "taint-iris-next:catalog",
        "Generate a target-specific CWE catalog tailored to this codebase.",
        vec![
            target_option(),
            model_option(),
            prompt_option(
                "TAINT_IRIS_NEXT_CATALOG_PROMPT",
                "catalog generation",
            ),
        ],
    )
    .with_prompt(editable_prompt(
        "catalog generation",
        "taint-iris-next",
        "catalog",
        "TAINT_IRIS_NEXT_CATALOG_PROMPT",
        crate::capabilities::taint_iris_next::TAINT_IRIS_NEXT_CATALOG_SYSTEM_PROMPT.to_string(),
    ))
}

fn taint_iris_next_codeql_db_tool() -> ToolDescriptor {
    hidden_tool_with_options(
        "taint-iris-next:codeql-db",
        "Build the CodeQL database for taint-iris-next dataflow evidence.",
        vec![
            target_option(),
            model_option(),
            prompt_option(
                "TAINT_IRIS_NEXT_CODEQL_BUILD_PROMPT",
                "CodeQL build planning",
            ),
        ],
    )
    .with_prompt(editable_prompt(
        "CodeQL build planning",
        "taint-iris-next",
        "codeql-db",
        "TAINT_IRIS_NEXT_CODEQL_BUILD_PROMPT",
        crate::capabilities::taint_iris_next::TAINT_IRIS_NEXT_CODEQL_BUILD_SYSTEM_PROMPT
            .to_string(),
    ))
}

fn prompt_option(name: &str, role: &str) -> OptionSpec {
    opt(
        name,
        OptionType::String,
        &format!("System prompt text or workspace-file override for {role}."),
    )
    .inline_or_workspace_file()
    .advanced()
}

fn taint_iris_next_review_options() -> Vec<OptionSpec> {
    let mut options = vec![
        target_option(),
        max_findings_option(20),
        model_option(),
        opt(
            "TAINT_IRIS_NEXT_PROMPT",
            OptionType::String,
            "System prompt text or workspace-file override for taint review.",
        )
        .inline_or_workspace_file()
        .advanced(),
    ];
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
    options.extend(vec![
        cwe_focus_option(),
        discover_signals_option(),
        target_subdir_option(),
    ]);
    options
}

fn taint_iris_next_backend_knobs() -> Vec<OptionSpec> {
    vec![
        evidence_backend_option(),
        catalog_languages_option(),
        max_budget_usd_option(),
        codeql_analyze_timeout_option(),
        min_evidence_level_option(),
    ]
}

fn taint_iris_next_limit_knobs() -> Vec<OptionSpec> {
    vec![
        max_catalog_entries_option(),
        max_candidates_per_cwe_option(),
        max_evidence_per_cwe_option(),
        max_files_per_query_option(),
        max_specs_per_cwe_option(),
        max_agent_findings_option(),
    ]
}

fn evidence_backend_option() -> OptionSpec {
    opt("backend", OptionType::Enum, "Evidence backend selector.")
        .choices(&[
            "auto",
            "structural",
            "semgrep",
            "codeql",
            "joern",
            "language",
        ])
        .default(json!("auto"))
        .advanced()
}

fn catalog_languages_option() -> OptionSpec {
    opt(
        "languages",
        OptionType::StringList,
        "Language filters for catalog ranking.",
    )
    .advanced()
}

fn max_budget_usd_option() -> OptionSpec {
    opt(
        "maxBudgetUsd",
        OptionType::Float,
        "Maximum runtime budget for this hunt.",
    )
    .aliases(&["max_budget_usd"])
    .advanced()
}

fn codeql_analyze_timeout_option() -> OptionSpec {
    opt(
        "codeqlAnalyzeTimeoutMs",
        OptionType::Int,
        "CodeQL analyze timeout in milliseconds.",
    )
    .aliases(&["codeql_analyze_timeout_ms"])
    .default(json!(180000))
    .advanced()
}

fn min_evidence_level_option() -> OptionSpec {
    opt(
        "minEvidenceLevel",
        OptionType::Enum,
        "Minimum evidence level.",
    )
    .aliases(&["min_evidence_level"])
    .choices(&["path", "linked", "candidate"])
    .default(json!("linked"))
    .advanced()
}

fn max_catalog_entries_option() -> OptionSpec {
    opt(
        "maxCatalogEntries",
        OptionType::Int,
        "Maximum catalog entries.",
    )
    .aliases(&["maxCwes", "max_catalog_entries", "max_cwes"])
    .default(json!(24))
    .advanced()
}

fn max_candidates_per_cwe_option() -> OptionSpec {
    opt(
        "maxCandidatesPerCwe",
        OptionType::Int,
        "Maximum candidates per CWE.",
    )
    .aliases(&["max_candidates_per_cwe"])
    .default(json!(2000))
    .advanced()
}

fn max_evidence_per_cwe_option() -> OptionSpec {
    opt(
        "maxEvidencePerCwe",
        OptionType::Int,
        "Maximum evidence items per CWE.",
    )
    .aliases(&["max_evidence_per_cwe"])
    .default(json!(12))
    .advanced()
}

fn max_files_per_query_option() -> OptionSpec {
    opt(
        "maxFilesPerQuery",
        OptionType::Int,
        "Maximum files per query.",
    )
    .aliases(&["max_files_per_query"])
    .default(json!(120))
    .advanced()
}

fn max_specs_per_cwe_option() -> OptionSpec {
    opt("maxSpecsPerCwe", OptionType::Int, "Maximum specs per CWE.")
        .aliases(&["max_specs_per_cwe"])
        .default(json!(16))
        .advanced()
}

fn max_agent_findings_option() -> OptionSpec {
    opt(
        "maxAgentFindings",
        OptionType::Int,
        "Maximum agent findings.",
    )
    .aliases(&["max_agent_findings"])
    .advanced()
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
        systems_hunt_tools(),
        systems_hunt_dag_nodes(),
    )
}

fn systems_hunt_tools() -> Vec<ToolDescriptor> {
    systems_hunt_tool_specs()
        .into_iter()
        .map(|(name, description, runtime_requirement)| {
            systems_hunt_tool(name, description).with_policy(workspace_policy(
                ToolPhase::Scan,
                runtime_requirement,
                FindingStoreRequirement::Required,
            ))
        })
        .collect()
}

fn systems_hunt_tool(name: &str, description: &str) -> ToolDescriptor {
    SYSTEMS_PROMPT_BINDINGS
        .iter()
        .filter(|binding| binding.applies_to(name))
        .fold(
            hidden_tool_with_options(name, description, systems_hunt_options()),
            |tool, binding| tool.with_prompt(binding.prompt()),
        )
}

fn systems_prompt(role: &str, verb: &str, option_key: &str, content: &str) -> PromptSpec {
    editable_prompt(role, "systems-hunt", verb, option_key, content.to_string())
}

struct SystemsPromptBinding {
    tool_name: &'static str,
    role: &'static str,
    verb: &'static str,
    option_key: &'static str,
    content: &'static str,
    include_in_main: bool,
}

impl SystemsPromptBinding {
    fn applies_to(&self, tool_name: &str) -> bool {
        self.tool_name == tool_name
            || (self.include_in_main && tool_name == "systems-hunt:systems-hunt")
    }

    fn prompt(&self) -> PromptSpec {
        systems_prompt(self.role, self.verb, self.option_key, self.content)
    }
}

const SYSTEMS_PROMPT_BINDINGS: [SystemsPromptBinding; 5] = [
    SystemsPromptBinding {
        tool_name: "systems-hunt:systems-invariant-extract",
        role: "invariant extraction",
        verb: "invariants",
        option_key: "SYSTEMS_INVARIANT_PROMPT",
        content: crate::capabilities::systems_hunt::SYSTEMS_INVARIANT_SYSTEM_PROMPT,
        include_in_main: true,
    },
    SystemsPromptBinding {
        tool_name: "systems-hunt:systems-trigger-synth",
        role: "trigger synthesis",
        verb: "triggers",
        option_key: "SYSTEMS_TRIGGER_PROMPT",
        content: crate::capabilities::systems_hunt::SYSTEMS_TRIGGER_SYSTEM_PROMPT,
        include_in_main: true,
    },
    SystemsPromptBinding {
        tool_name: "systems-hunt:systems-hunt",
        role: "vulnerability hunt",
        verb: "hunt",
        option_key: "SYSTEMS_HUNT_PROMPT",
        content: crate::capabilities::systems_hunt::SYSTEMS_HUNT_SYSTEM_PROMPT,
        include_in_main: true,
    },
    SystemsPromptBinding {
        tool_name: "systems-hunt:deep-semantic-cwe-select",
        role: "deep semantic CWE selection",
        verb: "deep-semantic-cwe-select",
        option_key: "SYSTEMS_DEEP_CWE_PROMPT",
        content: crate::capabilities::systems_hunt::DEEP_SEMANTIC_CWE_SYSTEM_PROMPT,
        include_in_main: false,
    },
    SystemsPromptBinding {
        tool_name: "systems-hunt:deep-semantic-hunt",
        role: "deep semantic hunt",
        verb: "deep-semantic-hunt",
        option_key: "SYSTEMS_DEEP_HUNT_PROMPT",
        content: crate::capabilities::systems_hunt::DEEP_SEMANTIC_HUNT_SYSTEM_PROMPT,
        include_in_main: false,
    },
];

fn systems_hunt_tool_specs() -> Vec<(&'static str, &'static str, RuntimeRequirement)> {
    vec![
        (
            "systems-hunt:systems-context-gatherer",
            "Gather ranked systems-programming attack surfaces.",
            RuntimeRequirement::Never,
        ),
        (
            "systems-hunt:systems-invariant-extract",
            "Extract invariants from gathered systems context.",
            RuntimeRequirement::Always,
        ),
        (
            "systems-hunt:systems-trigger-synth",
            "Synthesize trigger hypotheses from systems invariants.",
            RuntimeRequirement::Always,
        ),
        (
            "systems-hunt:systems-hunt",
            "Run the bundled systems invariant and trigger hunt.",
            RuntimeRequirement::Always,
        ),
        (
            "systems-hunt:deep-semantic-cwe-select",
            "Select deep-semantic CWE classes for systems hunting.",
            RuntimeRequirement::Always,
        ),
        (
            "systems-hunt:deep-semantic-hunt",
            "Run deep-semantic systems finding review.",
            RuntimeRequirement::Always,
        ),
    ]
}

fn systems_hunt_options() -> Vec<OptionSpec> {
    let mut options = vec![target_option(), max_findings_option(30)];
    options.extend(systems_hunt_limit_options());
    options.extend(systems_hunt_handoff_options());
    options.extend(systems_hunt_runtime_options());
    options.extend(systems_hunt_prompt_options());
    options.push(model_option());
    options
}

fn systems_hunt_prompt_options() -> Vec<OptionSpec> {
    [
        ("SYSTEMS_INVARIANT_PROMPT", "invariant extraction"),
        ("SYSTEMS_TRIGGER_PROMPT", "trigger synthesis"),
        ("SYSTEMS_HUNT_PROMPT", "vulnerability hunting"),
        ("SYSTEMS_DEEP_CWE_PROMPT", "deep semantic CWE selection"),
        ("SYSTEMS_DEEP_HUNT_PROMPT", "deep semantic hunting"),
    ]
    .into_iter()
    .map(|(name, role)| {
        opt(
            name,
            OptionType::String,
            &format!("System prompt text or workspace-file override for {role}."),
        )
        .inline_or_workspace_file()
        .advanced()
    })
    .collect()
}

fn systems_hunt_limit_options() -> Vec<OptionSpec> {
    let mut options = systems_hunt_numeric_limit_options();
    options.push(include_non_production_option());
    options.push(systems_hunt_artifact_dir_option());
    options
}

fn systems_hunt_numeric_limit_options() -> Vec<OptionSpec> {
    vec![
        int_option(
            "maxSurfaces",
            "Maximum ranked surfaces.",
            50,
            &["max_surfaces"],
        ),
        int_option(
            "maxFiles",
            "Maximum files to inspect.",
            5000,
            &["max_files"],
        ),
        int_option(
            "headBytes",
            "Bytes to read from each file.",
            16384,
            &["head_bytes"],
        ),
        int_option(
            "maxTriggerHypothesesPerSurface",
            "Maximum trigger hypotheses per selected surface.",
            3,
            &["max_trigger_hypotheses_per_surface"],
        ),
        int_option(
            "maxCweClasses",
            "Maximum deep-semantic CWE classes.",
            6,
            &["max_cwe_classes"],
        ),
    ]
}

fn include_non_production_option() -> OptionSpec {
    opt(
        "includeNonProduction",
        OptionType::Bool,
        "Include docs, examples, and tests in surface discovery.",
    )
    .aliases(&["include_non_production"])
    .default(json!(false))
    .advanced()
}

fn systems_hunt_artifact_dir_option() -> OptionSpec {
    opt("artifactDir", OptionType::Path, "Artifact directory.")
        .aliases(&["artifact_dir"])
        .default(json!(".kuzushi/systems-hunt"))
        .state_write()
        .advanced()
}

fn systems_hunt_handoff_options() -> Vec<OptionSpec> {
    vec![
        opt("context", OptionType::Json, "Systems context handoff.")
            .aliases(&["systemsContext", "systems_context"])
            .advanced(),
        opt("systemsInvariants", OptionType::Json, "Invariant handoff.")
            .aliases(&["invariants", "systems_invariants"])
            .advanced(),
        opt("triggers", OptionType::Json, "Trigger handoff.").advanced(),
        opt("cwes", OptionType::Json, "Deep-semantic CWE handoff.").advanced(),
    ]
}

fn systems_hunt_runtime_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "thinkingLevel",
            OptionType::String,
            "Agent reasoning level.",
        )
        .aliases(&["reasoningEffort", "effort"])
        .advanced(),
        opt(
            "whiteboxStatic",
            OptionType::Json,
            "Whitebox static analysis policy.",
        )
        .aliases(&["whitebox_static"])
        .advanced(),
    ]
}

fn int_option(name: &str, description: &str, default: i64, aliases: &[&str]) -> OptionSpec {
    opt(name, OptionType::Int, description)
        .aliases(aliases)
        .default(json!(default))
        .advanced()
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
