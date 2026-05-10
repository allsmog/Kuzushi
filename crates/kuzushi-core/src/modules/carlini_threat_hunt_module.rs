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
            vec![target_option(), max_findings_option(20), model_option()],
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
            vec![target_option(), max_findings_option(20), model_option()],
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
                    mcps_option(),
                    cwe_focus_option(),
                    discover_signals_option(),
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
            dag(
                "taint-iris-next:catalog",
                "catalog",
                &["context:build"],
            ),
            dag(
                "taint-iris-next:codeql-db",
                "codeql-db",
                &["context:build"],
            ),
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
