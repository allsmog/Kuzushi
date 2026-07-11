use super::*;

pub(crate) fn uaf_hunt_module() -> BuiltinModule {
    builtin_module(
        "uaf-hunt",
        "Use-After-Free Hunt",
        ModuleKind::Offense,
        "Find use-after-free, double-free, and post-free dereferences in C/C++ code \
         by walking the clang call graph between allocation and free sites.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Hunt,
                RuntimeRequirement::Always,
                FindingStoreRequirement::Required,
            ),
            vec![tool_with_options(
                "uaf-hunt:hunt",
                "Run the call-graph-augmented agent to hunt CWE-416 / CWE-415 / CWE-476 patterns. \
                 JSON-only input fields (not declared as scalar options): \
                 `allocFreePairs` and `extraAllocFreePairs` are arrays of \
                 {\"alloc\":\"...\",\"free\":\"...\"} entries; allocFreePairs replaces the \
                 defaults, extraAllocFreePairs appends to them.",
                uaf_hunt_options(),
            )],
        ),
        // Opt-in only: do not auto-run inside sast:scan's DAG. Operators
        // invoke uaf-hunt explicitly when they want call-graph-augmented
        // analysis (it requires compile_commands.json + clangd).
        vec![],
    )
}

fn uaf_hunt_options() -> Vec<OptionSpec> {
    vec![
        target_option(),
        max_findings_option(30),
        opt(
            "compileCommandsPath",
            OptionType::Path,
            "Workspace compile_commands.json path.",
        )
        .workspace_read(),
        opt("maxAgentSteps", OptionType::Int, "Maximum tool-loop steps.").advanced(),
        opt("clangTimeoutSecs", OptionType::Int, "Per-clang-call timeout.").advanced(),
        model_option(),
    ]
}
