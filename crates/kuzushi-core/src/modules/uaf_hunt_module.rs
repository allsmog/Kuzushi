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
                ToolPhase::Scan,
                RuntimeRequirement::Always,
                FindingStoreRequirement::Required,
            ),
            vec![tool_with_options(
                "uaf-hunt:hunt",
                "Run the call-graph-augmented agent to hunt CWE-416 / CWE-415 / CWE-476 patterns. \
                 `allocFreePairs` and `extraAllocFreePairs` are declared JSON arrays of \
                 {\"alloc\":\"...\",\"free\":\"...\"} entries; allocFreePairs replaces the \
                 defaults, extraAllocFreePairs appends to them. Experimental auxiliary Scan work;                  whole-repository analysis only. Review candidates and coverage before further work.",
                uaf_hunt_options(),
            ).with_discovery_maturity(ModuleMaturity::Labs).without_phase_result()],
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
        max_findings_option(30).integer_range(1, 500),
        opt(
            "compileCommandsPath",
            OptionType::Path,
            "Workspace compiler database JSON. At most 8 MiB and 100000 commands; captured before navigation. Custom filenames are supported.",
        )
        .workspace_read(),
        opt(
            "allocFreePairs",
            OptionType::Json,
            "Replacement allocation/free pairs as an array of {alloc, free} objects. Non-empty; takes precedence over extraAllocFreePairs.",
        )
        .editable_json()
        .advanced(),
        opt(
            "extraAllocFreePairs",
            OptionType::Json,
            "Additional allocation/free pairs as an array of {alloc, free} objects. Extends the defaults when allocFreePairs is omitted.",
        )
        .editable_json()
        .advanced(),
        opt("maxAgentSteps", OptionType::Int, "Maximum model/tool-loop steps. Every provider request still consumes the approved investigation allowance.")
            .default(json!(120)).aliases(&["max_agent_steps"]).integer_range(1, 400),
        opt("clangTimeoutSecs", OptionType::Int, "Deadline in seconds for initialization and each clang request, including pipe writes and skipped messages. Cancellation stops the helper; transport failure never restarts it automatically.")
            .default(json!(60)).aliases(&["clang_timeout_secs"]).integer_range(1, 300),
        opt("externalCompileCommandsPath", OptionType::Path, "Explicit operator-owned compiler database outside the target. Use an absolute path; cannot be combined with compileCommandsPath. Only a bounded private copy reaches navigation.")
            .external_read().aliases(&["external_compile_commands_path"]),
        model_option(),
    ]
}

#[cfg(test)]
mod tests;
