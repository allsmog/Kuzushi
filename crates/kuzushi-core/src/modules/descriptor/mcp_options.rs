use super::*;

pub(in crate::modules) fn mcps_option() -> OptionSpec {
    opt(
        "mcps",
        OptionType::Bool,
        "Attach conditional kuzushi MCP oracle servers as agent tools when their target artifacts exist.",
    )
    .default(json!(true))
    .advanced()
}

pub(in crate::modules) fn codeql_prewarm_option() -> OptionSpec {
    opt(
        "codeqlPrewarm",
        OptionType::Bool,
        "Pre-compile common CodeQL CWE query folders at MCP server startup.",
    )
    .aliases(&["codeql_prewarm"])
    .default(json!(false))
    .advanced()
}

pub(in crate::modules) fn codeql_cache_dir_option() -> OptionSpec {
    opt(
        "codeqlCacheDir",
        OptionType::Path,
        "Override CodeQL's pack cache directory for the MCP CodeQL server.",
    )
    .aliases(&["codeql_cache_dir"])
    .external_write()
    .advanced()
}

pub(in crate::modules) fn mcp_tool_timeout_ms_option() -> OptionSpec {
    opt(
        "mcpToolTimeoutMs",
        OptionType::Int,
        "Wall-clock cap in milliseconds for each MCP tool call from the bridge.",
    )
    .aliases(&["mcp_tool_timeout_ms"])
    .default(json!(60000))
    .advanced()
}

/// Bounds how long an agentic investigation may keep calling tools. A run
/// that reaches it fails with `model_turn_limit`; a forced verdict from an
/// unfinished investigation is never accepted in its place.
pub(in crate::modules) fn max_model_turns_option(default: u32) -> OptionSpec {
    opt(
        "maxModelTurns",
        OptionType::Int,
        "Model turns an agentic investigation may take (1-40) before it stops without an answer.",
    )
    .aliases(&["max_model_turns"])
    .default(json!(default))
    .advanced()
}

pub(in crate::modules) fn bridge_verbose_option() -> OptionSpec {
    opt(
        "bridgeVerbose",
        OptionType::Bool,
        "Emit request-scoped, metadata-only bridge diagnostics to bridge stderr.",
    )
    .aliases(&["bridge_verbose"])
    .default(json!(false))
    .advanced()
}

pub(in crate::modules) fn bridge_log_path_option() -> OptionSpec {
    opt(
        "bridgeLogPath",
        OptionType::Path,
        "Append request-scoped, metadata-only bridge diagnostics to this path.",
    )
    .aliases(&["bridge_log_path"])
    .external_write()
    .advanced()
}

pub(in crate::modules) fn allow_deterministic_fallback_option() -> OptionSpec {
    opt(
        "allowDeterministicFallback",
        OptionType::Bool,
        "Allow deterministic linked-story projection when the agent fails to return valid JSON.",
    )
    .aliases(&["allow_deterministic_fallback"])
    .default(json!(false))
    .advanced()
}

pub(in crate::modules) fn cwe_focus_option() -> OptionSpec {
    opt(
        "cweFocus",
        OptionType::StringList,
        "Comma-separated CWE allow-list to focus the hunt on.",
    )
    .aliases(&["cwe_focus"])
    .advanced()
}

pub(in crate::modules) fn discover_signals_option() -> OptionSpec {
    opt(
        "discoverSignals",
        OptionType::Bool,
        "Run the per-target source/sink discovery pass at plan time.",
    )
    .aliases(&["discover_signals"])
    .default(json!(true))
    .advanced()
}

pub(in crate::modules) fn target_subdir_option() -> OptionSpec {
    opt(
        "targetSubdir",
        OptionType::Path,
        "Relative subdirectory under the target to scan.",
    )
    .aliases(&["target_subdir"])
    .workspace_read()
    .advanced()
}
