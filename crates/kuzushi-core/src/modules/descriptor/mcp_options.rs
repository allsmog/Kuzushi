use super::*;

/// Option specs for the kuzushi MCP-as-agent surface (tree-sitter, joern,
/// codeql) attached to the agent during a `taint-iris-next:hunt`. They
/// match the env vars the bridge and MCP servers honour, but exposing
/// them as module options lets the shell discover them via
/// `options taint-iris-next:hunt` and tweak them with `set`/`setg`
/// without the operator having to remember the env-var names.
///
/// Each option is `advanced()` because most agents hit good defaults;
/// `show advanced` in the shell surfaces them on demand.
pub(in crate::modules) fn mcps_option() -> OptionSpec {
    opt(
        "mcps",
        OptionType::Bool,
        "Attach the kuzushi MCP servers (tree-sitter, joern, codeql) as agent tools \
         during the hunt. Lets the agent triangulate candidates via AST queries, \
         CodeQL CWE-folder flows, and Joern taint paths in addition to the \
         deterministic plan. Default true; the bridge also respects \
         KUZUSHI_AGENT_MCPS=1 as an env-var override.",
    )
    .default(json!(true))
}

pub(in crate::modules) fn joern_cpg_option() -> OptionSpec {
    opt(
        "joernCpg",
        OptionType::Path,
        "Path to a joern CPG (`cpg.bin`) the joern MCP server should importCpg \
         when it auto-spawns `joern --server` on first taint call. Defaults to \
         the value of KUZUSHI_JOERN_CPG; build with \
         `joern-parse <repo> --output <repo>/.kuzushi/cpg.bin`.",
    )
    .advanced()
}

pub(in crate::modules) fn joern_per_cwe_timeout_ms_option() -> OptionSpec {
    opt(
        "joernPerCweTimeoutMs",
        OptionType::Int,
        "Wall-clock budget per CWE inside scripts/taint_iris_next_flows.sc \
         (joern's reachableByFlows is exponential and one broad CWE can \
         deadlock the rest). Default 60000 (60s); 0 disables the timeout.",
    )
    .default(json!(60000))
    .advanced()
}

pub(in crate::modules) fn codeql_prewarm_option() -> OptionSpec {
    opt(
        "codeqlPrewarm",
        OptionType::Bool,
        "Have kuzushi-mcp-codeql pre-compile common CWE folders for every \
         installed language pack at startup so the first agent flows_for_cwe \
         call is a cache hit. Off by default — the warmup itself takes \
         5-10 minutes for a fresh box and is wasted in one-shot CI runs.",
    )
    .default(json!(false))
    .advanced()
}

pub(in crate::modules) fn codeql_cache_dir_option() -> OptionSpec {
    opt(
        "codeqlCacheDir",
        OptionType::Path,
        "Override CodeQL's pack cache directory (default $HOME/.codeql). \
         Useful for shared cache volumes (CI, multi-tenant boxes). \
         Read by kuzushi-mcp-codeql via KUZUSHI_CODEQL_CACHE_DIR.",
    )
    .advanced()
}

pub(in crate::modules) fn mcp_tool_timeout_ms_option() -> OptionSpec {
    opt(
        "mcpToolTimeoutMs",
        OptionType::Int,
        "Wall-clock cap (ms) for any single MCP tool call dispatched from the \
         bridge. Surfaces a runaway joern/codeql query as a tool error \
         instead of hanging the agent loop. Default 60000 (60s).",
    )
    .default(json!(60000))
    .advanced()
}

pub(in crate::modules) fn bridge_verbose_option() -> OptionSpec {
    opt(
        "bridgeVerbose",
        OptionType::Bool,
        "Forward every bridge stderr line (including [mcp:*] tool-call traces, \
         turn boundaries, and MCP child stderr) to kuzushi's stderr in real \
         time. Default false; equivalent to KUZUSHI_BRIDGE_VERBOSE=1.",
    )
    .default(json!(false))
    .advanced()
}

pub(in crate::modules) fn bridge_log_path_option() -> OptionSpec {
    opt(
        "bridgeLogPath",
        OptionType::Path,
        "Append every bridge log line to this file in addition to (or instead \
         of) forwarding it to stderr. Useful when stdout is being captured by \
         Rust. Equivalent to KUZUSHI_BRIDGE_LOG=<path>.",
    )
    .advanced()
}

/// Filter the ranked CWE catalog down to a comma-separated allow-list
/// of CWE identifiers (`CWE-78,CWE-94,CWE-426,...`). When set, both the
/// deterministic structural pass (which seeds candidates from each
/// catalog entry's `structuralQueries`) and the agent prompt are
/// scoped to those CWEs only. Useful for "hunt for privesc + RCE on
/// postgres without pulling in the SQLi / path-traversal noise" type
/// of session. Entry matching is done on the `cwe` field exactly
/// (case-insensitive); unknown CWEs are silently dropped so a typo
/// doesn't fail the run loud, just narrows the scope.
pub(in crate::modules) fn cwe_focus_option() -> OptionSpec {
    opt(
        "cweFocus",
        OptionType::StringList,
        "Comma-separated CWE allow-list to focus the hunt on. Filters \
         the ranked catalog (and therefore the structural seeds) to the \
         listed entries and tells the agent to prioritise them. Example: \
         \"CWE-78,CWE-94,CWE-426,CWE-269\" to hunt for privesc + RCE. \
         Empty / unset means \"use the full catalog\".",
    )
}

/// Toggle the per-target source/sink discovery pass that scans the
/// codebase for canonical entry-point markers (PG_FUNCTION_INFO_V1,
/// `@app.route`, `app.get(...)`) and privesc/RCE primitives (`dlopen`,
/// `load_external_function`, `SetUserId`, `system(`, `eval(`...).
/// Discovery is regex-only and pure-Rust — cheap on any reasonable
/// repo — and feeds catalog ranking + the agent prompt with names that
/// actually exist in the code, not just the static catalog's a-priori
/// guess. Persists to `<target>/.kuzushi/discovered-signals.json`.
pub(in crate::modules) fn discover_signals_option() -> OptionSpec {
    opt(
        "discoverSignals",
        OptionType::Bool,
        "Run the per-target source/sink discovery pass at plan time. \
         Default true; turn off for fast/clean runs that should rely on \
         the static catalog only.",
    )
    .default(json!(true))
    .advanced()
}

/// Operator opt-in for the deterministic linked-story → finding
/// fallback when the agent fails to return valid JSON (parse error,
/// transport 401/5xx, output truncated). Default false: agent failure
/// surfaces honestly as zero findings + warnings, per CLAUDE.md
/// §"Model & runtime safety". Set to true when running offline / for
/// review batches where you want the heuristic linker's stories
/// projected as `review_candidates` even without agent triage.
pub(in crate::modules) fn allow_deterministic_fallback_option() -> OptionSpec {
    opt(
        "allowDeterministicFallback",
        OptionType::Bool,
        "Allow the deterministic linked-story → finding fallback when \
         the agent fails to return valid JSON. Default false (honest \
         failure: 0 findings + parse-error warning). Turn on for \
         offline / review batches where heuristic stories are useful \
         even without agent triage. Mirrors \
         KUZUSHI_TAINT_IRIS_NEXT_ALLOW_DETERMINISTIC_FALLBACK env var.",
    )
    .default(json!(false))
    .advanced()
}
