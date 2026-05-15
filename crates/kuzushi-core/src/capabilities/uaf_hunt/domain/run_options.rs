use super::AllocFreePair;
use std::path::PathBuf;

/// Parsed input options for `uaf-hunt:hunt`. The adapter layer is
/// responsible for assembling this from JSON; the application layer
/// receives a fully-resolved struct.
#[derive(Debug, Clone)]
pub struct UafHuntInput {
    pub max_findings: usize,
    pub max_agent_steps: u32,
    /// Effective alloc/free pair set: either operator-provided
    /// `allocFreePairs` (overrides defaults entirely) or
    /// `default_alloc_free_pairs()` + `extraAllocFreePairs`.
    pub alloc_free_pairs: Vec<AllocFreePair>,
    /// Resolved path to `compile_commands.json`. Required — the
    /// adapter bails before constructing this struct when missing.
    pub compile_commands_path: PathBuf,
    /// Operator-supplied per-tool-call timeout for mcp-clang RPCs.
    pub clang_call_timeout_secs: u64,
    /// Include docs/examples/tests/fixtures in repo-walking tools. Defaults
    /// false so production hunts spend their budget on shipped code.
    pub include_non_production: bool,
    pub model: Option<String>,
}
