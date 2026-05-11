//! Single source of truth for "which native tools need an `AgentRuntime`."
//!
//! Both the Rust shell (`kuzushi-tui::app::workers::run_background_tool`) and
//! the CLI's `kuzushi run` adapter (`kuzushi-cli::tool_requirements`) decide
//! whether to construct a `PiAgentCoreRuntime` before dispatching a tool. They
//! used to keep their own private allowlists; the lists drifted, and the TUI's
//! copy was missing `smoke:next-step`, `full-mode:hunt`, `deep-audit:run`, and
//! `classifier-gate:score`. Those tools fail at runtime with "requires an
//! agent runtime; none configured" because the caller never passes one.
//!
//! Per CLAUDE.md's mode-parity rule ("Do not duplicate policy or parsing
//! logic across scan, shell, and run modes"), this module is the shared
//! allowlist. Anything that bails out via `*_runtime(runtime)?` in
//! `src/modules/` must appear here, otherwise the shell will refuse to call
//! it.
//!
//! `tool_uses_agent_runtime` is name-only. `sast:scan` has scanner-only modes
//! that don't need a runtime (handled by `wants_sast_runtime` in the CLI).
//! When that nuance matters, callers should layer their own input check on
//! top of this helper rather than baking it in here.

const RUNTIME_TOOL_NAMES: &[&str] = &[
    "agentic-sast:scan",
    "carlini-threat-hunt:run",
    "classifier-gate:score",
    "deep-audit:run",
    "full-mode:hunt",
    "ndiff:extract-fix-pattern",
    "ndiff:hunt-variants",
    "patch:finding",
    "prompt-armor:analyze",
    "prompt-armor:attack",
    "prompt-armor:scan",
    "randori:pasta",
    "sast:scan",
    "shinsa:nist-quick-check",
    "shinsa:nist-scan",
    "shinsa:quick-check",
    "shinsa:scan",
    "smoke:next-step",
    "systems-hunt:deep-semantic-cwe-select",
    "systems-hunt:deep-semantic-hunt",
    "systems-hunt:systems-hunt",
    "systems-hunt:systems-invariant-extract",
    "systems-hunt:systems-trigger-synth",
    "taint-iris-next:hunt",
    "taint-iris:hunt",
    "threat-model:build",
    "tob:audit",
    "triage:run",
    "variant:hunt",
    "variant:lift-pattern",
    "vendor-assessment:assess",
    "verify:finding",
    "vuln-scout:audit",
    "x-ray:run",
    "x-ray:x-ray",
];

/// Returns true when `tool_name` is one of the native tools whose handler
/// dereferences an `AgentRuntime` and bails when it's missing. Callers should
/// construct a `PiAgentCoreRuntime` (or another `AgentRuntime` impl) before
/// dispatch when this returns true.
pub fn tool_uses_agent_runtime(tool_name: &str) -> bool {
    RUNTIME_TOOL_NAMES.binary_search(&tool_name).is_ok()
}

/// All tool names known to require an agent runtime, in sorted order.
/// Exposed for tests and for tools that want to render the allowlist.
pub fn agent_runtime_tool_names() -> &'static [&'static str] {
    RUNTIME_TOOL_NAMES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_is_sorted_for_binary_search() {
        let mut sorted = RUNTIME_TOOL_NAMES.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            RUNTIME_TOOL_NAMES, &sorted[..],
            "RUNTIME_TOOL_NAMES must stay sorted; binary_search relies on it"
        );
    }

    #[test]
    fn allowlist_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for name in RUNTIME_TOOL_NAMES {
            assert!(seen.insert(*name), "duplicate entry: {name}");
        }
    }

    #[test]
    fn tools_that_bail_without_runtime_are_listed() {
        // Mirror of the `*_runtime(runtime)?` bail sites in src/modules/.
        // Anything that bails with "requires an agent runtime" must be here,
        // otherwise the shell will skip building a runtime and the tool will
        // fail at execution time.
        for tool in [
            "smoke:next-step",
            "full-mode:hunt",
            "deep-audit:run",
            "classifier-gate:score",
        ] {
            assert!(
                tool_uses_agent_runtime(tool),
                "{tool} bails without a runtime but isn't in the allowlist"
            );
        }
    }
}
