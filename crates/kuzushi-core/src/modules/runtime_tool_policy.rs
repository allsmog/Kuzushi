//! Single source of truth for which tool dispatches need a live
//! `AgentRuntime`. Both `kuzushi-cli` (one-shot `kuzushi run …`) and
//! `kuzushi-tui` (shell-mode background workers) must agree, otherwise the
//! tool fails immediately with
//! `<tool> requires an agent runtime; none configured`.
//!
//! Keep `RUNTIME_TOOL_NAMES` and the catalog registration in sync — the
//! drift-detection test in `tests.rs` keeps that honest at compile-test
//! time.

/// Tool names that always require an `AgentRuntime`. Sorted alphabetically
/// to keep diffs small when new tools are added.
pub const RUNTIME_TOOL_NAMES: &[&str] = &[
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

/// Returns true when the named tool must be invoked with a live
/// `AgentRuntime`. Note: `sast:scan` is *conditionally* runtime-bound and
/// is handled by the CLI separately via its input inspection.
pub fn tool_requires_agent_runtime(tool: &str) -> bool {
    RUNTIME_TOOL_NAMES.binary_search(&tool).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_is_sorted_and_unique() {
        // binary_search relies on sort order; duplicate names would also
        // suggest a copy/paste mistake.
        let mut sorted = RUNTIME_TOOL_NAMES.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            RUNTIME_TOOL_NAMES,
            sorted.as_slice(),
            "RUNTIME_TOOL_NAMES must stay sorted + unique"
        );
    }

    #[test]
    fn known_runtime_tools_are_recognized() {
        for tool in [
            "full-mode:hunt",
            "deep-audit:run",
            "carlini-threat-hunt:run",
            "systems-hunt:systems-invariant-extract",
            "taint-iris-next:hunt",
        ] {
            assert!(
                tool_requires_agent_runtime(tool),
                "{tool} should be in RUNTIME_TOOL_NAMES",
            );
        }
    }

    #[test]
    fn deterministic_tools_are_not_in_runtime_list() {
        for tool in [
            "context:build",
            "findings:list",
            "secret-scan:scan",
            "semgrep:scan",
            "codeql:scan",
            "iac-scan:scan",
            "systems-hunt:systems-context-gatherer",
            "workspace:status",
        ] {
            assert!(
                !tool_requires_agent_runtime(tool),
                "{tool} must not be in RUNTIME_TOOL_NAMES",
            );
        }
    }
}
