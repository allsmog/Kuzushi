//! Single source of truth for "which native tools need an `AgentRuntime`."
//!
//! Both the Rust shell (`kuzushi-tui::app::workers::run_background_tool`)
//! and the CLI's `kuzushi run` adapter (`kuzushi-cli::tool_requirements`)
//! decide whether to construct a `PiAgentCoreRuntime` before dispatching
//! a tool. They used to keep their own private allowlists; the lists
//! drifted, and the TUI's copy was missing `smoke:next-step`,
//! `full-mode:hunt`, `deep-audit:run`, and `classifier-gate:score`.
//! Those tools fail at runtime with "requires an agent runtime; none
//! configured" because the caller never passes one.
//!
//! Per CLAUDE.md's mode-parity rule ("Do not duplicate policy or parsing
//! logic across scan, shell, and run modes"), this module is the shared
//! allowlist + the input-aware combiner. Anything that bails out via
//! `*_runtime(runtime)?` in `src/modules/` must appear in
//! `RUNTIME_TOOL_NAMES`, otherwise the shell will refuse to call it.
//!
//! `tool_uses_agent_runtime` is name-only and is the right helper for
//! UX surfaces that don't have the tool input handy (e.g. status-line
//! label). `tool_needs_runtime` adds the `sast:scan` input nuance:
//! sast:scan can run in scanner-only mode (no triage, no verify, no
//! agentic sub-task) and doesn't need a runtime in that case. Callers
//! that have input should prefer `tool_needs_runtime`.

use serde_json::Value;

/// Sorted allowlist for `tool_uses_agent_runtime`. `sast:scan` is
/// intentionally absent — its runtime requirement depends on input
/// (`wants_sast_runtime`), and the combiner `tool_needs_runtime`
/// handles it. Adding `sast:scan` here unconditionally would force the
/// scanner-only mode to also pay for a runtime; removing the nuance
/// broke the CLI's `run_tool_policy_predicates_cover_workspace_store_and_runtime`
/// regression test until this carve-out was reintroduced.
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
    "taint-iris-next:catalog",
    "taint-iris-next:codeql-db",
    "taint-iris-next:hunt",
    "taint-iris:hunt",
    "threat-intel:apply",
    "threat-intel:harvest",
    "threat-model:build",
    "tob:audit",
    "triage:run",
    "uaf-hunt:hunt",
    "variant:hunt",
    "variant:lift-pattern",
    "vendor-assessment:assess",
    "verify:finding",
    "vuln-scout:audit",
    "x-ray:run",
    "x-ray:x-ray",
];

/// Returns true when `tool_name` is one of the native tools whose
/// handler dereferences an `AgentRuntime` and bails when it's missing.
/// `sast:scan` is *not* covered here — use `tool_needs_runtime` when
/// the tool input is available so the scanner-only mode skips the
/// runtime construction.
pub fn tool_uses_agent_runtime(tool_name: &str) -> bool {
    RUNTIME_TOOL_NAMES.binary_search(&tool_name).is_ok()
}

pub fn tool_requires_agent_runtime(tool_name: &str) -> bool {
    tool_uses_agent_runtime(tool_name)
}

/// Input-aware variant of `tool_uses_agent_runtime`. Adds the
/// `sast:scan` carve-out: only build a runtime when the input asks for
/// a triage / verify / autoPatch pass or an agentic sub-task. The CLI
/// uses this in `kuzushi run`, the TUI in its background-tool worker.
pub fn tool_needs_runtime(tool_name: &str, input: &Value) -> bool {
    if tool_uses_agent_runtime(tool_name) {
        return true;
    }
    tool_name == "sast:scan" && wants_sast_runtime(input)
}

/// All tool names known to require an agent runtime, in sorted order.
/// Exposed for tests and for tools that want to render the allowlist.
pub fn agent_runtime_tool_names() -> &'static [&'static str] {
    RUNTIME_TOOL_NAMES
}

/// Whether `sast:scan` should construct an agent runtime for the given
/// input. Moved out of `kuzushi-cli` so the TUI can apply the same
/// rule. Conservatively: any triage/verify/autoPatch/agentic-task
/// request needs a runtime; scanner-only / whitebox-static runs don't.
///
/// This is the canonical reference for what "needs runtime" means in
/// the `sast:scan` context — every call site in the workspace should
/// route through here rather than re-deriving the rule.
pub fn wants_sast_runtime(input: &Value) -> bool {
    let whitebox_static = crate::whitebox_static::whitebox_static_enabled(input).unwrap_or(false);
    let triage_runtime = input
        .get("triage")
        .or_else(|| input.get("aiTriage"))
        .or_else(|| input.get("ai_triage"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let execution_runtime = !whitebox_static
        && input
            .get("verify")
            .or_else(|| input.get("autoPatch"))
            .or_else(|| input.get("auto_patch"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

    triage_runtime || execution_runtime || sast_tasks_request_runtime(input)
}

fn sast_tasks_request_runtime(input: &Value) -> bool {
    input
        .get("tasks")
        .and_then(Value::as_array)
        .is_some_and(|tasks| {
            tasks
                .iter()
                .filter_map(Value::as_str)
                .any(|task| matches!(task.trim(), task if SAST_RUNTIME_TASK_NAMES.contains(&task)))
        })
}

const SAST_RUNTIME_TASK_NAMES: &[&str] = &[
    "agentic",
    "agentic-sast",
    "agentic-sast:scan",
    "carlini",
    "carlini-threat-hunt",
    "carlini-threat-hunt:run",
    "deep-semantic",
    "deep-semantic-hunt",
    "iris",
    "iris-next",
    "systems",
    "systems-hunt",
    "systems-hunt:deep-semantic-hunt",
    "systems-hunt:systems-hunt",
    "taint",
    "taint-iris",
    "taint-iris-next",
    "taint-iris-next:hunt",
    "taint-iris:hunt",
    "taint-next",
    "threat-hunt",
];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn allowlist_is_sorted_for_binary_search() {
        let mut sorted = RUNTIME_TOOL_NAMES.to_vec();
        sorted.sort_unstable();
        assert_eq!(
            RUNTIME_TOOL_NAMES,
            &sorted[..],
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
        // otherwise the shell will skip building a runtime and the tool
        // will fail at execution time.
        for tool in [
            "smoke:next-step",
            "full-mode:hunt",
            "deep-audit:run",
            "classifier-gate:score",
            "uaf-hunt:hunt",
        ] {
            assert!(
                tool_uses_agent_runtime(tool),
                "{tool} bails without a runtime but isn't in the allowlist"
            );
        }
    }

    #[test]
    fn sast_scan_is_excluded_from_name_only_allowlist() {
        assert!(
            !tool_uses_agent_runtime("sast:scan"),
            "sast:scan must NOT be in the name-only allowlist — the scanner-only \
             mode should skip the runtime, and that nuance is in tool_needs_runtime"
        );
    }

    #[test]
    fn tool_needs_runtime_covers_sast_scan_input_nuance() {
        assert!(tool_needs_runtime("sast:scan", &json!({"triage": true})));
        assert!(tool_needs_runtime("sast:scan", &json!({"verify": true})));
        assert!(tool_needs_runtime(
            "sast:scan",
            &json!({"tasks": ["agentic-sast"]})
        ));
        assert!(!tool_needs_runtime(
            "sast:scan",
            &json!({"whiteboxStatic": true})
        ));
        assert!(!tool_needs_runtime("sast:scan", &json!({})));
    }

    #[test]
    fn tool_needs_runtime_falls_through_to_allowlist_for_other_tools() {
        assert!(tool_needs_runtime("deep-audit:run", &json!({})));
        assert!(tool_needs_runtime("uaf-hunt:hunt", &json!({})));
        assert!(!tool_needs_runtime("findings:list", &json!({})));
    }

    #[test]
    fn wants_sast_runtime_treats_whitebox_static_as_scanner_only_for_verify() {
        // verify=true + whiteboxStatic=true → scanner-only wins; no
        // runtime needed. The whitebox-static profile suppresses the
        // verify executor because static evidence can't be exercised
        // without the shell.
        assert!(!wants_sast_runtime(
            &json!({"verify": true, "whiteboxStatic": true})
        ));
        // triage still requires a runtime even under whitebox-static
        // (the triage prompt runs offline).
        assert!(wants_sast_runtime(
            &json!({"triage": true, "whiteboxStatic": true})
        ));
    }
}
