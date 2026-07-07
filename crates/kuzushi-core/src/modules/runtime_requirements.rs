//! Single source of truth for "which native tools need an `AgentRuntime`."
//!
//! Both the Rust shell (`kuzushi-tui::app::workers::run_background_tool`)
//! and the CLI's `kuzushi run` adapter (`kuzushi-cli::tool_requirements`)
//! decide whether to construct a `LangGraphRuntime` before dispatching
//! a tool. They used to keep their own private allowlists; the lists
//! drifted, and the TUI's copy was missing `full-mode:hunt`,
//! `deep-audit:run`, and `classifier-gate:score`.
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

use crate::config::V2Config;
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
    "exploit-chain:scan",
    "full-mode:hunt",
    "ndiff:extract-fix-pattern",
    "ndiff:hunt-variants",
    "offense-review:threat-hunt",
    "patch:finding",
    "prompt-armor:analyze",
    "prompt-armor:attack",
    "prompt-armor:scan",
    "randori:pasta",
    "shinsa:nist-quick-check",
    "shinsa:nist-scan",
    "shinsa:quick-check",
    "shinsa:scan",
    "systems-hunt:deep-semantic-cwe-select",
    "systems-hunt:deep-semantic-hunt",
    "systems-hunt:systems-hunt",
    "systems-hunt:systems-invariant-extract",
    "systems-hunt:systems-trigger-synth",
    "taint-iris-next:catalog",
    "taint-iris-next:codeql-db",
    "taint-iris-next:finding-review",
    "taint-iris-next:hunt",
    "taint-iris:hunt",
    "threat-intel:apply",
    "threat-intel:harvest",
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

pub const FINDING_STORE_TOOL_PREFIXES: &[&str] = &[
    "chrome-rce:",
    "findings:",
    "module-recommender:",
    "offense:",
    "systems-hunt:",
    "uaf-hunt:",
    "variant:",
];

pub const FINDING_STORE_TOOL_NAMES: &[&str] = &[
    "agentic-sast:scan",
    "android-apk:code-scan",
    "android-apk:fileprovider-scan",
    "android-apk:hybrid-detect",
    "android-apk:manifest-scan",
    "android-apk:native-libs",
    "android-apk:network-security-config",
    "android-apk:scan",
    "cargo-audit:scan",
    "carlini-threat-hunt:run",
    "codeql:scan",
    "dep-hygiene:check",
    "exploit-chain:scan",
    "govulncheck:scan",
    "iac-scan:scan",
    "license-scan:scan",
    "ndiff:hunt-variants",
    "offense-review:threat-hunt",
    "patch:finding",
    "prompt-armor:analyze",
    "prompt-armor:attack",
    "prompt-armor:scan",
    "sast:scan",
    "sbom-scan:scan",
    "secret-scan:scan",
    "semgrep:scan",
    "shinsa:nist-quick-check",
    "shinsa:nist-scan",
    "shinsa:quick-check",
    "shinsa:scan",
    "taint-iris-next:finding-review",
    "taint-iris-next:hunt",
    "taint-iris:hunt",
    "tob:audit",
    "triage:run",
    "verify:exploit",
    "verify:finding",
    "vuln-scout:audit",
];

pub const WORKSPACE_TOOL_PREFIXES: &[&str] = &[
    "findings:",
    "module-recommender:",
    "context:",
    "recon:",
    "bounty:",
    "vendor-assessment:",
    "chrome-rce:",
    "vuln-scout:",
    "tob:",
    "shinsa:",
    "prompt-armor:",
    "x-ray:",
    "threat-model:",
    "randori:",
    "variant:",
    "ndiff:",
    "systems-hunt:",
    "threat-intel:",
    "uaf-hunt:",
];

pub const WORKSPACE_TOOL_NAMES: &[&str] = &[
    "carlini-threat-hunt:run",
    "offense-review:threat-hunt",
    "agentic-sast:scan",
    "taint-iris:hunt",
    "taint-iris-next:dataflow-plan",
    "taint-iris-next:source-sink-trace",
    "taint-iris-next:finding-review",
    "taint-iris-next:hunt",
    "taint-iris-next:catalog",
    "taint-iris-next:codeql-db",
    "triage:run",
    "verify:finding",
    "verify:exploit",
    "patch:finding",
    "context-lite:index",
    "full-mode:hunt",
    "classifier-gate:score",
    "deep-audit:run",
    "sast:scan",
    "semgrep:scan",
    "codeql:scan",
    "iac-scan:scan",
    "license-scan:scan",
    "sbom-scan:scan",
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

pub fn tool_uses_finding_store(tool_name: &str) -> bool {
    FINDING_STORE_TOOL_PREFIXES
        .iter()
        .any(|prefix| tool_name.starts_with(prefix))
        || FINDING_STORE_TOOL_NAMES.contains(&tool_name)
}

pub fn tool_needs_finding_store(tool_name: &str) -> bool {
    tool_uses_finding_store(tool_name)
}

pub fn tool_defaults_to_workspace(tool_name: &str) -> bool {
    has_known_prefix(tool_name, WORKSPACE_TOOL_PREFIXES)
        || has_known_name(tool_name, WORKSPACE_TOOL_NAMES)
}

/// Input-aware variant of `tool_uses_agent_runtime`. Adds the
/// `sast:scan` carve-out: only build a runtime when the input asks for
/// a triage / verify / autoPatch pass or an agentic sub-task. The CLI
/// uses this in `kuzushi run`, the TUI in its background-tool worker.
pub fn tool_needs_runtime(tool_name: &str, input: &Value) -> bool {
    if let Some(needs_runtime) = input_specific_runtime_requirement(tool_name, input) {
        return needs_runtime;
    }
    tool_always_needs_runtime(tool_name)
}

/// Runtime construction predicate for callers that have the resolved operator
/// config. Required-runtime tools must get a runtime. A small number of tools
/// can optionally use a runtime when the operator has configured a model while
/// still running deterministically without one.
pub fn tool_wants_runtime(tool_name: &str, input: &Value, config: &V2Config) -> bool {
    tool_needs_runtime(tool_name, input)
        || threat_model_build_wants_runtime(tool_name, config)
        || module_recommender_wants_runtime(tool_name, input, config)
}

fn threat_model_build_needs_runtime(input: &Value) -> bool {
    input
        .get("model")
        .and_then(Value::as_str)
        .is_some_and(|model| !model.trim().is_empty())
}

fn input_specific_runtime_requirement(tool_name: &str, input: &Value) -> Option<bool> {
    match tool_name {
        "full-mode:hunt" => Some(full_mode_hunt_needs_runtime(input)),
        "threat-model:build" => Some(threat_model_build_needs_runtime(input)),
        "sast:scan" => Some(wants_sast_runtime(input)),
        _ => None,
    }
}

fn tool_always_needs_runtime(tool_name: &str) -> bool {
    tool_uses_agent_runtime(tool_name) || tool_name == "pwn:auto-solve"
}

fn threat_model_build_wants_runtime(tool_name: &str, config: &V2Config) -> bool {
    tool_name == "threat-model:build" && config.model.is_some()
}

fn module_recommender_wants_runtime(tool_name: &str, input: &Value, config: &V2Config) -> bool {
    tool_name == "module-recommender:recommend"
        && config.model.is_some()
        && input
            .get("useModelRanking")
            .and_then(Value::as_bool)
            .unwrap_or(true)
}

fn full_mode_hunt_needs_runtime(input: &Value) -> bool {
    !input
        .get("dryRun")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn has_known_prefix(tool_name: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| tool_name.starts_with(prefix))
}

fn has_known_name(tool_name: &str, names: &[&str]) -> bool {
    names.contains(&tool_name)
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
    "offense-review",
    "offense-review:threat-hunt",
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
    fn finding_store_allowlist_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for name in FINDING_STORE_TOOL_NAMES {
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
            "full-mode:hunt",
            "deep-audit:run",
            "exploit-chain:scan",
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
    fn tool_needs_runtime_allows_full_mode_dry_run_without_runtime() {
        assert!(!tool_needs_runtime(
            "full-mode:hunt",
            &json!({"dryRun": true})
        ));
        assert!(tool_needs_runtime(
            "full-mode:hunt",
            &json!({"dryRun": false})
        ));
        assert!(tool_needs_runtime("full-mode:hunt", &json!({})));
    }

    #[test]
    fn pwn_auto_solve_always_needs_runtime() {
        assert!(tool_needs_runtime("pwn:auto-solve", &json!({})));
    }

    #[test]
    fn threat_model_build_runtime_requirement_is_input_aware() {
        assert!(!tool_uses_agent_runtime("threat-model:build"));
        assert!(!tool_needs_runtime("threat-model:build", &json!({})));
        assert!(tool_needs_runtime(
            "threat-model:build",
            &json!({"model": "openai:gpt-5.4"})
        ));
    }

    #[test]
    fn threat_model_build_wants_runtime_when_config_has_model() {
        let mut config = V2Config::default();
        assert!(!tool_wants_runtime(
            "threat-model:build",
            &json!({}),
            &config
        ));

        config.model = Some("openai:gpt-5.4".to_string());
        assert!(tool_wants_runtime(
            "threat-model:build",
            &json!({}),
            &config
        ));
    }

    #[test]
    fn recommender_wants_runtime_only_when_model_ranking_is_enabled_with_model() {
        let mut config = V2Config::default();
        assert!(!tool_wants_runtime(
            "module-recommender:recommend",
            &json!({}),
            &config
        ));

        config.model = Some("openai:gpt-5.4".to_string());
        assert!(tool_wants_runtime(
            "module-recommender:recommend",
            &json!({}),
            &config
        ));
        assert!(!tool_wants_runtime(
            "module-recommender:recommend",
            &json!({"useModelRanking": false}),
            &config
        ));
    }

    #[test]
    fn offense_review_threat_hunt_needs_runtime() {
        assert!(tool_needs_runtime("offense-review:threat-hunt", &json!({})));
    }

    #[test]
    fn tool_needs_runtime_falls_through_to_allowlist_for_other_tools() {
        assert!(tool_needs_runtime("deep-audit:run", &json!({})));
        assert!(tool_needs_runtime("exploit-chain:scan", &json!({})));
        assert!(tool_needs_runtime("uaf-hunt:hunt", &json!({})));
        assert!(!tool_needs_runtime("findings:list", &json!({})));
    }

    #[test]
    fn taint_iris_next_decomposed_tools_split_runtime_boundary() {
        assert!(!tool_needs_runtime(
            "taint-iris-next:dataflow-plan",
            &json!({})
        ));
        assert!(!tool_needs_runtime(
            "taint-iris-next:source-sink-trace",
            &json!({})
        ));
        assert!(tool_needs_runtime(
            "taint-iris-next:finding-review",
            &json!({})
        ));
    }

    #[test]
    fn finding_store_requirement_covers_cross_mode_drift_cases() {
        assert!(tool_needs_finding_store("cargo-audit:scan"));
        assert!(tool_needs_finding_store("offense:chain"));
        assert!(tool_needs_finding_store("variant:hunt"));
        assert!(tool_needs_finding_store("variant:lift-pattern"));
        assert!(!tool_needs_finding_store("taint-iris-next:dataflow-plan"));
    }

    #[test]
    fn tools_that_persist_findings_get_a_store() {
        for tool in [
            "dep-hygiene:check",
            "secret-scan:scan",
            "sbom-scan:scan",
            "exploit-chain:scan",
            "android-apk:scan",
            "android-apk:manifest-scan",
            "android-apk:network-security-config",
            "android-apk:fileprovider-scan",
            "android-apk:code-scan",
            "android-apk:native-libs",
            "android-apk:hybrid-detect",
        ] {
            assert!(tool_needs_finding_store(tool), "{tool} should get a store");
        }
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
