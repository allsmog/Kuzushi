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
//! Per AGENTS.md's mode-parity rule ("Do not duplicate policy or parsing
//! logic across scan, shell, and run modes"), this module exposes shared
//! descriptor-backed queries plus the input-aware combiner.
//!
//! `tool_uses_agent_runtime` is name-only and is the right helper for
//! UX surfaces that don't have the tool input handy (e.g. status-line
//! label). `tool_needs_runtime` adds the `sast:scan` input nuance:
//! sast:scan can run in scanner-only mode (no triage, no verify, no
//! agentic sub-task) and doesn't need a runtime in that case. Callers
//! that have input should prefer `tool_needs_runtime`.

use crate::config::V2Config;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy)]
struct SharedToolPolicy {
    runtime: crate::modules::RuntimeRequirement,
    finding_store: crate::modules::FindingStoreRequirement,
    workspace: crate::modules::WorkspaceRequirement,
    continuation: crate::modules::ContinuationSupport,
}

fn shared_tool_policies() -> &'static BTreeMap<String, SharedToolPolicy> {
    static POLICIES: OnceLock<BTreeMap<String, SharedToolPolicy>> = OnceLock::new();
    POLICIES.get_or_init(|| {
        let registry = crate::modules::registry::ModuleRegistry::with_v2_builtins();
        registry
            .all_modules()
            .flat_map(|module| module.tools())
            .map(|tool| {
                (
                    tool.name.clone(),
                    SharedToolPolicy {
                        runtime: tool.runtime_requirement,
                        finding_store: tool.finding_store_requirement,
                        workspace: tool.workspace_requirement,
                        continuation: tool.continuation,
                    },
                )
            })
            .collect()
    })
}

pub fn tool_uses_agent_runtime(tool_name: &str) -> bool {
    shared_tool_policies()
        .get(tool_name)
        .is_some_and(|policy| policy.runtime != crate::modules::RuntimeRequirement::Never)
}

pub fn tool_requires_agent_runtime(tool_name: &str) -> bool {
    shared_tool_policies()
        .get(tool_name)
        .is_some_and(|policy| policy.runtime == crate::modules::RuntimeRequirement::Always)
}

/// Descriptor-declared continuation capability of a tool, for planner /
/// result-card / `resume` surfaces that must know without executing it.
pub fn tool_continuation(tool_name: &str) -> crate::modules::ContinuationSupport {
    shared_tool_policies()
        .get(tool_name)
        .map(|policy| policy.continuation)
        .unwrap_or_default()
}

pub fn tool_uses_finding_store(tool_name: &str) -> bool {
    tool_needs_finding_store(tool_name)
}

pub fn tool_needs_finding_store(tool_name: &str) -> bool {
    shared_tool_policies().get(tool_name).is_some_and(|policy| {
        policy.finding_store == crate::modules::FindingStoreRequirement::Required
    })
}

pub fn tool_defaults_to_workspace(tool_name: &str) -> bool {
    shared_tool_policies()
        .get(tool_name)
        .is_some_and(|policy| policy.workspace == crate::modules::WorkspaceRequirement::Required)
}

/// Input-aware variant of `tool_uses_agent_runtime`. Adds the
/// `sast:scan` carve-out: only build a runtime when the input asks for
/// a triage / verify / autoPatch pass or an agentic sub-task. The CLI
/// uses this in `kuzushi run`, the TUI in its background-tool worker.
pub fn tool_needs_runtime(tool_name: &str, input: &Value) -> bool {
    match shared_tool_policies()
        .get(tool_name)
        .map(|policy| policy.runtime)
    {
        Some(crate::modules::RuntimeRequirement::Always) => true,
        Some(crate::modules::RuntimeRequirement::InputAware) => {
            input_aware_tool_needs_runtime(tool_name, input)
        }
        _ => false,
    }
}

/// Runtime construction predicate for callers that have the resolved operator
/// config. Required-runtime tools must get a runtime. A small number of tools
/// can optionally use a runtime when the operator has configured a model while
/// still running deterministically without one.
pub fn tool_wants_runtime(tool_name: &str, input: &Value, config: &V2Config) -> bool {
    tool_needs_runtime(tool_name, input) || tool_optionally_wants_runtime(tool_name, input, config)
}

/// Model that this invocation will actually execute, for durable receipts.
/// Runtime-free tools must not inherit the operator's configured model merely
/// because one is available in the profile.
pub fn tool_execution_model(tool_name: &str, input: &Value, config: &V2Config) -> Option<String> {
    if !tool_wants_runtime(tool_name, input, config) {
        return None;
    }
    input
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|model| !model.is_empty())
        .map(str::to_string)
        .or_else(|| config.model.clone())
}

pub(super) fn input_aware_tool_needs_runtime(tool_name: &str, input: &Value) -> bool {
    input_specific_runtime_requirement(tool_name, input).unwrap_or(false)
}

pub(super) fn tool_optionally_wants_runtime(
    tool_name: &str,
    input: &Value,
    config: &V2Config,
) -> bool {
    module_recommender_wants_runtime(tool_name, input, config)
}

/// Threat modeling is model-backed by default. Only the explicitly requested
/// `pipeline=deterministic` fold runs without a runtime — a missing model is
/// never a silent reason to degrade to the deterministic pipeline.
fn threat_model_build_needs_runtime(input: &Value) -> bool {
    !input
        .get("pipeline")
        .and_then(Value::as_str)
        .is_some_and(|pipeline| pipeline.trim().eq_ignore_ascii_case("deterministic"))
}

fn input_specific_runtime_requirement(tool_name: &str, input: &Value) -> Option<bool> {
    match tool_name {
        "verify:finding" => Some(!super::verification_is_empirical(input)),
        "context:build" => Some(context_build_needs_runtime(input)),
        "offense:chain" => Some(
            input
                .get("goal")
                .and_then(Value::as_str)
                .is_some_and(|goal| !goal.trim().is_empty()),
        ),
        "full-mode:hunt" => Some(full_mode_hunt_needs_runtime(input)),
        "threat-model:build" => Some(threat_model_build_needs_runtime(input)),
        "patch:reverify" => Some(patch_reverify_needs_runtime(input)),
        "sast:scan" => Some(wants_sast_runtime(input)),
        _ => None,
    }
}

fn context_build_needs_runtime(input: &Value) -> bool {
    input
        .get("enrichment")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || input
            .get("scope")
            .and_then(Value::as_str)
            .is_some_and(|scope| scope == "enrichment")
}

fn patch_reverify_needs_runtime(input: &Value) -> bool {
    let Some(tool) = input.get("detectorTool").and_then(Value::as_str) else {
        return false;
    };
    if tool == "patch:reverify" {
        return false;
    }
    let detector_input = input.get("detectorInput").unwrap_or(&Value::Null);
    tool_needs_runtime(tool, detector_input)
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

/// All descriptor-declared runtime tools, including hidden DAG nodes, sorted
/// by tool name. This compatibility view is derived from the registry snapshot;
/// dispatch callers should prefer the descriptor-backed predicates above.
pub fn agent_runtime_tool_names() -> &'static [&'static str] {
    static NAMES: OnceLock<Vec<&'static str>> = OnceLock::new();
    NAMES
        .get_or_init(|| {
            shared_tool_policies()
                .iter()
                .filter(|(_, policy)| policy.runtime != crate::modules::RuntimeRequirement::Never)
                .map(|(name, _)| name.as_str())
                .collect()
        })
        .as_slice()
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
    let triage_runtime = any_true_input(input, &["triage", "aiTriage", "ai_triage"]);
    let execution_runtime =
        !whitebox_static && any_true_input(input, &["verify", "autoPatch", "auto_patch"]);

    triage_runtime || execution_runtime || sast_tasks_request_runtime(input)
}

fn any_true_input(input: &Value, names: &[&str]) -> bool {
    names
        .iter()
        .any(|name| input.get(name).and_then(Value::as_bool).unwrap_or(false))
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
                "{tool} bails without a runtime but its descriptor does not declare one"
            );
        }
    }

    #[test]
    fn input_aware_runtime_is_declared_without_forcing_every_input() {
        assert!(tool_uses_agent_runtime("sast:scan"));
        assert!(!tool_requires_agent_runtime("sast:scan"));
    }

    #[test]
    fn context_build_runtime_tracks_enrichment_inputs() {
        assert!(tool_uses_agent_runtime("context:build"));
        assert!(!tool_requires_agent_runtime("context:build"));
        assert!(!tool_needs_runtime("context:build", &json!({})));
        assert!(tool_needs_runtime(
            "context:build",
            &json!({"enrichment": true})
        ));
        assert!(tool_needs_runtime(
            "context:build",
            &json!({"scope": "enrichment"})
        ));
    }

    #[test]
    fn tool_needs_runtime_covers_sast_scan_input_nuance() {
        assert!(tool_needs_runtime("sast:scan", &json!({"triage": true})));
        assert!(tool_needs_runtime("sast:scan", &json!({"verify": true})));
        assert!(tool_needs_runtime(
            "sast:scan",
            &json!({"verify": false, "autoPatch": true})
        ));
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
    fn execution_receipts_name_only_models_that_the_tool_will_use() {
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-5.5".to_string());

        assert_eq!(
            tool_execution_model("recon:import", &json!({}), &config),
            None
        );
        assert_eq!(
            tool_execution_model("deep-audit:run", &json!({}), &config).as_deref(),
            Some("openai:gpt-5.5")
        );
        assert_eq!(
            tool_execution_model(
                "threat-model:build",
                &json!({"model": "anthropic:claude-sonnet-4-6"}),
                &config,
            )
            .as_deref(),
            Some("anthropic:claude-sonnet-4-6")
        );
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
    fn threat_model_build_is_model_backed_by_default() {
        assert!(tool_uses_agent_runtime("threat-model:build"));
        assert!(tool_needs_runtime("threat-model:build", &json!({})));
        assert!(tool_needs_runtime(
            "threat-model:build",
            &json!({"model": "openai:gpt-5.4"})
        ));
    }

    #[test]
    fn threat_model_build_skips_runtime_only_for_explicit_deterministic_pipeline() {
        assert!(!tool_needs_runtime(
            "threat-model:build",
            &json!({"pipeline": "deterministic"})
        ));

        let mut config = V2Config::default();
        config.model = Some("openai:gpt-5.4".to_string());
        assert!(!tool_wants_runtime(
            "threat-model:build",
            &json!({"pipeline": "deterministic"}),
            &config
        ));
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
    fn tool_needs_runtime_reads_descriptor_policy_for_other_tools() {
        assert!(tool_needs_runtime("deep-audit:run", &json!({})));
        assert!(tool_needs_runtime("exploit-chain:scan", &json!({})));
        assert!(tool_needs_runtime("uaf-hunt:hunt", &json!({})));
        assert!(!tool_needs_runtime("findings:list", &json!({})));
        // Of the corpus-honesty verbs, only the model-driven dedupe judge
        // needs a runtime; grounding and threat-model verify/import are
        // deterministic.
        assert!(tool_needs_runtime("triage:dedupe", &json!({})));
        assert!(!tool_needs_runtime("findings:ground", &json!({})));
        assert!(!tool_needs_runtime("threat-model:verify", &json!({})));
        assert!(!tool_needs_runtime("threat-model:import", &json!({})));
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
    fn finding_store_tools_always_receive_workspace_resolution() {
        let registry = crate::modules::registry::ModuleRegistry::with_v2_builtins();
        for tool in registry.tools().filter(|tool| {
            tool.finding_store_requirement == crate::modules::FindingStoreRequirement::Required
        }) {
            assert!(tool_defaults_to_workspace(&tool.name), "{}", tool.name);
        }
    }

    #[test]
    fn tools_that_persist_findings_get_a_store() {
        for tool in [
            "dep-hygiene:check",
            "secret-scan:scan",
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
