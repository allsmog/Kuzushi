/// Code-index facade and routing primitives, re-exported so other
/// modules don't need to take a separate dep on `kuzushi-codeindex`.
macro_rules! public_modules {
    ($($module:ident),+ $(,)?) => {
        $(pub mod $module;)+
    };
}

#[rustfmt::skip]
public_modules!(
    agent_router, artifact_kb, attachments, attack_surface, capabilities, carlini_threat_hunt,
    classifier_gate, code_nav, concurrency, config, content_store, context, deep_auditor, demo, dep_hygiene, diff_scope,
    engagement, event_log, events, evidence, findings, fleet, full_mode_multi, iac_scan, identity, incremental_index,
    license_scan, modules, offense, options, patch, plugin_sandbox, pr_comment, prompt_stack, prompts, proof, query, recon,
    progress, remediation, report, repository_inventory, review_yield, run_artifacts, run_lifecycle,
    session_transcript,
    run_trace, runbooks, runtime, sbom_scan, scan, scanners, secret_scan, semantic_cache, semgrep_rule_synthesis, source_span, spend, static_context,
    static_evidence, static_narrative, static_proof_validator, static_ranking, static_registry, storage_v3,
    strategy, suppressions, systems_hunt, text, threat_leads, threat_model, triage, variant_ndiff, verification, verify,
    workflow_attempts,
    whitebox_static, whitebox_suppressions, worker_protocol, workspace, x_ray,
);

pub(crate) mod artifact_contract;
pub(crate) mod bounded_file;
pub(crate) mod bounded_subprocess;
mod checkpoint_limits;
pub(crate) mod codeql_build_mode;
pub(crate) mod codeql_repository_execution;
#[cfg(test)]
mod env_boundary_lint;
pub(crate) mod file_lock;
pub(crate) mod fs_atomic;
pub(crate) mod git_rev;
pub(crate) mod jsonl_tail;
pub(crate) mod module_result;
#[cfg(test)]
mod panic_surface_lint;
pub(crate) mod process_lookup;
mod runtime_diagnostics;
pub(crate) mod sqlite_connection;
pub(crate) mod structured_output;
#[cfg(test)]
mod terminal_output_lint;
#[cfg(test)]
pub(crate) mod test_env;
pub(crate) mod yaml;

mod code_index;
mod public_exports;
pub use demo::{
    is_demo_fixture_path, offline_demo_scan_input, offline_demo_task_labels, prepare_demo_fixture,
};
pub use public_exports::*;
pub use runtime_diagnostics::{take_runtime_diagnostics, RuntimeDiagnostic};
