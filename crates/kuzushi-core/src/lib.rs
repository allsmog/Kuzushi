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
    engagement, event_log, events, evidence, findings, full_mode_multi, iac_scan, identity, incremental_index,
    license_scan, modules, offense, options, patch, plugin_sandbox, pr_comment, prompt_stack, prompts, proof, recon,
    remediation, report, repository_inventory, run_artifacts,
    run_trace, runbooks, runtime, sbom_scan, scan, scanners, secret_scan, semgrep_rule_synthesis, source_span, spend, static_context,
    static_evidence, static_narrative, static_proof_validator, static_ranking, static_registry, storage_v3,
    strategy, systems_hunt, threat_leads, threat_model, triage, variant_ndiff, verification, verify,
    whitebox_static, whitebox_suppressions, worker_protocol, workspace, x_ray,
);

pub(crate) mod artifact_contract;
pub(crate) mod codeql_build_mode;
pub(crate) mod fs_atomic;
pub(crate) mod module_result;
pub(crate) mod process_lookup;
pub(crate) mod structured_output;
#[cfg(test)]
pub(crate) mod test_env;

mod code_index;
mod public_exports;
pub use demo::{offline_demo_scan_input, offline_demo_task_labels, prepare_demo_fixture};
pub use public_exports::*;
