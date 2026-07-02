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
    classifier_gate, code_nav, concurrency, config, context, deep_auditor, dep_hygiene, diff_scope,
    events, evidence, findings, full_mode_multi, iac_scan, license_scan, modules, offense, options, patch,
    pr_comment, prompt_stack, proof, recon, remediation, report, repository_inventory, run_artifacts, run_trace, runtime,
    sbom_scan, scan, scanners, secret_scan, semgrep_rule_synthesis, source_span, spend, static_context,
    static_evidence, static_narrative, static_proof_validator, static_ranking, static_registry,
    strategy, systems_hunt, threat_leads, threat_model, triage, variant_ndiff, verification, verify,
    whitebox_static, whitebox_suppressions, workspace, x_ray,
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
pub use public_exports::*;
