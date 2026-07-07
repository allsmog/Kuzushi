use super::*;

#[allow(unused_imports)]
use self::agentic_sast::run_agentic_sast_report;
#[allow(unused_imports)]
use self::options::validate_tool_input_options;
#[allow(unused_imports)]
use self::pipeline::{run_pipeline_approval_gate, run_pipeline_task_selector};
#[allow(unused_imports)]
use self::workspace_tools::{export_workspace_findings_tool, workspace_status_output};
#[allow(unused_imports)]
use self::{
    agentic_sast_module, carlini_threat_hunt_module, catalog_module, chrome_rce,
    classifier_gate_module, config_module, context, deep_audit_module, dep_hygiene_module,
    findings_module, full_mode_module, native_scanners, ndiff_module, offense_review_module,
    patch_module, pipeline_module, plugin_adapters, prompt_armor, randori_module, recon_module,
    report_module, resolve_tool_target, router_module, router_show_tool, run_classifier_score_tool,
    run_deep_audit_tool, run_full_mode_hunt_tool, sast_module, secret_scan_module,
    systems_hunt_module, taint_iris_module, taint_iris_next_module, threat_leads_module,
    threat_model_module, triage_module, variant_module, vendor_assessment, verify_module,
    workspace_module, x_ray_module,
};
use crate::capabilities::systems_hunt::execute_systems_hunt_tool;
use crate::capabilities::uaf_hunt::execute_uaf_hunt_tool;
use crate::carlini_threat_hunt::run_carlini_threat_hunt;
use crate::dep_hygiene::check_dependency_hygiene;
use crate::findings::FindingListFilter;
use crate::modules::application::sast_scan::run_sast_scan_with_registry;
#[allow(unused_imports)]
use crate::options::ToolOptionStore;
use crate::recon::execute_recon_tool;
use crate::remediation::patch::run_patch_finding;
use crate::scan::ScanCancellation;
use crate::secret_scan::{scan_for_secrets, SecretScanOptions};
use crate::threat_leads::execute_threat_leads_tool;
use crate::threat_model::execute_threat_model_tool;
use crate::variant_ndiff::{
    run_ndiff_extract_fix_pattern, run_ndiff_fetch_cve, run_ndiff_hunt_variants, run_variant_hunt,
    run_variant_lift_pattern,
};
use crate::x_ray::execute_x_ray_tool;
use anyhow::{Context, Result};
pub(in crate::modules) use dispatch_catalog_tool::*;
pub(in crate::modules) use dispatch_plugin_prompt_tool::*;
pub(in crate::modules) use module_registry::*;
pub(in crate::modules) use run_taint_iris_tool::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
mod dispatch_catalog_tool;
mod dispatch_plugin_prompt_tool;
mod module_registry;
mod run_taint_iris_tool;
#[cfg(test)]
mod tests;
pub use module_registry::ModuleRegistry;
