use super::*;

use self::{
    binary_option, builtin_module, dag, model_option, opt, resolve_tool_target, target_option,
    tool_with_options,
};
use crate::dep_hygiene::CargoAuditScanner;
use crate::findings::{persist_tool_findings, Finding, GenericPersistedRun, StaticProofState};
use crate::iac_scan::{scan_iac, IacScanOptions};
use crate::license_scan::{scan_licenses_with_options, LicenseScanOptions};
use crate::runtime::AgentRuntime;
use crate::sbom_scan::scan_sbom;
use crate::scan::{
    index_codeql_sarif_documents_as_static_evidence, scan_exploit_chains_with_runtime,
    CodeqlPersistedRun,
    CodeqlScanReport, CodeqlScanner, ExploitChainReport, ExploitChainScanner, GovulncheckScanner,
    ScanEngine, ScanEngineOutput, SemgrepPersistedRun, SemgrepScanReport, SemgrepScanner,
};
use crate::whitebox_static::{
    mark_whitebox_static_findings, whitebox_static_profile_requested,
    whitebox_static_proof_state_from_input,
};
pub(in crate::modules) use android_apk_code_scan::*;
pub(in crate::modules) use android_apk_fileprovider::*;
pub(in crate::modules) use android_apk_hybrid_detect::*;
pub(in crate::modules) use android_apk_manifest_parser::*;
pub(in crate::modules) use android_apk_manifest_parser_state::*;
pub(in crate::modules) use android_apk_manifest_scan::*;
pub(in crate::modules) use android_apk_module::*;
pub(in crate::modules) use android_apk_native_elf::*;
pub(in crate::modules) use android_apk_native_libs::*;
pub(in crate::modules) use android_apk_network_security::*;
pub(in crate::modules) use android_apk_nsc_parser::*;
pub(in crate::modules) use android_apk_prepare::*;
pub(in crate::modules) use android_apk_sast_handoff::*;
pub(in crate::modules) use android_apk_scan::*;
pub(in crate::modules) use android_apk_taint_sources::*;
pub(in crate::modules) use android_apk_toolchain::*;
use anyhow::{Context, Result};
pub(in crate::modules) use persist_semgrep_findings::*;
pub(in crate::modules) use run_android_apk::*;
pub(in crate::modules) use semgrep_module::*;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
mod android_apk_code_scan;
mod android_apk_fileprovider;
mod android_apk_hybrid_detect;
mod android_apk_manifest_parser;
mod android_apk_manifest_parser_state;
mod android_apk_manifest_scan;
mod android_apk_module;
mod android_apk_native_elf;
mod android_apk_native_libs;
mod android_apk_network_security;
mod android_apk_nsc_parser;
mod android_apk_prepare;
mod android_apk_sast_handoff;
mod android_apk_scan;
mod android_apk_taint_sources;
mod android_apk_toolchain;
mod exploit_chain_output;
mod persist_semgrep_findings;
mod register_modules;
mod run_android_apk;
mod semgrep_module;
use exploit_chain_output::exploit_chain_output;
pub(in crate::modules) use register_modules::{execute_tool, register_modules};

fn validated_android_workspace_path(
    workspace_root: &Path,
    candidate: &Path,
    expect_directory: bool,
) -> Result<PathBuf> {
    let relative = candidate.strip_prefix(workspace_root).map_err(|_| {
        anyhow::anyhow!(
            "android-apk path {} must stay inside workspace {}",
            candidate.display(),
            workspace_root.display()
        )
    })?;
    let path = crate::workspace::validated_workspace_descendant(workspace_root, relative)?;
    let metadata = std::fs::symlink_metadata(&path)
        .with_context(|| format!("Could not inspect android-apk path {}", path.display()))?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink()
            && if expect_directory {
                metadata.file_type().is_dir()
            } else {
                metadata.file_type().is_file()
            },
        "android-apk path is not a real {}: {}",
        if expect_directory {
            "directory"
        } else {
            "file"
        },
        path.display()
    );
    Ok(path)
}

fn validated_android_workspace_dir(workspace_root: &Path, candidate: &Path) -> Result<PathBuf> {
    validated_android_workspace_path(workspace_root, candidate, true)
}

fn validated_android_workspace_file(workspace_root: &Path, candidate: &Path) -> Result<PathBuf> {
    validated_android_workspace_path(workspace_root, candidate, false)
}
