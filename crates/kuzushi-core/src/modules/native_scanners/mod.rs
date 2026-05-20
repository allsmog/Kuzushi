use super::*;

use self::{
    binary_option, builtin_module, dag, opt, resolve_tool_target, target_option, tool_with_options,
};
use crate::findings::{persist_tool_findings, Finding, GenericPersistedRun, StaticProofState};
use crate::iac_scan::{scan_iac, IacScanOptions};
use crate::runtime::AgentRuntime;
use crate::scan::{
    index_codeql_sarif_as_static_evidence, scan_exploit_chains_with_runtime, CodeqlPersistedRun,
    CodeqlScanReport, CodeqlScanner, ExploitChainReport, ExploitChainScanner, ScanCancellation,
    SemgrepPersistedRun, SemgrepScanReport, SemgrepScanner,
};
use crate::whitebox_static::{mark_whitebox_static_findings, whitebox_static_profile_requested};
use anyhow::Result;
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
pub(in crate::modules) use android_apk_taint_sources::*;
pub(in crate::modules) use android_apk_toolchain::*;
pub(in crate::modules) use android_apk_webview_scan::*;
pub(in crate::modules) use persist_semgrep_findings::*;
pub(in crate::modules) use run_android_apk::*;
pub(in crate::modules) use semgrep_module::*;
use serde_json::{json, Value};
use std::path::Path;
use uuid::Uuid;
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
mod android_apk_taint_sources;
mod android_apk_toolchain;
mod android_apk_webview_scan;
mod persist_semgrep_findings;
mod register_modules;
mod run_android_apk;
mod semgrep_module;
pub(in crate::modules) use register_modules::{execute_tool, register_modules};
