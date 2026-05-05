pub mod carlini_threat_hunt;
pub mod config;
pub mod dep_hygiene;
pub mod events;
pub mod findings;
pub mod iac_scan;
pub mod modules;
pub mod patch;
pub mod recon;
pub mod runtime;
pub mod scan;
pub mod secret_scan;
pub mod systems_hunt;
pub mod threat_model;
pub mod variant_ndiff;
pub mod workspace;
pub mod x_ray;

pub use carlini_threat_hunt::{run_carlini_threat_hunt, run_carlini_threat_hunt_report};
pub use config::{
    load_config, load_config_for_target, ConfigPaths, RuntimeConfig, RuntimeKind, V2Config,
};
pub use dep_hygiene::{
    analyze_manifest as analyze_dep_hygiene_manifest, check_dependency_hygiene, DepHygieneFinding,
    DepHygieneReport, DepHygieneScanner, DepHygieneSeverity, ManifestKind,
};
pub use findings::{
    Finding, FindingListFilter, FindingListReport, FindingStore, FindingVerdictFilter,
    PatchAttempt, PatchResult, PatchStatus, Severity, TriageOutcome, TriageVerdict,
};
pub use iac_scan::{
    scan_iac, IacScanFinding, IacScanKind, IacScanOptions, IacScanReport, IacScanScanner,
};
pub use modules::{BuiltinModule, ModuleMetadata, ModuleRegistry, ToolDescriptor};
pub use patch::run_patch_finding;
pub use recon::{execute_recon_tool, ReconHost, ReconNote, ReconService, ReconWorkspaceStore};
pub use runtime::{AgentQueryRequest, AgentQueryResponse, AgentRuntime, TriageRequest};
pub use scan::{
    default_scan_engines, normalize_codeql_sarif, normalize_semgrep_json, run_scan_engines,
    run_semgrep_scan, scan_engines_for_tasks, CodeqlScanner, ScanCancellation, ScanEngine, ScanRun,
    SemgrepScanner,
};
pub use secret_scan::{
    scan_for_secrets, SecretScanFinding, SecretScanOptions, SecretScanReport, SecretScanScanner,
    SecretSeverity,
};
pub use systems_hunt::{execute_systems_hunt_tool, run_systems_hunt_report, SystemsHuntReport};
pub use threat_model::execute_threat_model_tool;
pub use workspace::WorkspaceTarget;
pub use x_ray::{execute_x_ray_tool, read_x_ray_report_artifacts, XRayReportData};
