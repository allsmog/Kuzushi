pub use kuzushi_cpg::{
    artifact_dir as cpg_artifact_dir, artifact_langs as cpg_artifact_langs,
    supported_languages as cpg_supported_languages, GRAPH_SHAPE_VERSION as CPG_GRAPH_SHAPE_VERSION,
};

pub use crate::attack_surface::{
    build_attack_surface_map, build_attack_surface_map_from_inventory, AttackSurface,
    AttackSurfaceKind, AttackSurfaceMap, AttackSurfaceRisk, AttackSurfaceSummary,
};
pub use crate::capabilities::classifier_gate::{
    ClassifierConfig, LikelyVulnClassifier, QuantileEstimator, Score,
};
pub use crate::capabilities::deep_auditor::{
    record_evidence, run_deep_auditor, DeepAuditConfig, DeepAuditOutcome, EvidenceCitation,
    VulnAnalysis,
};
pub use crate::capabilities::full_mode_multi::{
    cost_summary as full_mode_cost_summary, plan as full_mode_plan, report_to_tool_json,
    run as run_full_mode_multi, ChunkPlan, CostSummary, FileBucket, FullModeConfig,
    FullModeLanguage, FullModePlan, FullModeReport,
};
pub use crate::capabilities::semgrep_rule_synthesis::{
    synthesize_candidate_semgrep_rules, SemgrepCandidateRule, SemgrepRuleFixture,
    SemgrepRuleSynthesisReport, SemgrepRuleValidation,
};
pub use crate::capabilities::systems_hunt::{
    execute_systems_hunt_tool, gather_surfaces, run_systems_hunt_report, RankedSystemsSurface,
    SystemsContextMetadata, SystemsContextOutput, SystemsHuntReport,
};
pub use crate::carlini_threat_hunt::{
    run_carlini_threat_hunt, run_carlini_threat_hunt_report, CarliniThreatHuntPersistedRun,
    CarliniThreatHuntReport,
};
pub use crate::dep_hygiene::{
    analyze_manifest as analyze_dep_hygiene_manifest, check_dependency_hygiene,
    parse_cargo_audit_output, CargoAuditScanner, DepHygieneFinding, DepHygieneReport,
    DepHygieneScanner, DepHygieneSeverity, ManifestKind,
};
pub use crate::diff_scope::{
    build_whitebox_diff_scope_report, git_diff_files, ChangedFile, ChangedLineRange, DiffContext,
    DiffContextKind, DiffFileStatus, DiffFindingStatus, DiffFindingTag, DiffRangeKind, DiffScope,
    DiffScopeSummary, WhiteboxDiffScopeReport,
};
pub use crate::iac_scan::{
    scan_iac, IacScanFinding, IacScanKind, IacScanOptions, IacScanReport, IacScanScanner,
};
pub use crate::license_scan::{
    scan_licenses, scan_licenses_with_options, LicenseScanFinding, LicenseScanOptions,
    LicenseScanReport, LicenseScanScanner,
};
pub use crate::recon::{
    execute_recon_tool, ReconHost, ReconNote, ReconService, ReconWorkspaceStore,
};
pub use crate::sbom_scan::{
    scan_sbom, SbomComponent, SbomDependencyEdge, SbomLockfile, SbomScanReport,
};
pub use crate::scan::{
    default_scan_engines, index_codeql_sarif_as_static_evidence, normalize_codeql_sarif,
    normalize_semgrep_json, parse_govulncheck_json, run_scan_engines, run_semgrep_scan,
    scan_engines_for_tasks, CodeqlScanner, GovulncheckScanner, ScanCancellation, ScanEngine,
    ScanEngineOutput, ScanRun, ScanRunOptions, SemgrepScanner,
};
pub use crate::secret_scan::{
    scan_for_secrets, SecretScanFinding, SecretScanOptions, SecretScanReport, SecretScanScanner,
    SecretSeverity,
};
pub use crate::threat_model::{
    execute_threat_model_tool, load_persistent_threat_model, save_persistent_threat_model,
    try_load_persistent_threat_model,
};
pub use crate::variant_ndiff::{
    derive_whitebox_variant_patterns, hunt_whitebox_static_variants, WhiteboxVariantPattern,
    WhiteboxVariantSearchReport,
};
pub use crate::x_ray::{execute_x_ray_tool, read_x_ray_report_artifacts, XRayReportData};
