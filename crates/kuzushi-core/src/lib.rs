pub mod artifact_kb;
pub mod attachments;
pub mod attack_surface;
pub mod carlini_threat_hunt;
pub mod config;
pub mod dep_hygiene;
pub mod events;
pub mod findings;
pub mod iac_scan;
pub mod modules;
pub mod options;
pub mod patch;
pub mod pr_comment;
pub mod recon;
pub mod repository_inventory;
pub mod runtime;
pub mod scan;
pub mod secret_scan;
pub mod source_span;
pub mod static_evidence;
pub mod static_narrative;
pub mod static_proof_validator;
pub mod static_ranking;
pub mod static_registry;
pub mod systems_hunt;
pub mod threat_model;
pub mod variant_ndiff;
pub mod whitebox_static;
pub mod workspace;
pub mod x_ray;

pub use artifact_kb::{
    artifact_kb_path, artifact_knowledge_prompt_context, index_workspace_artifacts,
    search_artifact_knowledge, ArtifactIndexReport, ArtifactKnowledgePromptContext,
    ArtifactKnowledgeRecord, ArtifactKnowledgeSnippet, ArtifactKnowledgeStore,
    ArtifactSearchReport, ArtifactSearchResult, StaleArtifactRecord,
};
pub use attachments::{
    attach_source, attachment_store_path, detach_source, is_supported_attachment_module,
    known_artifacts, list_attachments, reparse_source, AttachmentKind, AttachmentRecord,
    KnownArtifact, SUPPORTED_ATTACHMENT_MODULES,
};
pub use attack_surface::{
    build_attack_surface_map, build_attack_surface_map_from_inventory, AttackSurface,
    AttackSurfaceKind, AttackSurfaceMap, AttackSurfaceSummary,
};
pub use carlini_threat_hunt::{run_carlini_threat_hunt, run_carlini_threat_hunt_report};
pub use config::{
    load_config, load_config_for_target, ConfigPaths, RuntimeConfig, RuntimeKind, V2Config,
};
pub use dep_hygiene::{
    analyze_manifest as analyze_dep_hygiene_manifest, check_dependency_hygiene, DepHygieneFinding,
    DepHygieneReport, DepHygieneScanner, DepHygieneSeverity, ManifestKind,
};
pub use findings::{
    format_finding_alias, parse_finding_alias, resolve_finding_alias, sorted_finding_aliases,
    stable_finding_alias, Finding, FindingListFilter, FindingListReport, FindingStore,
    FindingVerdictFilter, PatchAttempt, PatchResult, PatchStatus, Severity, StaticProofState,
    TriageOutcome, TriageVerdict,
};
pub use iac_scan::{
    scan_iac, IacScanFinding, IacScanKind, IacScanOptions, IacScanReport, IacScanScanner,
};
pub use modules::{BuiltinModule, ModuleMetadata, ModuleRegistry, ToolDescriptor};
pub use options::{OptionScope, OptionTarget, ToolOptionStore};
pub use patch::run_patch_finding;
pub use pr_comment::{build_pr_comment, PrCommentInput};
pub use recon::{execute_recon_tool, ReconHost, ReconNote, ReconService, ReconWorkspaceStore};
pub use repository_inventory::{
    build_repository_inventory, InventoryEntrypoint, InventoryFile, InventoryFramework,
    InventoryLanguage, InventoryPathClassification, InventoryRouteController, InventorySourceFile,
    RepositoryInventory,
};
pub use runtime::{
    AgentQueryRequest, AgentQueryResponse, AgentRuntime, AgentToolPolicy, TriageRequest,
};
pub use scan::{
    default_scan_engines, index_codeql_sarif_as_static_evidence, normalize_codeql_sarif,
    normalize_semgrep_json, run_scan_engines, run_semgrep_scan, scan_engines_for_tasks,
    CodeqlScanner, ScanCancellation, ScanEngine, ScanEngineOutput, ScanRun, ScanRunOptions,
    SemgrepScanner,
};
pub use secret_scan::{
    scan_for_secrets, SecretScanFinding, SecretScanOptions, SecretScanReport, SecretScanScanner,
    SecretSeverity,
};
pub use source_span::{extract_source_span, SourceSpan};
pub use static_evidence::{
    index_semgrep_findings_as_static_evidence, static_content_hash, static_evidence_path,
    StaticEvidenceEdge, StaticEvidenceEdgeKind, StaticEvidenceIndexReport, StaticEvidenceNode,
    StaticEvidenceNodeKind, StaticEvidenceStore, STATIC_EVIDENCE_EDGE_KINDS,
    STATIC_EVIDENCE_NODE_KINDS,
};
pub use static_narrative::{
    build_static_narrative_report, validate_static_narrative_text, StaticFindingNarrative,
    StaticNarrativeReport,
};
pub use static_proof_validator::{
    static_proof_claim_from_whitebox_schema, validate_static_proof_claim,
    verify_static_proof_citation, StaticProofAssessment, StaticProofAssessmentStatus,
    StaticProofCitation, StaticProofClaim, StaticProofEvidence, StaticProofValidation,
    VerifiedStaticProofCitation,
};
pub use static_ranking::{
    rank_static_findings, score_static_finding, StaticImpactFactors, StaticImpactScore,
    StaticRankedFinding,
};
pub use static_registry::{
    default_static_registry, match_static_registry, static_registry_version, StaticRegistryEntry,
    StaticRegistryKind, StaticRegistryMatch, StaticRegistryPatternKind, StaticRegistryQuery,
    STATIC_REGISTRY_VERSION,
};
pub use systems_hunt::{execute_systems_hunt_tool, run_systems_hunt_report, SystemsHuntReport};
pub use threat_model::{
    execute_threat_model_tool, load_persistent_threat_model, save_persistent_threat_model,
};
pub use whitebox_static::{
    agent_tool_policy_for_input, analysis_mode_from_input, apply_whitebox_static_sast_policy,
    default_whitebox_static_agent_tool_policy, mark_whitebox_static_findings,
    validate_whitebox_static_agent_tool_policy, whitebox_static_enabled,
    whitebox_static_profile_requested, whitebox_static_proof_state_from_input,
    whitebox_static_proof_state_from_str, AnalysisMode, WhiteboxStaticPolicy,
};
pub use workspace::{
    export_workspace_findings, WorkspaceExportFormat, WorkspaceFindingsExport, WorkspaceTarget,
};
pub use x_ray::{execute_x_ray_tool, read_x_ray_report_artifacts, XRayReportData};
