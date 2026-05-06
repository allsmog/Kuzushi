pub mod agent_router;
pub mod artifact_kb;
pub mod attachments;
pub mod carlini_threat_hunt;
pub mod classifier_gate;
pub mod code_nav;
pub mod config;
pub mod deep_auditor;
pub mod dep_hygiene;
pub mod events;
pub mod findings;
pub mod full_mode_multi;
pub mod iac_scan;
pub mod modules;
pub mod options;
pub mod patch;
pub mod pr_comment;
pub mod recon;
pub mod runtime;
pub mod scan;
pub mod secret_scan;
pub mod spend;
pub mod systems_hunt;
pub mod threat_model;
pub mod variant_ndiff;
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
pub use agent_router::{AgentRole, AgentRouter, ModelRoute, RoutedRuntime};
pub use carlini_threat_hunt::{run_carlini_threat_hunt, run_carlini_threat_hunt_report};
pub use code_nav::{
    code_nav_tool_specs, code_nav_toolbox, find_references_tool, list_definitions_tool,
    read_definition_tool, read_source_tool, CodeNavConfig, CodeNavTool,
};
pub use classifier_gate::{
    ClassifierConfig, LikelyVulnClassifier, QuantileEstimator, Score,
};
pub use deep_auditor::{
    run_deep_auditor, save_evidence, DeepAuditConfig, DeepAuditOutcome, EvidenceCitation,
    VulnAnalysis,
};
pub use config::{
    load_config, load_config_for_target, AnthropicOauthConfig, ConfigPaths, RuntimeConfig,
    RuntimeKind, V2Config,
};
pub use dep_hygiene::{
    analyze_manifest as analyze_dep_hygiene_manifest, check_dependency_hygiene, DepHygieneFinding,
    DepHygieneReport, DepHygieneScanner, DepHygieneSeverity, ManifestKind,
};
pub use findings::{
    Finding, FindingListFilter, FindingListReport, FindingStore, FindingVerdictFilter,
    PatchAttempt, PatchResult, PatchStatus, Severity, TriageOutcome, TriageVerdict,
};
pub use full_mode_multi::{
    cost_summary as full_mode_cost_summary, plan as full_mode_plan, report_to_tool_json,
    run as run_full_mode_multi, ChunkPlan, CostSummary, FileBucket, FullModeConfig,
    FullModeLanguage, FullModePlan, FullModeReport,
};
pub use iac_scan::{
    scan_iac, IacScanFinding, IacScanKind, IacScanOptions, IacScanReport, IacScanScanner,
};
pub use modules::{BuiltinModule, ModuleMetadata, ModuleRegistry, ToolDescriptor};
pub use options::{OptionScope, OptionTarget, ToolOptionStore};
pub use patch::run_patch_finding;
pub use pr_comment::{build_pr_comment, PrCommentInput};
pub use recon::{execute_recon_tool, ReconHost, ReconNote, ReconService, ReconWorkspaceStore};
pub use runtime::{
    run_tool_loop, AgentLoopOutcome, AgentLoopStep, AgentQueryRequest, AgentQueryResponse,
    AgentRuntime, AgentTool, AgentToolLoopRequest, LoopHistoryEntry, ToolBox, ToolCall,
    ToolCallHandler, ToolResult, TriageRequest,
};
pub use scan::{
    default_scan_engines, normalize_codeql_sarif, normalize_semgrep_json, run_scan_engines,
    run_semgrep_scan, scan_engines_for_tasks, CodeqlScanner, ScanCancellation, ScanEngine, ScanRun,
    ScanRunOptions, SemgrepScanner,
};
pub use secret_scan::{
    scan_for_secrets, SecretScanFinding, SecretScanOptions, SecretScanReport, SecretScanScanner,
    SecretSeverity,
};
pub use spend::{parse_budget_flag, Operation as SpendOperation, SpendError, SpendLimiter, SpendTicket};
pub use systems_hunt::{execute_systems_hunt_tool, run_systems_hunt_report, SystemsHuntReport};
pub use threat_model::{
    execute_threat_model_tool, load_persistent_threat_model, save_persistent_threat_model,
};
pub use workspace::{
    export_workspace_findings, WorkspaceExportFormat, WorkspaceFindingsExport, WorkspaceTarget,
};
pub use x_ray::{execute_x_ray_tool, read_x_ray_report_artifacts, XRayReportData};
