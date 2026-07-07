mod application;
pub mod artifact_kb;
pub mod artifacts;
pub mod attack_surface;
pub mod diff_scope;
mod domain;
mod git_metadata;
pub mod inventory;
pub mod source_span;

#[cfg(test)]
mod tests;

pub use application::{
    active_workspace_required_message, build_project_model_document,
    discover_and_save_nested_project_scopes, discover_nested_project_scopes,
    export_workspace_findings, export_workspace_findings_with_options,
    findings_since_filter_expression, load_nested_project_scopes, load_program_scope,
    load_project_model_document, preview_workspace_findings_export, project_model_scope_path,
    record_user_review_decision_for_finding, record_user_review_decision_for_finding_at_watermark,
    refresh_project_model_staleness, save_nested_project_scopes, save_project_model_document,
    workspace_export_omitted_fields, workspace_finding_export_records_with_context,
    workspace_finding_export_records_with_reviews, workspace_status_for_target,
    write_program_scope_scaffold, ProjectModelDocument, ProjectModelSection,
    ProjectModelSectionOrigin, WorkspaceAnalysisExportSummary,
    WorkspaceEvidenceExportSummary, WorkspaceFindingExportLocation, WorkspaceFindingExportRecord,
    WorkspaceFindingProvenanceSummary, WorkspaceFindingReviewContext, WorkspaceFindingsExportPreview,
    WorkspaceRunExportContext, WorkspaceStatus, WorkspaceVerificationExportSummary,
    PROJECT_MODEL_SCHEMA_VERSION,
};
pub use artifact_kb::*;
pub use artifacts::{artifact_state, ArtifactState};
pub use attack_surface::*;
pub use diff_scope::*;
pub use domain::{
    legacy_codeql_db_path, project_model_dir, project_model_scopes_path,
    workspace_artifact_kb_db_path, workspace_attachments_path, workspace_codeql_db_path,
    workspace_config_path, workspace_event_log_dir, workspace_findings_db_path, workspace_history_path,
    workspace_models_path, workspace_objects_dir, workspace_options_path, workspace_state_dir,
    workspace_state_root, workspace_static_evidence_db_path, workspace_suppressions_path,
    HostPattern, NestedProjectKind,
    NestedProjectScope, NestedProjectScopeTree, ProgramScope, ProgramScopeFile, ProgramScopeList,
    ScopeVerdict, WorkspaceExportCompleteness, WorkspaceExportFormat, WorkspaceExportOptions,
    WorkspaceFindingsExport, WorkspaceTarget, KUZUSHI_STATE_DIR, LEGACY_CODEQL_DB_DIR,
    LEGACY_CODEQL_STATE_DIR, PROJECT_MODEL_DIR, PROJECT_MODEL_SCOPES_FILE, ROOT_SCOPE_ID,
    WORKSPACE_ARTIFACT_KB_DB_FILE, WORKSPACE_ATTACHMENTS_FILE, WORKSPACE_CODEQL_DB_DIR,
    WORKSPACE_CONFIG_FILE, WORKSPACE_EVENT_LOG_DIR, WORKSPACE_FINDINGS_DB_FILE, WORKSPACE_MODELS_FILE,
    WORKSPACE_OBJECTS_DIR, WORKSPACE_OPTIONS_FILE, WORKSPACE_STATE_VERSION_DIR,
    WORKSPACE_STATIC_EVIDENCE_DB_FILE, WORKSPACE_SUPPRESSIONS_FILE,
};
pub use git_metadata::{
    resolve_target_git_commit, switch_target_revision, target_git_metadata, TargetRevisionSwitch,
};
pub use inventory::*;
pub use source_span::*;
