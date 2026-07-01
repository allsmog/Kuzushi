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
    build_project_model_document, export_workspace_findings, load_program_scope,
    load_project_model_document, project_model_scope_path, refresh_project_model_staleness,
    save_project_model_document, workspace_status_for_target, ProjectModelDocument,
    ProjectModelSection, ProjectModelSectionOrigin, WorkspaceStatus, PROJECT_MODEL_SCHEMA_VERSION,
};
pub use artifact_kb::*;
pub use artifacts::{artifact_state, ArtifactState};
pub use attack_surface::*;
pub use diff_scope::*;
pub use domain::{
    discover_and_save_nested_project_scopes, discover_nested_project_scopes,
    legacy_codeql_db_path, load_nested_project_scopes, project_model_dir,
    project_model_scopes_path, save_nested_project_scopes, workspace_artifact_kb_db_path,
    workspace_attachments_path, workspace_codeql_db_path, workspace_config_path,
    workspace_findings_db_path, workspace_history_path, workspace_models_path,
    workspace_options_path, workspace_state_dir, workspace_state_root,
    workspace_static_evidence_db_path, HostPattern, ProgramScope, ProgramScopeFile,
    ProgramScopeList, ScopeVerdict, NestedProjectKind, NestedProjectScope,
    NestedProjectScopeTree, WorkspaceExportFormat, WorkspaceFindingsExport, WorkspaceTarget,
    KUZUSHI_STATE_DIR, LEGACY_CODEQL_DB_DIR, LEGACY_CODEQL_STATE_DIR, PROJECT_MODEL_DIR,
    PROJECT_MODEL_SCOPES_FILE, ROOT_SCOPE_ID, WORKSPACE_ARTIFACT_KB_DB_FILE,
    WORKSPACE_ATTACHMENTS_FILE, WORKSPACE_CODEQL_DB_DIR, WORKSPACE_CONFIG_FILE,
    WORKSPACE_FINDINGS_DB_FILE, WORKSPACE_MODELS_FILE, WORKSPACE_OPTIONS_FILE,
    WORKSPACE_STATE_VERSION_DIR, WORKSPACE_STATIC_EVIDENCE_DB_FILE,
};
pub use git_metadata::{
    resolve_target_git_commit, switch_target_revision, target_git_metadata, TargetRevisionSwitch,
};
pub use inventory::*;
pub use source_span::*;
