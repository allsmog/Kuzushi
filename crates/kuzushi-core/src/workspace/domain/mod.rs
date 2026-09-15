use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

mod nested_scope;
mod program_scope;
mod workspace_state_initialization;
mod workspace_state_io;
mod workspace_target;

pub(crate) use nested_scope::{
    inherited_sections_for_child_scope, normalize_relative_path, scope_id, scope_sort_key,
    valid_scope_id, SCOPE_TREE_SCHEMA_VERSION,
};
pub use nested_scope::{
    project_model_dir, project_model_scopes_path, NestedProjectKind, NestedProjectScope,
    NestedProjectScopeTree, PROJECT_MODEL_DIR, PROJECT_MODEL_SCOPES_FILE, ROOT_SCOPE_ID,
};
pub use program_scope::{
    HostPattern, ProgramScope, ProgramScopeFile, ProgramScopeList, ScopeVerdict, TargetSyntax,
};
pub(crate) use workspace_state_io::{
    ensure_workspace_descendant_dir, validated_workspace_descendant,
};
pub(crate) use workspace_state_initialization::initialize_workspace_state;
pub use workspace_state_io::{
    ensure_workspace_output_dir, prepare_workspace_output_path,
    read_optional_workspace_text, read_workspace_text, remove_workspace_state_file,
    resolve_contained_output_path, resolve_report_output_path, write_workspace_file,
    write_workspace_state_file,
};
pub use workspace_target::{
    legacy_codeql_db_path, legacy_workspace_codeql_db_path,
    workspace_artifact_kb_db_path, workspace_attachments_path, workspace_codeql_db_path,
    workspace_config_path, workspace_event_log_dir, workspace_findings_db_path,
    workspace_history_path, workspace_models_path, workspace_objects_dir, workspace_options_path,
    workspace_state_dir, workspace_state_root, workspace_static_evidence_db_path,
    workspace_suppressions_path, WorkspaceExportCompleteness, WorkspaceExportFormat, ReviewYieldExportProvenance, WorkspaceExportOptions,
    WorkspaceFindingsExport, WorkspaceTarget, KUZUSHI_STATE_DIR, LEGACY_CODEQL_DB_DIR,
    LEGACY_CODEQL_STATE_DIR, WORKSPACE_ARTIFACT_KB_DB_FILE, WORKSPACE_ATTACHMENTS_FILE,
    WORKSPACE_CODEQL_DB_DIR, WORKSPACE_CONFIG_FILE, WORKSPACE_EVENT_LOG_DIR,
    WORKSPACE_FINDINGS_DB_FILE, WORKSPACE_MODELS_FILE, WORKSPACE_OBJECTS_DIR,
    WORKSPACE_OPTIONS_FILE, WORKSPACE_STATE_VERSION_DIR, WORKSPACE_STATIC_EVIDENCE_DB_FILE,
    WORKSPACE_SUPPRESSIONS_FILE,
};
