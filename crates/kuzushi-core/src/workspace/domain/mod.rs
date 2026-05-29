use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

mod workspace_target;

pub use workspace_target::{
    legacy_codeql_db_path, workspace_artifact_kb_db_path, workspace_attachments_path,
    workspace_codeql_db_path, workspace_config_path, workspace_findings_db_path,
    workspace_history_path, workspace_models_path, workspace_options_path, workspace_state_dir,
    workspace_state_root, workspace_static_evidence_db_path, WorkspaceExportFormat,
    WorkspaceFindingsExport, WorkspaceTarget, KUZUSHI_STATE_DIR, LEGACY_CODEQL_DB_DIR,
    LEGACY_CODEQL_STATE_DIR, WORKSPACE_ARTIFACT_KB_DB_FILE, WORKSPACE_ATTACHMENTS_FILE,
    WORKSPACE_CODEQL_DB_DIR, WORKSPACE_CONFIG_FILE, WORKSPACE_FINDINGS_DB_FILE,
    WORKSPACE_MODELS_FILE, WORKSPACE_OPTIONS_FILE, WORKSPACE_STATE_VERSION_DIR,
    WORKSPACE_STATIC_EVIDENCE_DB_FILE,
};
