use super::domain::*;
use crate::findings::{Finding, FindingListFilter, FindingStore};
use anyhow::{Context, Result};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

mod export_markdown_bundle;
mod export_sarif;
mod export_workspace_findings;
mod load_program_scope;
mod nested_scope;
mod project_model;
mod since_filter;
mod status;

pub use export_workspace_findings::export_workspace_findings;
pub use load_program_scope::{load_program_scope, write_program_scope_scaffold};
pub use nested_scope::{
    discover_and_save_nested_project_scopes, discover_nested_project_scopes,
    load_nested_project_scopes, save_nested_project_scopes,
};
pub use project_model::{
    build_project_model_document, load_project_model_document, project_model_scope_path,
    refresh_project_model_staleness, save_project_model_document, ProjectModelDocument,
    ProjectModelSection, ProjectModelSectionOrigin, PROJECT_MODEL_SCHEMA_VERSION,
};
pub use since_filter::findings_since_filter_expression;
pub use status::{workspace_status_for_target, WorkspaceStatus};

pub fn active_workspace_required_message(tool: &str) -> String {
    format!(
        "{tool} needs an active workspace target. Next: pass `--target <path>` \
         (or `--target .` to use the current directory), or start the shell with \
         `--target <path>`."
    )
}
