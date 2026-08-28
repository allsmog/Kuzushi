use super::domain::*;
use crate::findings::{Finding, FindingListFilter, FindingStore};
use anyhow::{Context, Result};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

mod changed_scan_scope;
mod export_evidence_origin;
mod export_markdown_bundle;
mod export_metadata;
mod export_projection;
mod export_projection_model;
mod export_review_context;
mod export_sarif;
mod export_vuln_findings;
mod export_workspace_findings;
mod load_program_scope;
mod nested_scope;
mod project_model;
mod record_review_decision;
mod record_review_session;
mod since_filter;
mod status;

pub use changed_scan_scope::{changed_scan_input, ChangedScanScope};
pub use export_metadata::workspace_export_omitted_fields;
pub use export_projection::{
    workspace_finding_export_records_with_context, workspace_finding_export_records_with_reviews,
};
pub use export_projection_model::{
    WorkspaceAnalysisExportSummary, WorkspaceEvidenceExportSummary, WorkspaceFindingExportLocation,
    WorkspaceFindingExportRecord, WorkspaceFindingProvenanceSummary, WorkspaceRunExportContext,
    WorkspaceRemediationExportSummary, WorkspaceVerificationExportSummary,
};
pub use export_review_context::WorkspaceFindingReviewContext;
pub use export_workspace_findings::{
    export_scan_findings_sarif, export_scan_findings_sarif_with_run_summary,
    export_workspace_findings, export_workspace_findings_with_options,
    preview_workspace_findings_export, WorkspaceFindingsExportPreview,
};
#[cfg(test)]
pub(crate) use export_markdown_bundle::write_markdown_bundle;
#[cfg(test)]
pub(crate) use export_workspace_findings::sanitize_csv_field;
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
pub use record_review_decision::{
    record_user_review_decision_for_finding, record_user_review_decision_for_finding_at_watermark,
    record_user_review_decision_for_finding_with_session,
};
pub use record_review_session::record_review_session_started;
pub use since_filter::findings_since_filter_expression;
pub use status::{workspace_status_for_target, WorkspaceStatus};

pub fn active_workspace_required_message(tool: &str) -> String {
    format!(
        "{tool} needs an active workspace target. Next: pass `--target <path>` \
         (or `--target .` to use the current directory), or start the shell with \
         `--target <path>`."
    )
}
