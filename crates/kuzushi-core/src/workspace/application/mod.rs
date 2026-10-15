use super::domain::*;
use crate::findings::{Finding, FindingListFilter, FindingStore};
use anyhow::{Context, Result};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

mod changed_scan_scope;
mod export_decision_basis;
mod review_source_applicability;
pub use review_source_applicability::WorkspaceReviewSourceApplicability;
mod export_evidence_origin;
mod export_investigation_receipt;
mod export_lessons;
mod export_markdown_bundle;
mod export_metadata;
mod export_projection;
mod export_projection_model;
mod export_relationships;
mod export_review_context;
mod export_sarif;
mod export_vuln_findings;
mod export_workspace_findings;
mod finding_lessons;
mod finding_relationships;
pub use finding_lessons::{execute_lesson_action, load_finding_lessons};
mod investigation_report;
pub use finding_relationships::{
    load_finding_relationships, record_finding_relationship_batch_review,
    record_finding_relationship_review, FindingRelationshipBatchReviewRequest,
    FindingRelationshipReviewRequest,
};
pub use investigation_report::{
    load_investigation_report, load_investigation_report_document,
    load_investigation_report_document_for_runs, load_investigation_report_for_runs,
    ContextMatrixInvestigationReceipt, InvestigationContextCase, InvestigationReportDocument,
    InvestigationReportEvidence, InvestigationReportReceipt, InvestigationReportSummary,
    InvestigationWorkCounts, ScopeStudyInvestigationReceipt,
};
mod load_program_scope;
mod nested_scope;
mod project_model;
mod record_review_decision;
mod record_review_session;
mod scan_scope_proposal;
mod since_filter;
mod status;

pub use changed_scan_scope::{changed_scan_input, ChangedScanScope};
mod review_decision_receipt;
mod review_source_capture;
pub use export_decision_basis::{
    read_finding_review_source, WorkspaceObservedSource, WorkspaceReviewDecisionBasis,
    WorkspaceReviewSourceComparison,
};
pub use export_lessons::WorkspaceLessonExportRecord;
#[cfg(test)]
pub(crate) use export_markdown_bundle::write_markdown_bundle;
pub use export_metadata::workspace_export_omitted_fields;
pub use export_projection::{
    workspace_finding_export_records_with_context, workspace_finding_export_records_with_reviews,
};
pub use export_projection_model::{
    WorkspaceAnalysisExportSummary, WorkspaceEvidenceExportSummary, WorkspaceFindingExportLocation,
    WorkspaceFindingExportRecord, WorkspaceFindingProvenanceSummary,
    WorkspaceRemediationExportSummary, WorkspaceRunExportContext,
    WorkspaceVerificationExportSummary,
};
pub use export_review_context::WorkspaceFindingReviewContext;
pub(crate) use export_workspace_findings::read_workspace_finding_export_records;
#[cfg(test)]
pub(crate) use export_workspace_findings::sanitize_csv_field;
pub use export_workspace_findings::{
    export_scan_findings_sarif, export_scan_findings_sarif_with_run_summary,
    export_workspace_findings, export_workspace_findings_with_options,
    preview_workspace_findings_export, review_completion_for_findings,
    WorkspaceFindingsExportPreview, WorkspaceReviewCompletion,
};
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
pub use review_decision_receipt::{
    read_review_decision_receipt, record_user_review_decision_with_receipt,
    WorkspaceReviewDecisionReceipt,
};
pub use review_source_capture::execute_source_review_action;
pub use review_source_capture::{
    capture_review_source, decide_on_review_source, read_decision_reviewed_source,
    read_review_source_capture, WorkspaceReviewSourceCapture,
};
pub use review_source_capture::{
    capture_review_source_with_limit, read_captured_review_code, MAX_REVIEW_SOURCE_BYTES,
};
pub use scan_scope_proposal::{
    accept_scan_scope_proposal, create_scan_scope_proposal, edit_scan_scope_proposal,
    load_accepted_scan_scope_proposal, load_scan_scope_proposal,
    resolve_accepted_scan_scope_selection, scan_scope_proposal_files,
};
pub(crate) use scan_scope_proposal::{
    suggest_scan_scope_proposal, validate_scan_scope_suggestion_input,
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

pub(crate) use scan_scope_proposal::{
    load_latest_scan_scope_proposal, load_scan_scope_proposal_cancellable,
    scan_scope_proposal_files_cancellable,
};
