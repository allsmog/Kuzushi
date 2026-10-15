mod application;
pub(crate) use application::read_workspace_finding_export_records;
pub use application::{execute_lesson_action, load_finding_lessons};
pub mod artifact_kb;
pub mod artifacts;
pub mod attack_surface;
pub mod coverage_ledger;
pub mod diff_scope;
mod domain;
mod git_history_mining;
mod git_metadata;
mod infrastructure;
pub(crate) use infrastructure::InventoryRoot;
pub mod inventory;
pub(crate) mod python_surface_policy;
pub mod report_preferences;
pub(crate) mod rust_surface_policy;
pub(crate) mod rust_test_source;
pub(crate) mod source_snapshot;
pub mod source_span;
pub mod tool_shelf;

#[cfg(test)]
mod tests;

pub use application::{
    accept_scan_scope_proposal, active_workspace_required_message, build_project_model_document,
    capture_review_source, capture_review_source_with_limit, changed_scan_input,
    create_scan_scope_proposal, decide_on_review_source, discover_and_save_nested_project_scopes,
    discover_nested_project_scopes, edit_scan_scope_proposal, execute_source_review_action,
    export_scan_findings_sarif, export_scan_findings_sarif_with_run_summary,
    export_workspace_findings, export_workspace_findings_with_options,
    findings_since_filter_expression, load_accepted_scan_scope_proposal,
    load_finding_relationships, load_investigation_report, load_investigation_report_document,
    load_investigation_report_document_for_runs, load_investigation_report_for_runs,
    load_nested_project_scopes, load_program_scope, load_project_model_document,
    load_scan_scope_proposal, preview_workspace_findings_export, project_model_scope_path,
    read_captured_review_code, read_decision_reviewed_source, read_finding_review_source,
    read_review_decision_receipt, read_review_source_capture,
    record_finding_relationship_batch_review, record_finding_relationship_review,
    record_review_session_started, record_user_review_decision_for_finding,
    record_user_review_decision_for_finding_at_watermark,
    record_user_review_decision_for_finding_with_session, record_user_review_decision_with_receipt,
    refresh_project_model_staleness, review_completion_for_findings, save_nested_project_scopes,
    save_project_model_document, scan_scope_proposal_files, workspace_export_omitted_fields,
    workspace_finding_export_records_with_context, workspace_finding_export_records_with_reviews,
    workspace_status_for_target, write_program_scope_scaffold, ChangedScanScope,
    ContextMatrixInvestigationReceipt, FindingRelationshipBatchReviewRequest,
    FindingRelationshipReviewRequest, InvestigationContextCase, InvestigationReportDocument,
    InvestigationReportEvidence, InvestigationReportReceipt, InvestigationReportSummary,
    InvestigationWorkCounts, ProjectModelDocument, ProjectModelSection, ProjectModelSectionOrigin,
    ScopeStudyInvestigationReceipt, WorkspaceAnalysisExportSummary, WorkspaceEvidenceExportSummary,
    WorkspaceFindingExportLocation, WorkspaceFindingExportRecord,
    WorkspaceFindingProvenanceSummary, WorkspaceFindingReviewContext,
    WorkspaceFindingsExportPreview, WorkspaceLessonExportRecord, WorkspaceObservedSource,
    WorkspaceRemediationExportSummary, WorkspaceReviewCompletion, WorkspaceReviewDecisionBasis,
    WorkspaceReviewDecisionReceipt, WorkspaceReviewSourceApplicability,
    WorkspaceReviewSourceCapture, WorkspaceReviewSourceComparison, WorkspaceRunExportContext,
    WorkspaceStatus, WorkspaceVerificationExportSummary, MAX_REVIEW_SOURCE_BYTES,
    PROJECT_MODEL_SCHEMA_VERSION,
};
pub use artifact_kb::*;
pub use artifacts::{
    artifact_modified_within, artifact_state, artifact_state_within, ArtifactState,
};
pub use attack_surface::*;
pub use diff_scope::*;
pub(crate) use domain::{
    ensure_workspace_descendant_dir, initialize_workspace_state, validated_workspace_descendant,
};
pub use domain::{
    ensure_workspace_output_dir, legacy_codeql_db_path, legacy_workspace_codeql_db_path,
    prepare_workspace_output_path, project_model_dir, project_model_scopes_path,
    read_optional_workspace_text, read_workspace_text, remove_workspace_state_file,
    resolve_contained_output_path, resolve_report_output_path, workspace_artifact_kb_db_path,
    workspace_attachments_path, workspace_codeql_db_path, workspace_config_path,
    workspace_event_log_dir, workspace_findings_db_path, workspace_history_path,
    workspace_models_path, workspace_objects_dir, workspace_options_path, workspace_state_dir,
    workspace_state_root, workspace_static_evidence_db_path, workspace_suppressions_path,
    write_workspace_file, write_workspace_state_file, HostPattern, NestedProjectKind,
    NestedProjectScope, NestedProjectScopeTree, ProgramScope, ProgramScopeFile, ProgramScopeList,
    ProposedScanScope, ReviewYieldExportProvenance, ScanScopeCoverage, ScanScopeDraft,
    ScanScopeEdit, ScanScopeExclusion, ScanScopeGeneration, ScanScopeProposalRef, ScanScopeReview,
    ScanScopeRevision, ScanScopeSource, ScopeCoverageApproval, ScopeFileFilter, ScopeFilePage,
    ScopeFilePreview, ScopeOverlapPreview, ScopeVerdict, TargetSyntax, WorkspaceExportCompleteness,
    WorkspaceExportFormat, WorkspaceExportOptions, WorkspaceFindingsExport, WorkspaceTarget,
    KUZUSHI_STATE_DIR, LEGACY_CODEQL_DB_DIR, LEGACY_CODEQL_STATE_DIR, PROJECT_MODEL_DIR,
    PROJECT_MODEL_SCOPES_FILE, ROOT_SCOPE_ID, WORKSPACE_ARTIFACT_KB_DB_FILE,
    WORKSPACE_ATTACHMENTS_FILE, WORKSPACE_CODEQL_DB_DIR, WORKSPACE_CONFIG_FILE,
    WORKSPACE_EVENT_LOG_DIR, WORKSPACE_FINDINGS_DB_FILE, WORKSPACE_MODELS_FILE,
    WORKSPACE_OBJECTS_DIR, WORKSPACE_OPTIONS_FILE, WORKSPACE_STATE_VERSION_DIR,
    WORKSPACE_STATIC_EVIDENCE_DB_FILE, WORKSPACE_SUPPRESSIONS_FILE,
};
pub use git_history_mining::{
    changed_files_since, mine_vuln_history, security_keywords_for_languages,
    GitHistoryMiningConfig, VulnCommit,
};
pub use git_metadata::{
    resolve_target_git_commit, switch_target_revision, target_git_metadata,
    target_revision_relationship, RevisionRelationship, TargetRevisionSwitch,
};
pub(crate) use infrastructure::{git_tracked_relative_paths, GitIndexEnumeration};
pub use inventory::*;
pub use source_span::*;
pub use tool_shelf::{
    load_tool_shelf, record_tool_use, save_tool_shelf, workspace_tool_shelf_path, RecentTool,
    ToolShelf, RECENTS_CAP, WORKSPACE_TOOL_SHELF_FILE,
};

pub(crate) use application::{
    load_latest_scan_scope_proposal, load_scan_scope_proposal_cancellable,
    scan_scope_proposal_files_cancellable,
};

pub use application::resolve_accepted_scan_scope_selection;
pub(crate) use application::{suggest_scan_scope_proposal, validate_scan_scope_suggestion_input};
pub use domain::{AcceptedScanScopeSelection, ScanScopeRef};
