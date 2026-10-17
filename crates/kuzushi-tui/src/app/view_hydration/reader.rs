use super::*;
use kuzushi_core::{CodeqlScanner, ScanEngine, SemgrepScanner};
use kuzushi_core::{LatestRunPointerIssue, LatestRunPointerState};

mod completion_io;
mod groups;
mod review_source;
mod study_usage;
mod workspace_io;
use completion_io::*;
use workspace_io::*;

#[derive(Debug, Default)]
pub(super) struct FsViewArtifactReader;

impl ViewArtifactReader for FsViewArtifactReader {
    fn read(&self, target: &Path, key: &ViewHydrationKey) -> ViewHydrationValue {
        read_artifact_value(target, key).unwrap_or_else(|| read_environment_value(key))
    }

    fn read_cancellable(
        &self,
        target: &Path,
        key: &ViewHydrationKey,
        cancellation: &ViewHydrationCancellation,
    ) -> Option<ViewHydrationValue> {
        if cancellation.is_canceled() {
            return None;
        }
        if let Some(value) = study_usage::read_study_usage(target, key, cancellation) {
            return value;
        }
        read_regular_cancellable(self, target, key, cancellation)
    }
}

fn read_regular_cancellable(
    reader: &FsViewArtifactReader,
    target: &Path,
    key: &ViewHydrationKey,
    cancellation: &ViewHydrationCancellation,
) -> Option<ViewHydrationValue> {
    if key == &ViewHydrationKey::TargetProfile {
        return TargetProfile::detect_cancellable(target, || cancellation.is_canceled())
            .map(ViewHydrationValue::TargetProfile);
    }
    if let Some(value) = groups::read_groups(target, key, cancellation) {
        return Some(value);
    }
    if key != &ViewHydrationKey::FileCompletionValues {
        return Some(reader.read(target, key));
    }
    let index = crate::app::workspace_file_candidates_cancellable(
        target,
        crate::app::FILE_PICKER_MAX_FILES,
        || cancellation.is_canceled(),
    )?;
    Some(ViewHydrationValue::FileCompletionValues(index))
}

fn read_artifact_value(target: &Path, key: &ViewHydrationKey) -> Option<ViewHydrationValue> {
    if let Some(value) = read_lesson_value(target, key)
        .or_else(|| groups::read_groups(target, key, &ViewHydrationCancellation::default()))
    {
        return Some(value);
    }
    if let ViewHydrationKey::FindingRelationships { finding_id, offset } = key {
        let result = kuzushi_core::WorkspaceTarget::new(target)
            .and_then(|workspace| {
                kuzushi_core::workspace::load_finding_relationships(
                    &workspace,
                    *finding_id,
                    *offset,
                )
            })
            .map_err(|e| format!("{e:#}"));
        return Some(ViewHydrationValue::FindingRelationships(result));
    }
    if let ViewHydrationKey::FindingsProjection(request) = key {
        return Some(ViewHydrationValue::FindingsProjection(
            super::super::findings::read_findings_projection(target, request)
                .map_err(|error| format!("{error:#}")),
        ));
    }
    review_source::read_review_source(target, key)
        .or_else(|| {
            study_usage::read_study_usage(target, key, &ViewHydrationCancellation::default())
                .flatten()
        })
        .or_else(|| read_completion_value(target, key))
        .or_else(|| read_report_value(target, key))
        .or_else(|| read_result_document_value(target, key))
        .or_else(|| read_run_value(target, key))
        .or_else(|| read_project_value(target, key))
        .or_else(|| read_workspace_file_value(target, key))
}

fn read_lesson_value(target: &Path, key: &ViewHydrationKey) -> Option<ViewHydrationValue> {
    let ViewHydrationKey::FindingLessons { offset } = key else {
        return None;
    };
    let result = kuzushi_core::WorkspaceTarget::new(target)
        .and_then(|workspace| kuzushi_core::workspace::load_finding_lessons(&workspace, *offset))
        .map_err(|error| format!("{error:#}"));
    Some(ViewHydrationValue::FindingLessons(result))
}

fn read_result_document_value(target: &Path, key: &ViewHydrationKey) -> Option<ViewHydrationValue> {
    match key {
        ViewHydrationKey::InvestigationAllowance { run_refs } => {
            Some(ViewHydrationValue::InvestigationAllowance(
                kuzushi_core::run_artifacts::load_investigation_allowance_for_runs(
                    target, run_refs,
                )
                .map(|snapshot| snapshot.map(Arc::new))
                .map_err(|error| format!("{error:#}")),
            ))
        }
        ViewHydrationKey::RunRequestContext { run_id } => {
            Some(ViewHydrationValue::RunRequestContext(
                kuzushi_core::run_artifacts::load_run_request_context(target, run_id)
                    .map(Arc::new)
                    .map_err(|error| format!("{error:#}")),
            ))
        }
        ViewHydrationKey::RunResultDocument {
            run_id,
            producer,
            digest,
        } => Some(ViewHydrationValue::RunResultDocument(
            kuzushi_core::run_artifacts::load_correlated_result_document(
                target, run_id, *producer, digest,
            )
            .map(Arc::new)
            .map_err(|error| format!("{error:#}")),
        )),
        _ => None,
    }
}

fn read_run_value(target: &Path, key: &ViewHydrationKey) -> Option<ViewHydrationValue> {
    const RECENT_RUN_HISTORY_LIMIT: usize = 100;
    match key {
        ViewHydrationKey::LatestRunPointer => Some(read_latest_pointer(target)),
        ViewHydrationKey::RunSummaryEntries => Some(ViewHydrationValue::RunSummaryEntries(
            read_recent_run_history(target, RECENT_RUN_HISTORY_LIMIT),
        )),
        ViewHydrationKey::RunArtifactText { run_id, leaf } => {
            Some(ViewHydrationValue::RunArtifactText(
                kuzushi_core::read_run_artifact_text(target, run_id, leaf),
            ))
        }
        ViewHydrationKey::RunProjection { run_id } => Some(ViewHydrationValue::RunProjection(
            kuzushi_core::run_lifecycle::load_run_projection(target, run_id)
                .map_err(|error| error.to_string()),
        )),
        ViewHydrationKey::PhaseReceiptOutcome { attempt_id } => {
            Some(ViewHydrationValue::PhaseReceiptOutcome(
                kuzushi_core::workflow_attempts::load_phase_receipt_projection_v2(
                    target, attempt_id,
                )
                .map(|receipt| {
                    receipt.map(|receipt| phase_attempt_outcome_from_run_status(receipt.status))
                })
                .map_err(|error| error.to_string()),
            ))
        }
        ViewHydrationKey::ScanStageReceipt { run_id } => {
            let state = match kuzushi_core::run_artifacts::load_scan_stage_data(target, run_id) {
                Ok(Some(receipt)) => ScanStageReceiptState::Ready(receipt),
                Ok(None) => ScanStageReceiptState::Missing,
                Err(error) => ScanStageReceiptState::Failed(error.to_string()),
            };
            Some(ViewHydrationValue::ScanStageReceipt(state))
        }
        _ => None,
    }
}

fn read_report_value(target: &Path, key: &ViewHydrationKey) -> Option<ViewHydrationValue> {
    match key {
        ViewHydrationKey::WorkspaceReportReview { findings_watermark } => {
            Some(ViewHydrationValue::WorkspaceReportReview(
                kuzushi_core::WorkspaceTarget::new(target)
                    .and_then(|workspace| {
                        kuzushi_core::workspace::load_workspace_review_summary(
                            &workspace,
                            *findings_watermark,
                        )
                    })
                    .map_err(|error| format!("{error:#}")),
            ))
        }
        ViewHydrationKey::InvestigationReport { run_refs, .. } => {
            Some(read_investigation_report(target, run_refs))
        }
        ViewHydrationKey::InvestigationStudyReport {
            campaign_id,
            plan_sha256,
            ..
        } => Some(read_study_report(target, campaign_id, plan_sha256)),
        _ => None,
    }
}

fn read_study_report(target: &Path, campaign: &str, digest: &str) -> ViewHydrationValue {
    let receipt = kuzushi_core::WorkspaceTarget::new(target)
        .and_then(|workspace| {
            let document =
                kuzushi_core::workspace::load_investigation_report_document(&workspace, campaign)?;
            anyhow::ensure!(
                document.summary().plan_sha256 == digest,
                "Selected study changed; reopen its report from the current plan"
            );
            Ok(Some(document))
        })
        .map_err(|error| format!("{error:#}"));
    ViewHydrationValue::InvestigationReport(receipt)
}

fn read_investigation_report(target: &Path, run_refs: &[String]) -> ViewHydrationValue {
    let receipt = kuzushi_core::WorkspaceTarget::new(target)
        .and_then(|workspace| {
            kuzushi_core::workspace::load_investigation_report_document_for_runs(
                &workspace, run_refs,
            )
        })
        .map_err(|error| error.to_string());
    ViewHydrationValue::InvestigationReport(receipt)
}

fn read_recent_run_history(target: &Path, limit: usize) -> RunSummaryEntriesHydration {
    match kuzushi_core::list_recent_run_summary_entries_with_recoveries(target, limit) {
        Ok(read) => RunSummaryEntriesHydration {
            state: RunSummaryEntriesState::Ready(read.entries),
            newly_recovered: read.newly_recovered,
        },
        Err(error) => RunSummaryEntriesHydration::without_recoveries(
            RunSummaryEntriesState::Failed(error.to_string()),
        ),
    }
}

fn read_project_value(target: &Path, key: &ViewHydrationKey) -> Option<ViewHydrationValue> {
    match key {
        ViewHydrationKey::GitMetadata => Some(ViewHydrationValue::GitMetadata(
            kuzushi_core::workspace::target_git_metadata(target),
        )),
        ViewHydrationKey::RevisionRelationship {
            accepted_revision,
            current_revision,
        } => Some(ViewHydrationValue::RevisionRelationship(
            kuzushi_core::workspace::target_revision_relationship(
                target,
                accepted_revision,
                current_revision,
            ),
        )),
        ViewHydrationKey::ProjectScopeTree => Some(ViewHydrationValue::ProjectScopeTree(
            project_scope_tree(target),
        )),
        ViewHydrationKey::ThreatModelStore => Some(read_threat_model_store(target)),
        ViewHydrationKey::MapRunContext { run_refs } => Some(ViewHydrationValue::MapRunContext(
            kuzushi_core::workflow_attempts::load_map_run_context(target, run_refs)
                .map_err(|error| format!("{error:#}")),
        )),
        ViewHydrationKey::ProjectModelDocument { scope_id, revision } => Some(
            read_project_model_document(target, scope_id, revision.as_deref()),
        ),
        ViewHydrationKey::StrategyQueue => {
            Some(ViewHydrationValue::StrategyQueue(strategy_queue(target)))
        }
        ViewHydrationKey::PromptMutations => Some(ViewHydrationValue::PromptMutations(
            prompt_mutations(target),
        )),
        _ => read_project_analysis_value(target, key),
    }
}

fn read_threat_model_store(target: &Path) -> ViewHydrationValue {
    let state = match kuzushi_core::load_threat_model_manifest(target) {
        Ok(None) => ThreatModelStoreState::Legacy,
        Ok(Some(manifest)) => match kuzushi_core::load_active_threat_model(target) {
            Ok(active) => ThreatModelStoreState::Ready { manifest, active },
            Err(error) => ThreatModelStoreState::Invalid(error.to_string()),
        },
        Err(error) => ThreatModelStoreState::Invalid(error.to_string()),
    };
    ViewHydrationValue::ThreatModelStore(state)
}

fn read_project_analysis_value(
    target: &Path,
    key: &ViewHydrationKey,
) -> Option<ViewHydrationValue> {
    match key {
        ViewHydrationKey::FindingPatchTruth {
            fingerprint,
            finding_scan_id,
            ..
        } => Some(read_finding_patch_truth(
            target,
            fingerprint,
            finding_scan_id.as_deref(),
        )),
        ViewHydrationKey::FindingAuditDataflow { fingerprint } => {
            Some(read_finding_audit_dataflow(target, fingerprint))
        }
        ViewHydrationKey::ScannedSnippet {
            stable_fp,
            scan_id,
            focus_line,
        } => Some(read_scanned_snippet(
            target,
            stable_fp,
            scan_id.as_deref(),
            *focus_line,
        )),
        _ => read_target_analysis_value(target, key),
    }
}

fn read_target_analysis_value(target: &Path, key: &ViewHydrationKey) -> Option<ViewHydrationValue> {
    match key {
        ViewHydrationKey::TargetProfile => Some(ViewHydrationValue::TargetProfile(
            TargetProfile::detect(target),
        )),
        ViewHydrationKey::MapArtifacts => Some(ViewHydrationValue::MapArtifacts(
            map_evidence_is_adequate(target),
        )),
        ViewHydrationKey::CpgArtifacts => Some(ViewHydrationValue::CpgArtifacts(
            kuzushi_core::cpg_has_artifacts(target),
        )),
        ViewHydrationKey::ScanRecommendations => Some(ViewHydrationValue::ScanRecommendations(
            scan_recommendations(target),
        )),
        ViewHydrationKey::TargetBase => Some(ViewHydrationValue::TargetBase(target_base(target))),
        _ => None,
    }
}

fn read_project_model_document(
    target: &Path,
    scope_id: &str,
    revision: Option<&str>,
) -> ViewHydrationValue {
    let document = kuzushi_core::workspace::load_project_model_document(target, scope_id, revision)
        .ok()
        .flatten();
    ViewHydrationValue::ProjectModelDocument(document)
}

fn read_finding_patch_truth(
    target: &Path,
    fingerprint: &str,
    finding_scan_id: Option<&str>,
) -> ViewHydrationValue {
    let state = match finding_patch_truth_for_target(target, fingerprint, finding_scan_id) {
        Ok(Some(truth)) => FindingPatchTruthState::Ready(truth),
        Ok(None) => FindingPatchTruthState::Missing,
        Err(error) => FindingPatchTruthState::Failed(error.to_string()),
    };
    ViewHydrationValue::FindingPatchTruth(state)
}

fn read_finding_audit_dataflow(target: &Path, fingerprint: &str) -> ViewHydrationValue {
    let state = match finding_audit_dataflow_for_target(target, fingerprint) {
        Ok(Some(rows)) => FindingAuditDataflowState::Ready(rows),
        Ok(None) => FindingAuditDataflowState::Missing,
        Err(error) => FindingAuditDataflowState::Failed(error.to_string()),
    };
    ViewHydrationValue::FindingAuditDataflow(state)
}

fn read_scanned_snippet(
    target: &Path,
    stable_fp: &str,
    scan_id: Option<&str>,
    focus_line: u32,
) -> ViewHydrationValue {
    let state = match scanned_snippet_for_target(target, stable_fp, scan_id, focus_line) {
        Ok(Some(window)) => ScannedSnippetState::Ready(window),
        Ok(None) => ScannedSnippetState::Missing,
        Err(error) => ScannedSnippetState::Failed(error.to_string()),
    };
    ViewHydrationValue::ScannedSnippet(state)
}

fn read_workspace_file_value(target: &Path, key: &ViewHydrationKey) -> Option<ViewHydrationValue> {
    match key {
        ViewHydrationKey::SourceFile { path } => Some(ViewHydrationValue::SourceFile(
            read_workspace_text(target, path, MAX_VIEW_SOURCE_BYTES),
        )),
        ViewHydrationKey::HarnessFile => Some(ViewHydrationValue::HarnessFile(
            read_optional_workspace_text(
                target,
                &crate::app::harness_file_path(target),
                MAX_VIEW_HARNESS_BYTES,
            )
            .ok()
            .flatten(),
        )),
        ViewHydrationKey::JsonFile { path } => {
            Some(ViewHydrationValue::JsonFile(read_json_file(target, path)))
        }
        ViewHydrationKey::PathState { path } => Some(ViewHydrationValue::PathState(
            inspect_view_path(target, path),
        )),
        ViewHydrationKey::DirectoryListing { path } => Some(ViewHydrationValue::DirectoryListing(
            read_directory(target, path),
        )),
        ViewHydrationKey::PromptOverrideHash { path } => Some(
            ViewHydrationValue::PromptOverrideHash(prompt_override_hash(target, path)),
        ),
        _ => None,
    }
}

fn read_environment_value(key: &ViewHydrationKey) -> ViewHydrationValue {
    if let ViewHydrationKey::ExecutableOptions { requirements, .. } = key {
        return ViewHydrationValue::ExecutableOptions(
            kuzushi_core::modules::missing_executable_requirements(requirements),
        );
    }
    let ViewHydrationKey::HealthChecks { credential_env } = key else {
        unreachable!("view hydration key was not assigned to a reader boundary")
    };
    ViewHydrationValue::HealthChecks(health_checks(credential_env))
}

fn read_latest_pointer(target: &Path) -> ViewHydrationValue {
    let state = kuzushi_core::read_latest_run_pointer(target).unwrap_or_else(|error| {
        LatestRunPointerState::Invalid(LatestRunPointerIssue::UnsafePath(error.to_string()))
    });
    ViewHydrationValue::LatestRunPointer(state)
}

fn map_evidence_is_adequate(target: &Path) -> bool {
    let facts = kuzushi_core::workflow_attempts::collect_map_evidence(target, &[]);
    kuzushi_core::workflow_attempts::assess_map_evidence(&facts).is_adequate()
}

/// Runs the coverage sweep (git diffs + repo walk) off-frame; the findings
/// store is advisory, so a target without one still yields recommendations.
fn scan_recommendations(target: &Path) -> ScanRecommendationsState {
    let db_path = kuzushi_core::workspace::workspace_findings_db_path(target);
    let store = db_path
        .exists()
        .then(|| kuzushi_core::FindingStore::open_read_only(&db_path).ok())
        .flatten();
    match kuzushi_core::capabilities::scan_recommender::recommend_scans_for_target(
        target,
        store.as_ref(),
    ) {
        Ok(rows) => ScanRecommendationsState::Ready(rows),
        Err(error) => ScanRecommendationsState::Failed(error.to_string()),
    }
}

fn project_scope_tree(target: &Path) -> ProjectScopeTreeState {
    match kuzushi_core::load_nested_project_scopes(target) {
        Ok(Some(tree)) => ProjectScopeTreeState::Persisted(tree),
        Ok(None) => ProjectScopeTreeState::RootOnly,
        Err(error) => ProjectScopeTreeState::Unreadable(error.to_string()),
    }
}

fn strategy_queue(target: &Path) -> StrategyQueueState {
    let workspace = match kuzushi_core::WorkspaceTarget::new(target) {
        Ok(workspace) => workspace,
        Err(error) => return StrategyQueueState::Unreadable(error.to_string()),
    };
    match kuzushi_core::load_strategy_queue(&workspace) {
        Ok(proposals) => StrategyQueueState::Ready(proposals),
        Err(error) => StrategyQueueState::Unreadable(error.to_string()),
    }
}

fn prompt_mutations(target: &Path) -> PromptMutationsState {
    let workspace = match kuzushi_core::WorkspaceTarget::new(target) {
        Ok(workspace) => workspace,
        Err(_) => return PromptMutationsState::Unreadable,
    };
    match kuzushi_core::load_prompt_mutations(&workspace) {
        Ok(mutations) => PromptMutationsState::Ready(mutations),
        Err(_) => PromptMutationsState::Unreadable,
    }
}

fn target_base(target: &Path) -> String {
    target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn inspect_path(path: &Path) -> PathState {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => PathState::Other,
        Ok(metadata) if metadata.is_file() => PathState::File {
            len: metadata.len(),
        },
        Ok(metadata) if metadata.is_dir() => PathState::Directory,
        Ok(_) => PathState::Other,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => PathState::Missing,
        Err(_) => PathState::Unreadable,
    }
}

fn inspect_view_path(target: &Path, path: &Path) -> PathState {
    if path.starts_with(target) {
        inspect_workspace_path(target, path)
    } else {
        inspect_path(path)
    }
}

fn health_checks(credential_env: &str) -> ViewHealthChecks {
    ViewHealthChecks {
        semgrep_error: SemgrepScanner::default()
            .preflight()
            .err()
            .map(|error| error.to_string()),
        codeql_error: CodeqlScanner::default()
            .preflight()
            .err()
            .map(|error| error.to_string()),
        credential_set: env_is_set(credential_env),
    }
}

fn env_is_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}

#[cfg(test)]
mod report_ledger_tests {
    use super::*;

    #[test]
    fn a_known_report_ledger_disappearing_is_unavailable_not_empty() {
        let root = tempfile::tempdir().unwrap();
        let key = ViewHydrationKey::WorkspaceReportReview {
            findings_watermark: Some(1),
        };
        let result = read_report_value(root.path(), &key).unwrap();
        assert!(
            matches!(result, ViewHydrationValue::WorkspaceReportReview(Err(_))),
            "{result:?}"
        );
        assert!(!root.path().join(".kuzushi").exists());
    }
}
