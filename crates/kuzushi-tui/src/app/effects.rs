use super::*;
use anyhow::Context;
use kuzushi_core::findings::ReviewDecision;
use kuzushi_core::incremental_index::WorkspaceIndexUpdate;
use kuzushi_core::DynamicModuleLoadOptions;
use kuzushi_core::OptionScope;
use std::path::{Path, PathBuf};

pub(crate) enum ShellEffect {
    OpenActivity(ActivityOpen),
    ApplyReviewedPatch(ReviewedPatchApply),
    ExportReport(ReportExport),
    RevealReportDestination,
    ApplySastTaskOptions(SastTaskOptionsApply),
    ApplyThreatPatch(ThreatPatchApply),
    AuthLogin(AuthLoginStart),
    ActivateTarget(TargetActivation),
    AdvancePrereqChain(PrereqChainAdvance),
    AbortForBudget,
    CancelActiveJobs,
    /// Cancel exactly one live job slot by kind (`jobs -k <id>`). Scoped so the
    /// per-row cancel a `Jobs` row advertises abors only that job, not every
    /// concurrent job the way `CancelActiveJobs` does.
    CancelJob(JobKind),
    ClearConversation,
    ContinuePastBudget,
    BuildContext(ContextBuild),
    DispatchAgent(AgentDispatch),
    DispatchNextPlanningTask(PlanningTaskDispatch),
    PrepareRunTool(RunToolPreparation),
    DispatchRunTool(RunToolLaunch),
    RefreshDeterministicRecommendations(DeterministicRecommendationRefresh),
    DiffPromptOverride(PromptOverrideDiff),
    EditPromptOverride(PromptOverrideEdit),
    ListPromptOverrides(PromptOverrideList),
    LoadDynamicModule(DynamicModuleLoad),
    OpenFilePicker,
    OpenPromptDocument(PromptDocumentOpen),
    OpenGuidedScan(GuidedScanOpen),
    ShowKnowledgeBase(KnowledgeBaseShow),
    AttachKnowledgeBaseSource(KnowledgeBaseAttach),
    DetachKnowledgeBaseSource(KnowledgeBaseSource),
    PauseActiveWork,
    ResetHouseRules(HouseRulesReset),
    PersistCommandHistory,
    RecordAgentRun(AgentRunRecord),
    RecordPromptMutation(PromptMutationRecord),
    RecordScanRun(ScanRunRecord),
    RecordScanStageTrace(ScanStageTraceRecord),
    RecordToolRun(ToolRunRecordEffect),
    RefreshContextView,
    RefreshFindings(FindingsRefresh),
    ReportFilteredFindingMovement(FilteredFindingMovementNotice),
    FinalizeWorkbenchOpen(WorkbenchOpenFinalize),
    FinalizeGuidedScanOpen,
    FinalizeOpenFinding(OpenFindingFinalize),
    FinalizeSastTaskCommand(SastTaskCommandFinalize),
    HydrateSceneSnapshots(SceneSnapshotsHydration),
    FinalizeScanCompletion(ScanCompletionFinalize),
    PersistGlobalModelSelection(GlobalModelSelectionPersist),
    PersistPlanningOptionOverride(PlanningOptionOverridePersist),
    PersistOptions(OptionScope),
    ResetPromptOverride(PromptOverrideReset),
    ResumeSession(ResumeSession),
    RequestExitAbort,
    RequestShellQuit,
    Quit,
    FinishShellQuit,
    RecordReviewDecision(ReviewDecisionApply),
    RecordProofDeferral(ProofDeferralApply),
    RecordSuppression(SuppressionApply),
    UpdatePromptMutationStatus(PromptMutationStatusUpdate),
    RefreshPwnState,
    RefreshProgramScope,
    OpenFinding(OpenFindingReference),
    OpenRunArtifact(OpenRunArtifact),
    SelectComponent(ComponentSelection),
    FireNextApprovedStrategy(StrategyFireNext),
    RecordStrategyCorrection(StrategyCorrectionRecord),
    UpdateStrategyProposalStatus(StrategyProposalStatusUpdate),
    SetSessionEnv(SessionEnvVar),
    ShowAuthStatus(AuthStatusShow),
    ShowContextStatus,
    ShowHouseRules(HouseRulesShow),
    RefreshHouseRules(HouseRulesRefresh),
    ShowPromptOverride(PromptOverrideShow),
    ShowWorkspaceStatus,
    ReparseKnowledgeBaseSource(KnowledgeBaseSource),
    StartOfflineDemoFixtureScan,
    StartPlanner(PlannerStart),
    PrepareScan(ScanStartPreparation),
    StartScan(ScanStartRequest),
    StartThreat(ThreatWorkerStart),
    SwitchTargetRevision(TargetRevisionSwitch),
    WaitForAbortCleanup,
    WorkspaceReindex(WorkspaceReindex),
    WorkspaceExportFindings(WorkspaceExportFindings),
    WorkspaceScopeInit(WorkspaceScopeInit),
    WriteHouseRules(HouseRulesWrite),
    WritePromptOverride(PromptOverrideWrite),
}

pub(crate) struct ActivityOpen {
    pub(crate) run_id: Option<String>,
}

pub(crate) struct DynamicModuleLoad {
    pub(crate) specifier: String,
}

pub(crate) struct GuidedScanOpen {
    pub(crate) target: Option<PathBuf>,
}

pub(crate) struct ScanStartPreparation {
    pub(crate) target: Option<PathBuf>,
    pub(crate) explicit_input: Option<serde_json::Value>,
}

pub(crate) struct KnowledgeBaseShow {
    pub(crate) module: Option<String>,
}

pub(crate) struct KnowledgeBaseAttach {
    pub(crate) source: String,
}

pub(crate) struct KnowledgeBaseSource {
    pub(crate) id: String,
}

pub(crate) struct ContextBuild {
    pub(crate) target: Option<PathBuf>,
    pub(crate) scope: Option<String>,
}

pub(crate) struct ResumeSession {
    pub(crate) run_id: Option<String>,
}

pub(crate) struct PlanningTaskDispatch {
    pub(crate) target: Option<PathBuf>,
    pub(crate) missing_workspace_message: &'static str,
    pub(crate) success_view: Option<PlanningDispatchView>,
}

pub(crate) struct DeterministicRecommendationRefresh {
    pub(crate) target: Option<PathBuf>,
}

pub(crate) struct PrereqChainAdvance {
    pub(crate) target: Option<PathBuf>,
}

pub(crate) enum PlanningDispatchView {
    Activity,
    Catalog,
}

pub(crate) struct ReviewedPatchApply {
    pub(crate) selected_attempt_id: String,
    pub(crate) alias: String,
    pub(crate) patch_run_id: String,
    pub(crate) diff: String,
    pub(crate) target: Option<PathBuf>,
}

pub(crate) struct ThreatPatchApply {
    pub(crate) patch: ThreatPatch,
    pub(crate) target: PathBuf,
}

pub(crate) struct ReviewDecisionApply {
    pub(crate) alias: Option<String>,
    pub(crate) decision: ReviewDecision,
    pub(crate) finding: Finding,
    pub(crate) read_watermark: Option<u64>,
    pub(crate) target: Option<PathBuf>,
}

pub(crate) struct ProofDeferralApply {
    pub(crate) target: Option<PathBuf>,
    pub(crate) reference: String,
    pub(crate) reason: String,
}

pub(crate) struct WorkspaceExportFindings {
    pub(crate) allow_empty: bool,
    pub(crate) completeness: Option<String>,
    pub(crate) format: Option<String>,
    pub(crate) output: PathBuf,
    pub(crate) target: Option<PathBuf>,
}

pub(crate) struct ReportExport {
    pub(crate) format: kuzushi_core::WorkspaceExportFormat,
    pub(crate) completeness: kuzushi_core::WorkspaceExportCompleteness,
    pub(crate) output: PathBuf,
    pub(crate) target: Option<PathBuf>,
}

pub(crate) struct WorkspaceReindex {
    pub(crate) target: Option<PathBuf>,
    pub(crate) changes: Vec<kuzushi_core::incremental_index::WorkspaceChange>,
}

pub(crate) struct WorkspaceScopeInit {
    pub(crate) target: Option<PathBuf>,
}

pub(crate) struct SessionEnvVar {
    pub(crate) key: String,
    pub(crate) value: String,
}

pub(crate) struct AuthStatusShow {
    pub(crate) api_key_env: String,
}

pub(crate) struct AuthLoginStart {
    pub(crate) provider: String,
    pub(crate) method: String,
    pub(crate) continue_after_success: bool,
}

pub(crate) struct GlobalModelSelectionPersist {
    pub(crate) model: String,
    pub(crate) thinking_level: Option<String>,
}

pub(crate) struct PlanningOptionOverridePersist {
    pub(crate) task: PlanningTaskId,
    pub(crate) tool_name: String,
    pub(crate) option_name: String,
    pub(crate) value: serde_json::Value,
}

pub(crate) struct PromptMutationRecord {
    pub(crate) target: Option<PathBuf>,
    pub(crate) module: String,
    pub(crate) verb: String,
    pub(crate) text: String,
}

pub(crate) struct PromptMutationStatusUpdate {
    pub(crate) target: Option<PathBuf>,
    pub(crate) id: String,
    pub(crate) status: kuzushi_core::PromptMutationStatus,
    pub(crate) reason: Option<String>,
}

pub(crate) struct SastTaskOptionsApply {
    pub(crate) mutations: Vec<SastTaskOptionMutation>,
    pub(crate) message_prefix: String,
}

pub(crate) enum SastTaskOptionMutation {
    Set {
        name: String,
        value: serde_json::Value,
    },
    Unset {
        name: String,
    },
}

pub(crate) struct SastTaskCommandFinalize {
    pub(crate) outcome: SastTaskCommandOutcome,
}

pub(crate) enum SastTaskCommandOutcome {
    Applied(String),
    Error(String),
}

pub(crate) struct ComponentSelection {
    pub(crate) target: Option<PathBuf>,
    pub(crate) raw: Option<String>,
}

pub(crate) struct StrategyProposalStatusUpdate {
    pub(crate) target: Option<PathBuf>,
    pub(crate) id: String,
    pub(crate) status: kuzushi_core::StrategyProposalStatus,
    pub(crate) label: &'static str,
}

pub(crate) struct StrategyFireNext {
    pub(crate) target: Option<PathBuf>,
}

pub(crate) struct StrategyCorrectionRecord {
    pub(crate) target: Option<PathBuf>,
    pub(crate) id: String,
    pub(crate) to_strategy: String,
    pub(crate) reason: Option<String>,
    pub(crate) scope: StrategyCorrectionCommandScope,
    pub(crate) active_run_id: Option<String>,
}

pub(crate) struct AgentRunRecord {
    pub(crate) target: Option<PathBuf>,
    pub(crate) run_id: String,
    pub(crate) latency_ms: Option<u64>,
    pub(crate) audit: AgentCallAudit,
    pub(crate) outcome: AgentRunOutcome,
}

pub(crate) enum AgentRunOutcome {
    Complete { answer_chars: usize },
    Failed { error: String },
    Canceled { reason: String },
}

pub(crate) struct ScanRunRecord {
    pub(crate) target: Option<PathBuf>,
    pub(crate) run_id: String,
    pub(crate) target_label: String,
    pub(crate) outcome: ScanRunOutcome,
}

pub(crate) enum ScanRunOutcome {
    Complete {
        result: serde_json::Value,
    },
    Partial {
        result: serde_json::Value,
    },
    Skipped {
        result: serde_json::Value,
    },
    FailedResult {
        result: serde_json::Value,
    },
    Failed {
        error: String,
    },
    Canceled {
        reason: String,
        findings_count: Option<usize>,
    },
    Interrupted {
        reason: String,
    },
}

pub(crate) struct ScanStageTraceRecord {
    pub(crate) target: Option<PathBuf>,
    pub(crate) run_id: String,
    pub(crate) stage: String,
}

pub(crate) struct ToolRunRecordEffect {
    pub(crate) target: Option<PathBuf>,
    pub(crate) run_id: Option<String>,
    pub(crate) tool_name: String,
    pub(crate) outcome: ToolRunRecordOutcome,
}

pub(crate) enum ToolRunRecordOutcome {
    Complete {
        result: serde_json::Value,
    },
    Failed {
        error: String,
    },
    ObservedComplete {
        result: serde_json::Value,
        completion: kuzushi_core::PendingToolCallCompletion,
    },
    ObservedFailed {
        error: String,
        completion: kuzushi_core::PendingToolCallCompletion,
    },
    ObservedCanceled {
        reason: String,
        completion: kuzushi_core::PendingToolCallCompletion,
    },
    ObservedInterrupted {
        reason: String,
        completion: kuzushi_core::PendingToolCallCompletion,
    },
    ObservedRefused {
        reason: String,
        completion: kuzushi_core::PendingToolCallCompletion,
    },
    Canceled {
        reason: String,
    },
    Interrupted {
        reason: String,
    },
    Refused {
        reason: String,
    },
}

pub(crate) struct FindingsRefresh {
    pub(crate) announce: bool,
    pub(crate) filter: Option<String>,
}

pub(crate) struct SuppressionApply {
    pub(crate) target: Option<PathBuf>,
    pub(crate) reference: String,
    pub(crate) reason: String,
    pub(crate) author: String,
    pub(crate) days: u64,
}

pub(crate) struct FilteredFindingMovementNotice {
    pub(crate) fingerprint: String,
}

pub(crate) struct WorkbenchOpenFinalize {
    pub(crate) focus: crate::ui_view_models::PhaseSurfaceId,
}

pub(crate) struct OpenFindingReference {
    pub(crate) reference: String,
}

pub(crate) struct OpenFindingFinalize {
    pub(crate) reference: String,
    pub(crate) outcome: OpenFindingOutcome,
}

pub(crate) enum OpenFindingOutcome {
    ChainAlias(ExploitChain),
    Found(Finding),
    Missing,
    MissingChainAlias { alias: String },
    MissingFindingAlias { alias: String },
    Error(String),
}

pub(crate) struct SceneSnapshotsHydration {
    pub(crate) target: Option<PathBuf>,
}

pub(crate) struct ScanCompletionFinalize {
    pub(crate) run_id: String,
    pub(crate) findings_count: usize,
}

pub(crate) struct TargetActivation {
    pub(crate) path: PathBuf,
    pub(crate) selected_scope: Option<TargetCandidateScope>,
    pub(crate) source: TargetActivationSource,
}

pub(crate) struct TargetRevisionSwitch {
    pub(crate) target: PathBuf,
    pub(crate) reference: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TargetActivationSource {
    Command,
    Picker,
    ScriptedScan,
    OfflineDemo,
}

pub(crate) struct HouseRulesWrite {
    pub(crate) path: PathBuf,
    pub(crate) value: String,
}

pub(crate) struct HouseRulesReset {
    pub(crate) path: PathBuf,
}

pub(crate) struct PromptOverrideWrite {
    pub(crate) path: PathBuf,
    pub(crate) value: String,
}

pub(crate) struct PromptDocumentOpen {
    pub(crate) prompts: Vec<kuzushi_core::modules::PromptSpec>,
    pub(crate) prompt_index: usize,
    pub(crate) origin: ShellView,
}

pub(crate) struct PromptOverrideReset {
    pub(crate) path: PathBuf,
}

pub(crate) struct PromptOverrideEdit {
    pub(crate) path: PathBuf,
}

pub(crate) struct PromptOverrideShow {
    pub(crate) path: PathBuf,
}

pub(crate) struct PromptOverrideDiff {
    pub(crate) path: PathBuf,
}

pub(crate) struct PromptOverrideList {
    pub(crate) dir: PathBuf,
}

pub(crate) struct HouseRulesShow {
    pub(crate) path: Option<PathBuf>,
}

pub(crate) struct HouseRulesRefresh {
    pub(crate) path: Option<PathBuf>,
}

pub(crate) struct OpenRunArtifact {
    pub(crate) selector: String,
    pub(crate) target: Option<PathBuf>,
    pub(crate) view: RunArtifactView,
}

#[derive(Clone, Copy)]
pub(crate) enum RunArtifactView {
    Replay,
    Trace,
}

#[derive(Debug, Clone)]
pub(crate) struct RunToolPreparation {
    pub(crate) tool_name: String,
    pub(crate) input: Option<String>,
    pub(crate) target: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub(crate) struct RunToolLaunch {
    pub(crate) tool_name: String,
    pub(crate) input: PreparedToolInput,
    pub(crate) workspace: WorkspaceTarget,
    pub(crate) thinking_level: Option<String>,
    pub(crate) authorization: ExecutionAuthorization,
}

impl ShellApp {
    pub(super) fn start_offline_demo_fixture_scan_effect(&mut self) -> Vec<ShellEffect> {
        match kuzushi_core::prepare_demo_fixture() {
            Ok(demo_dir) => {
                self.log(
                    "demo",
                    format!(
                        "offline fixture ready at {} — deterministic engines only; no key or model required",
                        demo_dir.display()
                    ),
                );
                self.request_target_activation(TargetActivation {
                    path: demo_dir,
                    selected_scope: None,
                    source: TargetActivationSource::OfflineDemo,
                })
            }
            Err(error) => {
                self.log("error", format!("could not prepare demo fixture: {error}"));
                Vec::new()
            }
        }
    }

    pub(super) fn export_workspace_findings_effect(&mut self, export: WorkspaceExportFindings) {
        match export_findings_for_target(
            export.target.as_ref(),
            &export.output,
            export.format.as_deref(),
            export.completeness.as_deref(),
            export.allow_empty,
        ) {
            Ok(report) => {
                let workspace_view = self.build_workspace_view(Some(report.output_path.clone()));
                self.domain_mut().set_workspace_view(workspace_view);
                self.set_shell_view(ShellView::Workspace);
                self.set_focused_module(Some("workspace".to_string()));
                self.log(
                    "export",
                    workspace_export_message(&report, export.completeness.as_deref()),
                );
            }
            Err(error) => {
                let workspace_view = self.build_workspace_view(None);
                self.domain_mut().set_workspace_view(workspace_view);
                self.set_shell_view(ShellView::Workspace);
                self.log(
                    "error",
                    format!(
                        "{error}. Next: workspace export findings <path> [json|jsonl|sarif|csv|markdown-bundle] [--completeness open|complete] [--allow-empty]"
                    ),
                );
            }
        }
    }

    pub(super) fn export_report_effect(&mut self, export: ReportExport) {
        let timestamp = effect_timestamp();
        let result = export_findings_for_target(
            export.target.as_ref(),
            &export.output,
            Some(export.format.as_str()),
            Some(export.completeness.as_str()),
            true,
        );
        let receipt = match result {
            Ok(report) => ReportReceipt {
                format: report.format,
                completeness: export.completeness,
                count: Some(report.count),
                absolute_path: Some(report.output_path),
                error: None,
                timestamp,
            },
            Err(error) => ReportReceipt {
                format: export.format,
                completeness: export.completeness,
                count: None,
                absolute_path: report_absolute_path(export.target.as_ref(), &export.output),
                error: Some(error.to_string()),
                timestamp,
            },
        };
        self.router.report_mut().set_receipt(receipt);
        self.set_shell_view(ShellView::Report);
    }

    pub(super) fn reveal_report_destination_effect(&mut self) {
        let path = self
            .router
            .report()
            .receipt()
            .and_then(|receipt| receipt.absolute_path.clone());
        let result = path
            .as_deref()
            .context("export the report before revealing its destination")
            .and_then(reveal_destination);
        match result {
            Ok(()) => self.router.report_mut().set_reveal_error(None),
            Err(error) => self
                .router
                .report_mut()
                .set_reveal_error(Some(error.to_string())),
        }
    }

    pub(super) fn reindex_workspace_effect(&mut self, reindex: WorkspaceReindex) {
        match reindex_workspace_for_target(reindex.target.as_ref(), &reindex.changes) {
            Ok(update) => {
                let workspace_view = self.build_workspace_view(None);
                self.domain_mut().set_workspace_view(workspace_view);
                if workspace_reindex_clears_stale(&update) {
                    self.clear_workspace_stale();
                }
                self.set_shell_view(ShellView::Workspace);
                self.set_focused_module(Some("workspace".to_string()));
                self.log("workspace", workspace_reindex_message(&update));
            }
            Err(error) => {
                let workspace_view = self.build_workspace_view(None);
                self.domain_mut().set_workspace_view(workspace_view);
                self.set_shell_view(ShellView::Workspace);
                self.log(
                    "error",
                    format!("{error}. Next: target <path>, then workspace reindex"),
                );
            }
        }
    }

    pub(super) fn init_workspace_scope_effect(
        &mut self,
        init: WorkspaceScopeInit,
    ) -> Vec<ShellEffect> {
        match init_scope_for_target(init.target.as_ref()) {
            Ok(path) => {
                let workspace_view = self.build_workspace_view(None);
                self.domain_mut().set_workspace_view(workspace_view);
                self.set_shell_view(ShellView::Workspace);
                self.set_focused_module(Some("workspace".to_string()));
                self.log(
                    "scope",
                    format!(
                        "wrote {}. Edit in_scope/out_of_scope, then run recon/import tools.",
                        path.display()
                    ),
                );
                vec![ShellEffect::RefreshProgramScope]
            }
            Err(error) => {
                let workspace_view = self.build_workspace_view(None);
                self.domain_mut().set_workspace_view(workspace_view);
                self.set_shell_view(ShellView::Workspace);
                self.log(
                    "error",
                    format!("{error}. Next: target <path>, then workspace scope init"),
                );
                Vec::new()
            }
        }
    }

    pub(super) fn record_review_decision_effect(
        &mut self,
        apply: ReviewDecisionApply,
    ) -> Vec<ShellEffect> {
        let workspace = match workspace_for_target(apply.target.as_ref()) {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log_review_decision_workspace_error(error);
                return Vec::new();
            }
        };
        match record_review_decision_in_workspace(&workspace, &apply) {
            Ok(decision_id) => {
                self.clear_review_decision_conflict();
                let label = review_decision_finding_label(apply.alias.as_deref(), &apply.finding);
                self.log_saved_review_decision(decision_id, apply.decision.verdict, &label);
                self.review_decision_refresh_effects(&apply.finding)
            }
            Err(error) => {
                if self.log_review_decision_write_error(&apply.finding, error) {
                    self.review_decision_conflict_refresh_effects()
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn log_review_decision_workspace_error(&mut self, error: anyhow::Error) {
        self.set_error_notice(
            "review",
            with_next_step(error.to_string(), "target <path> then findings"),
        );
    }

    pub(super) fn apply_threat_patch_effect(&mut self, apply: ThreatPatchApply) {
        let target = apply.target;
        self.engagement.clear_pending_threat_patch();
        self.set_completed_activity("threat model", "pending patch applied");
        let mut document = kuzushi_core::load_persistent_threat_model(&target)
            .unwrap_or_else(|| serde_json::json!({}));
        merge_json(&mut document, &apply.patch.patch);
        match kuzushi_core::save_persistent_threat_model(&target, &document, true) {
            Ok(_) => self.log_applied_threat_patch(apply.patch.unsupported),
            Err(error) => self.log("error", format!("failed to write threat model: {error}")),
        }
    }

    fn log_applied_threat_patch(&mut self, unsupported: Vec<String>) {
        self.log(
            "threats",
            format!("applied patch ({} unsupported note(s))", unsupported.len()),
        );
        for note in unsupported {
            self.log("threats-skip", note);
        }
    }

    pub(super) fn apply_reviewed_patch_effect(&mut self, apply: ReviewedPatchApply) {
        let workspace = match workspace_for_target(apply.target.as_ref()) {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log(
                    "error",
                    with_next_step(error.to_string(), "target <path> then patch apply"),
                );
                return;
            }
        };
        let saga = match begin_patch_application(&workspace, self.findings(), &apply) {
            Ok(saga) => saga,
            Err(error) => {
                self.log("error", format!("patch apply blocked: {error}"));
                return;
            }
        };
        let result = kuzushi_core::remediation::patch::apply_prepared_reviewed_patch(
            workspace.root(),
            &apply.diff,
            &saga.plan,
        );
        match result {
            Ok(report) => self.finish_reviewed_patch_apply(&apply.alias, saga, report),
            Err(error) => self.fail_reviewed_patch_apply(saga, error),
        }
    }

    fn finish_reviewed_patch_apply(
        &mut self,
        alias: &str,
        mut saga: PatchApplicationSaga,
        report: kuzushi_core::remediation::patch::ReviewedPatchApplyReport,
    ) {
        saga.record.state = kuzushi_core::PatchLifecycleState::Applied;
        saga.record.touched_files = report.touched_files.clone();
        saga.record.applied_at = Some(effect_timestamp());
        saga.record.updated_at = effect_timestamp();
        saga.record.detail = Some("applied; re-verification required".to_string());
        if let Err(error) = saga.store.insert_patch_lifecycle_record(&saga.record) {
            self.invalidate_finding_patch_truth(Some(&saga.record.fingerprint));
            self.log(
                "error",
                format!(
                    "patch was applied, but terminal receipt persistence failed; recovery remains at application {}: {error}",
                    saga.record.application_id
                ),
            );
            return;
        }
        self.invalidate_finding_patch_truth(Some(&saga.record.fingerprint));
        self.engagement.clear_pending_patch();
        self.set_shell_view(ShellView::Workbench);
        self.router
            .workbench_mut()
            .set_page(Some(crate::app::WorkbenchPage::Fix));
        self.router
            .workbench_mut()
            .set_focus(crate::ui_view_models::PhaseSurfaceId::FixRemediation);
        self.log(
            "patch",
            applied_patch_message(alias, &report, &saga.record.application_id),
        );
    }

    fn fail_reviewed_patch_apply(&mut self, mut saga: PatchApplicationSaga, error: anyhow::Error) {
        saga.record.state = kuzushi_core::PatchLifecycleState::ApplyFailed;
        saga.record.detail = Some(error.to_string());
        saga.record.updated_at = effect_timestamp();
        let receipt_error = saga.store.insert_patch_lifecycle_record(&saga.record).err();
        self.invalidate_finding_patch_truth(Some(&saga.record.fingerprint));
        let detail = receipt_error.map_or_else(
            || error.to_string(),
            |receipt| format!("{error}; failed to persist terminal receipt: {receipt}"),
        );
        self.log(
            "error",
            with_next_step(detail, "review the diff or patch regen"),
        );
    }

    pub(super) fn dispatch_run_tool_effect(&mut self, launch: RunToolLaunch) -> Vec<ShellEffect> {
        self.dispatch_run_tool(
            launch.tool_name,
            launch.input,
            launch.workspace,
            launch.thinking_level,
            launch.authorization,
        )
    }

    pub(super) fn prepare_run_tool_effect(
        &mut self,
        prepare: RunToolPreparation,
    ) -> Vec<ShellEffect> {
        self.prepare_run_tool_launch(prepare)
    }

    pub(super) fn advance_prereq_chain_effect(&mut self, advance: PrereqChainAdvance) {
        let workspace = match workspace_for_target(advance.target.as_ref()) {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log(
                    "error",
                    with_next_step(
                        error.to_string(),
                        "target <path> then approve prerequisites",
                    ),
                );
                self.engagement.clear_pending_chain();
                return;
            }
        };
        self.advance_chain(workspace);
    }

    pub(super) fn cancel_active_jobs_effect(&mut self) {
        if !self.request_active_abort() {
            self.log("cancel", "no active scan/tool/agent to cancel");
        }
    }

    /// Cancel exactly one live job slot (`jobs -k <id>`). Scoped so a per-row
    /// cancel does not abort concurrent jobs the way `CancelActiveJobs` does.
    pub(super) fn cancel_job_effect(&mut self, kind: JobKind) {
        let cancelled = match kind {
            // The Run slot holds either a scan or a background tool; one of
            // these matches, the other is a no-op.
            JobKind::Run => self.request_scan_abort() | self.request_tool_abort(),
            JobKind::Agent => self.request_agent_abort(),
            JobKind::Plan => self.request_plan_abort(),
            JobKind::Threat => self.request_threat_abort(),
        };
        if !cancelled {
            self.log("jobs", "that job is no longer running; nothing to cancel");
            return;
        }
        self.flush_session_transcript();
        // Only the Run slot (scan/tool) ever writes DAG rows into the
        // Activity session — Agent/Plan/Threat jobs report through a
        // separate trace-free path (see `ShellEvent::kind()`). Cancelling a
        // non-Run job must not blank the still-live Run job's rows.
        if kind == JobKind::Run {
            if let Some(session) = self.activity_mut() {
                session.mark_active_tasks_canceling();
            }
        }
    }

    pub(super) fn open_run_artifact_effect(&mut self, open: OpenRunArtifact) {
        let Some(run_id) = resolve_run_artifact_selector(self, &open) else {
            return;
        };
        match open.view {
            RunArtifactView::Replay => {
                self.router.replay_mut().open(run_id.clone());
                self.set_shell_view(ShellView::Replay);
                self.log("replay", run_id);
            }
            RunArtifactView::Trace => {
                self.router.trace_mut().open(run_id.clone());
                self.set_shell_view(ShellView::Trace);
                self.log("trace", run_id);
            }
        }
    }

    pub(super) fn open_activity_effect(&mut self, open: ActivityOpen) {
        if self.activity().is_none() {
            let mut session =
                ActivitySession::new(open.run_id.unwrap_or_else(manual_activity_run_id));
            session.seed_from_registry_legacy(self.registry());
            self.set_activity(Some(session));
        }
        self.set_shell_view(ShellView::Activity);
        self.set_input_mode(InputMode::Navigate);
        self.log("activity", "live module-progress dashboard");
    }

    pub(super) fn load_dynamic_module_effect(&mut self, load: DynamicModuleLoad) {
        let options = DynamicModuleLoadOptions {
            trusted_specifiers: self.config().operator.trusted_modules.clone(),
            lockfile_path: Some(kuzushi_core::default_dynamic_lockfile_path()),
        };
        match self
            .registry_mut()
            .load_dynamic_module(&load.specifier, &options)
        {
            Ok(()) => {
                self.log("load", format!("{} loaded. Next: tools", load.specifier));
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }
}

fn resolve_run_artifact_selector(app: &mut ShellApp, open: &OpenRunArtifact) -> Option<String> {
    if open.selector != "latest" {
        return resolve_known_run_reference(app, open);
    }
    let Some(target) = open.target.as_deref() else {
        app.log(
            "error",
            format!(
                "{} latest needs a target. Next: target <path> or show runs",
                open.view.verb()
            ),
        );
        return None;
    };
    read_latest_run_id(app, target)
}

fn resolve_known_run_reference(app: &mut ShellApp, open: &OpenRunArtifact) -> Option<String> {
    let mut candidates = open
        .target
        .as_deref()
        .and_then(|target| kuzushi_core::list_run_summaries(target).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|summary| summary.run_id)
        .collect::<Vec<_>>();
    if let Some(session) = app.activity() {
        candidates.push(session.run_id.clone());
    }
    match resolve_run_reference(&open.selector, candidates.iter().map(String::as_str)) {
        RunReferenceResolution::Resolved(run_id) => Some(run_id),
        RunReferenceResolution::Ambiguous(matches) => {
            app.log(
                "error",
                format!(
                    "run reference {:?} is ambiguous: {}",
                    open.selector,
                    matches
                        .iter()
                        .map(|id| compact_run_reference(id))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
            None
        }
        RunReferenceResolution::Missing => {
            app.log("error", format!("run {:?} was not found", open.selector));
            None
        }
    }
}

fn read_latest_run_id(app: &mut ShellApp, target: &Path) -> Option<String> {
    match kuzushi_core::read_latest_run_pointer(target) {
        Ok(kuzushi_core::LatestRunPointerState::Ready(run_id)) => Some(run_id.as_str().to_string()),
        Ok(kuzushi_core::LatestRunPointerState::Missing) => {
            app.log("error", "latest run pointer is missing. Next: show runs");
            None
        }
        Ok(kuzushi_core::LatestRunPointerState::Invalid(issue)) => {
            app.log(
                "error",
                format!("latest run pointer is invalid: {issue:?}. Next: show runs"),
            );
            None
        }
        Err(error) => {
            app.log(
                "error",
                format!("could not resolve latest run pointer: {error}. Next: show runs"),
            );
            None
        }
    }
}

impl RunArtifactView {
    fn verb(self) -> &'static str {
        match self {
            Self::Replay => "replay",
            Self::Trace => "trace",
        }
    }
}

fn manual_activity_run_id() -> String {
    format!("manual-{}", current_unix_seconds())
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn record_review_decision_in_workspace(
    workspace: &WorkspaceTarget,
    apply: &ReviewDecisionApply,
) -> anyhow::Result<i64> {
    match apply.read_watermark {
        Some(read_watermark) => {
            kuzushi_core::workspace::record_user_review_decision_for_finding_at_watermark(
                workspace,
                &apply.finding,
                &apply.decision,
                Some(read_watermark),
            )
        }
        None => kuzushi_core::workspace::record_user_review_decision_for_finding(
            workspace,
            &apply.finding,
            &apply.decision,
        ),
    }
}

fn applied_patch_message(
    alias: &str,
    report: &kuzushi_core::remediation::patch::ReviewedPatchApplyReport,
    application_id: &str,
) -> String {
    let files = if report.touched_paths.is_empty() {
        "0 files".to_string()
    } else {
        format!(
            "{} {}: {}",
            report.touched_paths.len(),
            if report.touched_paths.len() == 1 {
                "file"
            } else {
                "files"
            },
            report.touched_paths.join(", ")
        )
    };
    format!(
        "applied reviewed patch for {alias} to {files}; re-verification required. Next: run patch:reverify {{\"applicationId\":\"{application_id}\"}}"
    )
}

struct PatchApplicationIdentity {
    store: kuzushi_core::FindingStore,
    stable_fp: String,
    fingerprint: String,
    finding_scan_id: String,
    patch_run_id: String,
    source_commit: String,
}

struct PatchApplicationSaga {
    store: kuzushi_core::FindingStore,
    record: kuzushi_core::PatchLifecycleRecord,
    plan: kuzushi_core::remediation::patch::ReviewedPatchApplyPlan,
}

fn patch_application_identity(
    workspace: &WorkspaceTarget,
    findings: &[Finding],
    apply: &ReviewedPatchApply,
) -> anyhow::Result<PatchApplicationIdentity> {
    ensure_apply_matches_durable_selection(workspace, apply)?;
    let store = kuzushi_core::FindingStore::open(workspace.findings_db_path())?;
    let finding = finding_for_patch_apply(&store, findings, &apply.alias)?;
    let patch = persisted_patch_for_apply(&store, &finding, apply)?;
    let provenance = patch
        .provenance
        .context("legacy patch has no source provenance; regenerate the patch")?;
    provenance.ensure_complete_for_apply()?;
    ensure_patch_target_matches(workspace, &provenance.target)?;
    let finding_scan_id = finding
        .scan_id
        .as_deref()
        .filter(|scan_id| !scan_id.trim().is_empty())
        .context("current finding has no discovery generation; regenerate the patch")?
        .to_string();
    anyhow::ensure!(
        provenance.detector_run_id.as_deref() == Some(finding_scan_id.as_str()),
        "patch belongs to an earlier finding generation; regenerate it"
    );
    let stable_fp = store.patch_lifecycle_stable_fp(&finding.fingerprint)?;
    Ok(PatchApplicationIdentity {
        store,
        stable_fp,
        fingerprint: finding.fingerprint,
        finding_scan_id,
        patch_run_id: patch.patch_run_id,
        source_commit: provenance.source_commit,
    })
}

fn ensure_apply_matches_durable_selection(
    workspace: &WorkspaceTarget,
    apply: &ReviewedPatchApply,
) -> anyhow::Result<()> {
    let selection = load_durable_fix_selection(workspace.root())?;
    anyhow::ensure!(
        selection.attempt_id == apply.selected_attempt_id,
        "durable Fix selection changed before Apply"
    );
    anyhow::ensure!(
        selection.patch.patch_run_id == apply.patch_run_id
            && selection.patch.diff == apply.diff
            && selection.patch.alias == apply.alias,
        "Apply request does not match the durable Fix selection"
    );
    Ok(())
}

fn finding_for_patch_apply(
    store: &kuzushi_core::FindingStore,
    findings: &[Finding],
    alias: &str,
) -> anyhow::Result<Finding> {
    if let Some(finding) = kuzushi_core::resolve_finding_alias(findings, alias) {
        return Ok(finding);
    }
    store
        .get_finding_by_reference(alias)?
        .with_context(|| format!("finding {alias:?} is not available"))
}

fn persisted_patch_for_apply(
    store: &kuzushi_core::FindingStore,
    finding: &Finding,
    apply: &ReviewedPatchApply,
) -> anyhow::Result<kuzushi_core::PatchResult> {
    let patch = store
        .get_patch_results_for_finding(&finding.fingerprint)?
        .into_iter()
        .find(|patch| patch.patch_run_id == apply.patch_run_id)
        .context("the reviewed patch result is no longer available")?;
    anyhow::ensure!(
        patch.status == kuzushi_core::PatchStatus::Sound,
        "patch {} is {}; only SOUND candidates can be applied",
        patch.patch_run_id,
        patch.status.as_str()
    );
    anyhow::ensure!(
        patch.diff.as_deref() == Some(apply.diff.as_str()),
        "the reviewed diff does not match its persisted patch result"
    );
    Ok(patch)
}

fn ensure_patch_target_matches(workspace: &WorkspaceTarget, recorded: &str) -> anyhow::Result<()> {
    let recorded = std::fs::canonicalize(recorded)
        .context("patch generation target is unavailable; regenerate the patch")?;
    anyhow::ensure!(
        recorded == workspace.root(),
        "patch was generated for another target; regenerate it for the active target"
    );
    Ok(())
}

fn begin_patch_application(
    workspace: &WorkspaceTarget,
    findings: &[Finding],
    apply: &ReviewedPatchApply,
) -> anyhow::Result<PatchApplicationSaga> {
    let identity = patch_application_identity(workspace, findings, apply)?;
    let plan = kuzushi_core::remediation::patch::prepare_reviewed_patch_apply(
        workspace.root(),
        &apply.diff,
        &identity.source_commit,
    )?;
    let now = effect_timestamp();
    let record = kuzushi_core::PatchLifecycleRecord {
        application_id: kuzushi_core::new_run_id("patch-application"),
        stable_fp: identity.stable_fp,
        fingerprint: identity.fingerprint,
        finding_scan_id: Some(identity.finding_scan_id),
        patch_run_id: identity.patch_run_id,
        target: workspace.root().display().to_string(),
        diff_hash: plan.diff_hash.clone(),
        base_commit: Some(plan.source_commit.clone()),
        touched_files: plan.touched_files.clone(),
        state: kuzushi_core::PatchLifecycleState::Applying,
        reverify_run_id: None,
        detail: Some("application intent recorded; mutation pending".to_string()),
        actor: "terminal-operator".to_string(),
        application_started_at: now.clone(),
        applied_at: None,
        updated_at: now,
    };
    identity.store.insert_patch_lifecycle_record(&record)?;
    Ok(PatchApplicationSaga {
        store: identity.store,
        record,
        plan,
    })
}

fn effect_timestamp() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

fn report_absolute_path(target: Option<&PathBuf>, output: &Path) -> Option<PathBuf> {
    let workspace = workspace_for_target(target).ok()?;
    Some(if output.is_absolute() {
        output.to_path_buf()
    } else {
        workspace.root().join(output)
    })
}

fn reveal_destination(path: &Path) -> anyhow::Result<()> {
    let mut command = reveal_destination_command(path)?;
    let status = command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .with_context(|| format!("could not reveal {}", path.display()))?;
    anyhow::ensure!(
        status.success(),
        "destination reveal exited with status {status}"
    );
    Ok(())
}

fn reveal_destination_command(path: &Path) -> anyhow::Result<std::process::Command> {
    platform_reveal_destination_command(path)
}

#[cfg(target_os = "macos")]
fn platform_reveal_destination_command(path: &Path) -> anyhow::Result<std::process::Command> {
    let mut command = std::process::Command::new("open");
    command.arg("-R").arg(path);
    Ok(command)
}

#[cfg(target_os = "linux")]
fn platform_reveal_destination_command(path: &Path) -> anyhow::Result<std::process::Command> {
    let mut command = std::process::Command::new("xdg-open");
    command.arg(path.parent().unwrap_or(path));
    Ok(command)
}

#[cfg(target_os = "windows")]
fn platform_reveal_destination_command(path: &Path) -> anyhow::Result<std::process::Command> {
    let mut command = std::process::Command::new("explorer");
    command.arg("/select,").arg(path);
    Ok(command)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn platform_reveal_destination_command(_path: &Path) -> anyhow::Result<std::process::Command> {
    anyhow::bail!("Reveal Destination is unavailable on this platform")
}

fn workspace_reindex_message(update: &WorkspaceIndexUpdate) -> String {
    match update {
        WorkspaceIndexUpdate::Noop { change_count } => {
            format!("no index update needed for {change_count} pending changes")
        }
        WorkspaceIndexUpdate::Invalidated {
            change_count,
            applied_seq,
            summary,
        } => format!(
            "recorded workspace invalidation for {change_count} pending changes at seq {applied_seq}: {summary}"
        ),
        WorkspaceIndexUpdate::Incremental(indexed) => format!(
            "incrementally indexed {} files at seq {} ({})",
            indexed.file_count, indexed.applied_seq, indexed.snapshot_hash
        ),
        WorkspaceIndexUpdate::Full(indexed) => format!(
            "indexed {} files at seq {} ({})",
            indexed.file_count, indexed.applied_seq, indexed.snapshot_hash
        ),
    }
}

fn workspace_reindex_clears_stale(update: &WorkspaceIndexUpdate) -> bool {
    !matches!(update, WorkspaceIndexUpdate::Noop { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::incremental_index::{index_workspace_snapshot, ReindexPlan, WorkspaceChange};
    use kuzushi_core::V2Config;

    #[test]
    fn report_export_success_stays_on_report_with_a_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let store = kuzushi_core::FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .record_run_started("report-run", workspace.root(), "completed")
            .unwrap();
        let finding = kuzushi_core::Finding::new_semgrep(
            "report.rule",
            "src/app.rs",
            4,
            Some(4),
            kuzushi_core::Severity::High,
            "report finding",
        );
        store.insert_finding("report-run", &finding).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        app.export_report_effect(ReportExport {
            format: kuzushi_core::WorkspaceExportFormat::Sarif,
            completeness: kuzushi_core::WorkspaceExportCompleteness::All,
            output: PathBuf::from("report.sarif"),
            target: Some(workspace.root().to_path_buf()),
        });

        assert_eq!(app.shell_view(), ShellView::Report);
        let receipt = app.router.report().receipt().unwrap();
        assert_eq!(receipt.count, Some(1));
        assert!(receipt.error.is_none());
        let expected_path = workspace.root().join("report.sarif");
        assert_eq!(
            receipt.absolute_path.as_deref(),
            Some(expected_path.as_path())
        );
        assert!(expected_path.exists());
    }

    #[test]
    fn report_export_failure_stays_on_report_with_retry_context() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing-target");
        let mut app = ShellApp::new(V2Config::default(), None);

        app.export_report_effect(ReportExport {
            format: kuzushi_core::WorkspaceExportFormat::Json,
            completeness: kuzushi_core::WorkspaceExportCompleteness::Complete,
            output: PathBuf::from("findings.json"),
            target: Some(missing),
        });

        assert_eq!(app.shell_view(), ShellView::Report);
        let receipt = app.router.report().receipt().unwrap();
        assert_eq!(receipt.count, None);
        assert!(receipt.error.is_some());
        assert_eq!(receipt.format, kuzushi_core::WorkspaceExportFormat::Json);
        assert_eq!(
            receipt.completeness,
            kuzushi_core::WorkspaceExportCompleteness::Complete
        );
    }

    #[test]
    fn effect_runtime_executes_lifecycle_effects() {
        let mut app = ShellApp::new(V2Config::default(), None);

        EffectRuntime::execute(&mut app, vec![ShellEffect::Quit]);

        assert!(app.should_quit());
    }

    #[test]
    fn quit_effect_requests_abort_then_finishes_shell_quit() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let cancel = ScanCancellation::default();
        app.set_scan_cancel_for_test(cancel.clone());
        app.set_scan_panel(Some(ScanPanelState {
            run_id: Some("run-1".to_string()),
            target: PathBuf::from("."),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            abort_requested: false,
            error: None,
        }));

        EffectRuntime::execute(&mut app, vec![ShellEffect::Quit]);

        assert!(cancel.is_cancelled());
        assert!(app.scan().is_some_and(|scan| scan.abort_requested));
        assert!(app.should_quit());
        assert!(app.log_lines().iter().any(|line| {
            line.prefix == "system" && line.body.contains("exit requested; closing shell")
        }));
    }

    #[test]
    fn offline_demo_fixture_effect_returns_target_activation_without_starting_worker() {
        let _fixture_lock = demo_fixture_test_lock();
        let mut app = ShellApp::new(V2Config::default(), None);

        let effects = app.start_offline_demo_fixture_scan_effect();

        assert_eq!(effects.len(), 1);
        assert!(matches!(
            effects[0],
            ShellEffect::ActivateTarget(TargetActivation {
                source: TargetActivationSource::OfflineDemo,
                ..
            })
        ));
        assert!(app.scan_is_none());
        assert!(!app.jobs().is_running(JobKind::Run));
        assert!(app
            .log_lines()
            .iter()
            .any(|entry| entry.body.contains("offline fixture ready")));
    }

    #[test]
    fn workspace_reindex_effect_clears_stale_state_after_success() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("src.rs"), "fn main() {}\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.apply_workspace_changes(&[WorkspaceChange::GitHeadChanged]);
        assert_eq!(
            app.workspace_stale().unwrap().strongest_plan(),
            ReindexPlan::FullSnapshot
        );

        let target = app.target_owned();
        let changes = app.workspace_pending_changes();
        EffectRuntime::execute(
            &mut app,
            vec![ShellEffect::WorkspaceReindex(WorkspaceReindex {
                target,
                changes,
            })],
        );

        assert!(app.workspace_stale().is_none());
        assert_eq!(app.shell_view(), ShellView::Workspace);
        assert!(workspace.objects_dir().join("blake3").is_dir());
        assert!(app.log_lines().iter().any(|entry| {
            entry.prefix == "workspace" && entry.body.contains("indexed 1 files")
        }));
    }

    #[test]
    fn workspace_reindex_effect_uses_pending_file_changes_incrementally() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("src")).unwrap();
        std::fs::write(temp.path().join("src/app.rs"), "fn main() {}\n").unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        index_workspace_snapshot(&workspace).unwrap();
        std::fs::write(
            temp.path().join("src/app.rs"),
            "fn main() { println!(\"changed\"); }\n", // terminal-output: inline fixture
        )
        .unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.apply_workspace_changes(&[WorkspaceChange::FileChanged("src/app.rs".into())]);

        let target = app.target_owned();
        let changes = app.workspace_pending_changes();
        EffectRuntime::execute(
            &mut app,
            vec![ShellEffect::WorkspaceReindex(WorkspaceReindex {
                target,
                changes,
            })],
        );

        assert!(app.workspace_stale().is_none());
        assert!(app.log_lines().iter().any(|entry| {
            entry.prefix == "workspace" && entry.body.contains("incrementally indexed 1 files")
        }));
    }

    #[test]
    fn workspace_reindex_effect_records_prompt_invalidation_and_clears_stale_state() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(temp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.apply_workspace_changes(&[WorkspaceChange::PromptOrHouseRuleChanged]);

        let target = app.target_owned();
        let changes = app.workspace_pending_changes();
        EffectRuntime::execute(
            &mut app,
            vec![ShellEffect::WorkspaceReindex(WorkspaceReindex {
                target,
                changes,
            })],
        );

        assert!(app.workspace_stale().is_none());
        assert!(app.log_lines().iter().any(|entry| {
            entry.prefix == "workspace" && entry.body.contains("recorded workspace invalidation")
        }));
    }
}
