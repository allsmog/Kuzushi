use super::*;
use kuzushi_core::findings::ReviewDecision;
use kuzushi_core::incremental_index::WorkspaceIndexUpdate;
use kuzushi_core::DynamicModuleLoadOptions;
use kuzushi_core::OptionScope;
use std::path::{Path, PathBuf};

pub(crate) enum ShellEffect {
    OpenActivity(ActivityOpen),
    ApplyReviewedPatch(ReviewedPatchApply),
    ApplySastTaskOptions(SastTaskOptionsApply),
    ApplyThreatPatch(ThreatPatchApply),
    AuthLogin(AuthLoginStart),
    ActivateTarget(TargetActivation),
    AdvancePrereqChain(PrereqChainAdvance),
    AbortForBudget,
    CancelActiveJobs,
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
    pub(crate) alias: String,
    pub(crate) diff: String,
    pub(crate) target: Option<PathBuf>,
}

pub(crate) struct ThreatPatchApply {
    pub(crate) patch: ThreatPatch,
    pub(crate) target: Option<PathBuf>,
}

pub(crate) struct ReviewDecisionApply {
    pub(crate) alias: Option<String>,
    pub(crate) decision: ReviewDecision,
    pub(crate) finding: Finding,
    pub(crate) read_watermark: Option<u64>,
    pub(crate) target: Option<PathBuf>,
}

pub(crate) struct WorkspaceExportFindings {
    pub(crate) allow_empty: bool,
    pub(crate) completeness: Option<String>,
    pub(crate) format: Option<String>,
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
}

pub(crate) struct ScanRunRecord {
    pub(crate) target: Option<PathBuf>,
    pub(crate) run_id: String,
    pub(crate) target_label: String,
    pub(crate) outcome: ScanRunOutcome,
}

pub(crate) enum ScanRunOutcome {
    Complete { findings_count: usize },
    Failed { error: String },
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
    Complete { result: serde_json::Value },
    Failed { error: String },
}

pub(crate) struct FindingsRefresh {
    pub(crate) announce: bool,
    pub(crate) filter: Option<String>,
}

pub(crate) struct FilteredFindingMovementNotice {
    pub(crate) fingerprint: String,
}

pub(crate) struct WorkbenchOpenFinalize {
    pub(crate) pane: WorkbenchPane,
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
    pub(crate) input: serde_json::Value,
    pub(crate) workspace: WorkspaceTarget,
    pub(crate) thinking_level: Option<String>,
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
                self.reduce_scan_start(
                    Some(demo_dir),
                    Some(kuzushi_core::offline_demo_scan_input()),
                )
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
                let label = review_decision_finding_label(apply.alias.as_deref(), &apply.finding);
                self.log_saved_review_decision(decision_id, apply.decision.verdict, &label);
                self.review_decision_refresh_effects(&apply.finding)
            }
            Err(error) => {
                self.log_review_decision_write_error(&apply.finding, error);
                Vec::new()
            }
        }
    }

    fn log_review_decision_workspace_error(&mut self, error: anyhow::Error) {
        self.log(
            "error",
            with_next_step(error.to_string(), "target <path> then findings"),
        );
    }

    pub(super) fn apply_threat_patch_effect(&mut self, apply: ThreatPatchApply) {
        let target = threat_patch_target_root(apply.target);
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
        match kuzushi_core::remediation::patch::apply_reviewed_patch(workspace.root(), &apply.diff)
        {
            Ok(report) => {
                self.engagement.clear_pending_patch();
                self.set_shell_view(ShellView::Workbench);
                self.router
                    .workbench_mut()
                    .set_page(Some(crate::app::WorkbenchPage::Ship));
                self.router
                    .workbench_mut()
                    .set_focus(crate::app::WorkbenchPane::Details);
                self.log("patch", applied_patch_message(&apply.alias, &report));
            }
            Err(error) => self.log(
                "error",
                with_next_step(error.to_string(), "review the diff or patch regen"),
            ),
        }
    }

    pub(super) fn dispatch_run_tool_effect(&mut self, launch: RunToolLaunch) -> Vec<ShellEffect> {
        self.dispatch_run_tool(
            launch.tool_name,
            launch.input,
            launch.workspace,
            launch.thinking_level,
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
            session.seed_from_registry(self.registry());
            self.set_activity(Some(session));
        }
        self.set_shell_view(ShellView::Activity);
        self.log("activity", "live module-progress dashboard");
    }

    pub(super) fn load_dynamic_module_effect(&mut self, load: DynamicModuleLoad) {
        let options = DynamicModuleLoadOptions {
            trusted_specifiers: self.config().operator.trusted_modules.clone(),
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
        return Some(open.selector.clone());
    }
    let latest_path = latest_run_pointer_path(app, open)?;
    read_latest_run_id(app, &latest_path)
}

fn latest_run_pointer_path(app: &mut ShellApp, open: &OpenRunArtifact) -> Option<PathBuf> {
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
    Some(crate::ui_view_models::ui_latest_run_path(Some(target)))
}

fn read_latest_run_id(app: &mut ShellApp, latest_path: &Path) -> Option<String> {
    let text = match std::fs::read_to_string(&latest_path) {
        Ok(text) => text,
        Err(error) => {
            app.log(
                "error",
                format!(
                    "could not read latest run pointer {}: {error}. Next: show runs",
                    latest_path.display()
                ),
            );
            return None;
        }
    };
    let run_id = text.trim();
    if run_id.is_empty() {
        app.log(
            "error",
            format!(
                "latest run pointer {} is empty. Next: show runs",
                latest_path.display()
            ),
        );
        return None;
    }
    Some(run_id.to_string())
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

fn threat_patch_target_root(target: Option<PathBuf>) -> PathBuf {
    target
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
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
    format!("applied reviewed patch for {alias} to {files}")
}

fn workspace_reindex_message(update: &WorkspaceIndexUpdate) -> String {
    match update {
        WorkspaceIndexUpdate::Noop { change_count } => {
            format!("no index update needed for {change_count} pending changes")
        }
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
    fn offline_demo_fixture_effect_returns_scan_followup_without_starting_worker() {
        let mut app = ShellApp::new(V2Config::default(), None);

        let effects = app.start_offline_demo_fixture_scan_effect();

        assert_eq!(effects.len(), 1);
        assert!(matches!(effects[0], ShellEffect::PrepareScan(_)));
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
            "fn main() { println!(\"changed\"); }\n",
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
    fn workspace_reindex_effect_keeps_stale_state_after_noop_update() {
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

        assert!(app.workspace_stale().is_some());
        assert!(app.log_lines().iter().any(|entry| {
            entry.prefix == "workspace" && entry.body.contains("no index update needed")
        }));
    }
}
