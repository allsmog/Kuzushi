use super::*;
use kuzushi_core::findings::ReviewDecision;
use kuzushi_core::OptionScope;
use std::path::PathBuf;

pub(crate) enum ShellEffect {
    ApplyReviewedPatch(ReviewedPatchApply),
    ApplyThreatPatch(ThreatPatchApply),
    CancelActiveJobs,
    DispatchAgent(AgentDispatch),
    DispatchRunTool(RunToolLaunch),
    PersistCommandHistory,
    PersistOptions(OptionScope),
    Quit,
    RecordReviewDecision(ReviewDecisionApply),
    StartPlanner(PlannerStart),
    StartScan(ScanStartRequest),
    StartThreat(ThreatWorkerStart),
    WorkspaceExportFindings(WorkspaceExportFindings),
    WorkspaceScopeInit(WorkspaceScopeInit),
}

pub(crate) struct ReviewedPatchApply {
    pub(crate) alias: String,
    pub(crate) diff: String,
    pub(crate) workspace: WorkspaceTarget,
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

pub(crate) struct WorkspaceScopeInit {
    pub(crate) target: Option<PathBuf>,
}

pub(crate) struct RunToolLaunch {
    pub(crate) tool_name: String,
    pub(crate) input: serde_json::Value,
    pub(crate) workspace: WorkspaceTarget,
    pub(crate) thinking_level: Option<String>,
}

impl ShellApp {
    pub(crate) fn execute_effects(&mut self, effects: Vec<ShellEffect>) {
        for effect in effects {
            self.execute_effect(effect);
        }
    }

    fn execute_effect(&mut self, effect: ShellEffect) {
        match effect {
            ShellEffect::ApplyReviewedPatch(apply) => self.apply_reviewed_patch_effect(apply),
            ShellEffect::ApplyThreatPatch(apply) => self.apply_threat_patch_effect(apply),
            ShellEffect::CancelActiveJobs => self.cancel_active_jobs_effect(),
            ShellEffect::DispatchAgent(dispatch) => self.dispatch_agent(dispatch),
            ShellEffect::DispatchRunTool(launch) => self.dispatch_run_tool_effect(launch),
            ShellEffect::PersistCommandHistory => self.persist_command_history(),
            ShellEffect::PersistOptions(scope) => self.persist_option_store(scope),
            ShellEffect::Quit => self.request_exit(),
            ShellEffect::RecordReviewDecision(apply) => self.record_review_decision_effect(apply),
            ShellEffect::StartPlanner(start) => self.dispatch_planner(start),
            ShellEffect::StartScan(request) => self.start_prepared_scan(request),
            ShellEffect::StartThreat(start) => self.dispatch_threat_worker(start),
            ShellEffect::WorkspaceExportFindings(export) => {
                self.export_workspace_findings_effect(export)
            }
            ShellEffect::WorkspaceScopeInit(init) => self.init_workspace_scope_effect(init),
        }
    }

    fn export_workspace_findings_effect(&mut self, export: WorkspaceExportFindings) {
        match export_findings_for_target(
            export.target.as_ref(),
            &export.output,
            export.format.as_deref(),
            export.completeness.as_deref(),
            export.allow_empty,
        ) {
            Ok(report) => {
                self.workspace_view = self.build_workspace_view(Some(report.output_path.clone()));
                self.shell_view = ShellView::Workspace;
                self.focused_module = Some("workspace".to_string());
                self.log(
                    "export",
                    workspace_export_message(&report, export.completeness.as_deref()),
                );
            }
            Err(error) => {
                self.workspace_view = self.build_workspace_view(None);
                self.shell_view = ShellView::Workspace;
                self.log(
                    "error",
                    format!(
                        "{error}. Next: workspace export findings <path> [json|jsonl|sarif|csv|markdown-bundle] [--completeness open|complete] [--allow-empty]"
                    ),
                );
            }
        }
    }

    fn init_workspace_scope_effect(&mut self, init: WorkspaceScopeInit) {
        match init_scope_for_target(init.target.as_ref()) {
            Ok(path) => {
                self.refresh_program_scope();
                self.workspace_view = self.build_workspace_view(None);
                self.shell_view = ShellView::Workspace;
                self.focused_module = Some("workspace".to_string());
                self.log(
                    "scope",
                    format!(
                        "wrote {}. Edit in_scope/out_of_scope, then run recon/import tools.",
                        path.display()
                    ),
                );
            }
            Err(error) => {
                self.workspace_view = self.build_workspace_view(None);
                self.shell_view = ShellView::Workspace;
                self.log(
                    "error",
                    format!("{error}. Next: target <path>, then workspace scope init"),
                );
            }
        }
    }

    fn record_review_decision_effect(&mut self, apply: ReviewDecisionApply) {
        let workspace = match workspace_for_target(apply.target.as_ref()) {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log(
                    "error",
                    with_next_step(error.to_string(), "target <path> then findings"),
                );
                return;
            }
        };
        let result = match apply.read_watermark {
            Some(read_watermark) => {
                kuzushi_core::workspace::record_user_review_decision_for_finding_at_watermark(
                    &workspace,
                    &apply.finding,
                    &apply.decision,
                    Some(read_watermark),
                )
            }
            None => kuzushi_core::workspace::record_user_review_decision_for_finding(
                &workspace,
                &apply.finding,
                &apply.decision,
            ),
        };
        match result {
            Ok(decision_id) => {
                let label = review_decision_finding_label(apply.alias.as_deref(), &apply.finding);
                self.log_saved_review_decision(decision_id, apply.decision.verdict, &label);
                self.refresh_findings_after_review_decision(&apply.finding);
            }
            Err(error) => self.log_review_decision_write_error(&apply.finding, error),
        }
    }

    fn apply_threat_patch_effect(&mut self, apply: ThreatPatchApply) {
        let target = threat_patch_target_root(apply.target);
        self.pending_threat_patch = None;
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

    fn apply_reviewed_patch_effect(&mut self, apply: ReviewedPatchApply) {
        match kuzushi_core::remediation::patch::apply_reviewed_patch(
            apply.workspace.root(),
            &apply.diff,
        ) {
            Ok(report) => {
                self.engagement.clear_pending_patch();
                self.shell_view = ShellView::Workbench;
                self.workbench_page = Some(crate::app::WorkbenchPage::Ship);
                self.workbench_focus = crate::app::WorkbenchPane::Details;
                self.log("patch", applied_patch_message(&apply.alias, &report));
            }
            Err(error) => self.log(
                "error",
                with_next_step(error.to_string(), "review the diff or patch regen"),
            ),
        }
    }

    fn dispatch_run_tool_effect(&mut self, launch: RunToolLaunch) {
        self.dispatch_run_tool(
            launch.tool_name,
            launch.input,
            launch.workspace,
            launch.thinking_level,
        );
    }

    fn cancel_active_jobs_effect(&mut self) {
        if !self.request_active_abort() {
            self.log("cancel", "no active scan/tool/agent to cancel");
        }
    }
}

fn threat_patch_target_root(target: Option<PathBuf>) -> PathBuf {
    target
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
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
