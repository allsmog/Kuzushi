use super::*;
use std::collections::VecDeque;

pub(crate) struct EffectRuntime;

impl EffectRuntime {
    pub(crate) fn execute(app: &mut ShellApp, effects: Vec<ShellEffect>) {
        let mut pending = VecDeque::from(effects);
        while let Some(effect) = pending.pop_front() {
            pending.extend(Self::execute_effect(app, effect));
        }
    }

    fn execute_effect(app: &mut ShellApp, effect: ShellEffect) -> Vec<ShellEffect> {
        match effect {
            ShellEffect::PrepareRunTool(prepare) => app.prepare_run_tool_effect(prepare),
            ShellEffect::PrepareScan(prepare) => app.prepare_scan_start_effect(prepare),
            ShellEffect::DispatchRunTool(launch) => app.dispatch_run_tool_effect(launch),
            ShellEffect::Quit => Self::quit_effects(),
            effect if Self::is_chained_effect(&effect) => Self::execute_chained_effect(app, effect),
            other => {
                Self::execute_terminal_effect(app, other);
                Vec::new()
            }
        }
    }

    fn quit_effects() -> Vec<ShellEffect> {
        vec![
            ShellEffect::RequestExitAbort,
            ShellEffect::WaitForAbortCleanup,
            ShellEffect::FinishShellQuit,
        ]
    }

    fn is_chained_effect(effect: &ShellEffect) -> bool {
        matches!(
            effect,
            ShellEffect::ActivateTarget(_)
                | ShellEffect::ApplySastTaskOptions(_)
                | ShellEffect::AuthLogin(_)
                | ShellEffect::BuildContext(_)
                | ShellEffect::AdvancePrereqChain(_)
                | ShellEffect::DispatchNextPlanningTask(_)
                | ShellEffect::FinalizeGuidedScanOpen
                | ShellEffect::FireNextApprovedStrategy(_)
                | ShellEffect::OpenFinding(_)
                | ShellEffect::OpenGuidedScan(_)
                | ShellEffect::RecordReviewDecision(_)
                | ShellEffect::RecordStrategyCorrection(_)
                | ShellEffect::SelectComponent(_)
                | ShellEffect::StartOfflineDemoFixtureScan
                | ShellEffect::SwitchTargetRevision(_)
                | ShellEffect::UpdateStrategyProposalStatus(_)
                | ShellEffect::WorkspaceScopeInit(_)
        )
    }

    fn execute_chained_effect(app: &mut ShellApp, effect: ShellEffect) -> Vec<ShellEffect> {
        match effect {
            ShellEffect::ActivateTarget(activation) => app.activate_target_effect(activation),
            ShellEffect::ApplySastTaskOptions(apply) => app.apply_sast_task_options_effect(apply),
            ShellEffect::AuthLogin(login) => app.start_auth_login_effect(login),
            ShellEffect::BuildContext(build) => app.build_context_effect(build),
            ShellEffect::AdvancePrereqChain(advance) => {
                app.advance_prereq_chain_effect(advance);
                Vec::new()
            }
            ShellEffect::DispatchNextPlanningTask(dispatch) => {
                app.dispatch_next_planning_task_effect(dispatch);
                Vec::new()
            }
            ShellEffect::FinalizeGuidedScanOpen => {
                app.finalize_guided_scan_open_effect();
                Vec::new()
            }
            ShellEffect::FireNextApprovedStrategy(fire) => {
                app.fire_next_approved_strategy_effect(fire)
            }
            ShellEffect::OpenFinding(open) => app.resolve_open_finding_effect(open),
            ShellEffect::OpenGuidedScan(open) => app.open_guided_scan(open.target),
            ShellEffect::RecordReviewDecision(apply) => app.record_review_decision_effect(apply),
            ShellEffect::RecordStrategyCorrection(record) => {
                app.record_strategy_correction_effect(record)
            }
            ShellEffect::SelectComponent(selection) => app.select_component_effect(selection),
            ShellEffect::StartOfflineDemoFixtureScan => {
                app.start_offline_demo_fixture_scan_effect()
            }
            ShellEffect::SwitchTargetRevision(switch) => app.switch_target_revision_effect(switch),
            ShellEffect::UpdateStrategyProposalStatus(update) => {
                app.update_strategy_proposal_status_effect(update)
            }
            ShellEffect::WorkspaceScopeInit(init) => app.init_workspace_scope_effect(init),
            _ => unreachable!("chained effect dispatch"),
        }
    }

    fn execute_terminal_effect(app: &mut ShellApp, effect: ShellEffect) {
        match effect {
            effect @ (ShellEffect::AbortForBudget
            | ShellEffect::CancelActiveJobs
            | ShellEffect::ClearConversation
            | ShellEffect::ContinuePastBudget
            | ShellEffect::FinishShellQuit
            | ShellEffect::PauseActiveWork
            | ShellEffect::RequestExitAbort
            | ShellEffect::RequestShellQuit
            | ShellEffect::WaitForAbortCleanup) => Self::execute_control_effect(app, effect),
            effect @ (ShellEffect::ApplyReviewedPatch(_) | ShellEffect::ApplyThreatPatch(_)) => {
                Self::execute_review_effect(app, effect)
            }
            effect @ ShellEffect::ShowAuthStatus(_) => Self::execute_auth_effect(app, effect),
            effect @ (ShellEffect::DispatchAgent(_)
            | ShellEffect::RefreshDeterministicRecommendations(_)
            | ShellEffect::StartPlanner(_)
            | ShellEffect::StartScan(_)
            | ShellEffect::StartThreat(_)) => Self::execute_worker_effect(app, effect),
            effect @ (ShellEffect::DiffPromptOverride(_)
            | ShellEffect::EditPromptOverride(_)
            | ShellEffect::ListPromptOverrides(_)
            | ShellEffect::RecordPromptMutation(_)
            | ShellEffect::RefreshHouseRules(_)
            | ShellEffect::ResetHouseRules(_)
            | ShellEffect::ResetPromptOverride(_)
            | ShellEffect::ShowHouseRules(_)
            | ShellEffect::ShowPromptOverride(_)
            | ShellEffect::UpdatePromptMutationStatus(_)
            | ShellEffect::WriteHouseRules(_)
            | ShellEffect::WritePromptOverride(_)) => Self::execute_content_effect(app, effect),
            other => Self::execute_shell_effect(app, other),
        }
    }

    fn execute_control_effect(app: &mut ShellApp, effect: ShellEffect) {
        match effect {
            ShellEffect::AbortForBudget => app.abort_for_budget(),
            ShellEffect::CancelActiveJobs => app.cancel_active_jobs_effect(),
            ShellEffect::ClearConversation => app.clear_conversation(),
            ShellEffect::ContinuePastBudget => app.continue_past_budget(),
            ShellEffect::FinishShellQuit => app.finish_shell_quit_effect(),
            ShellEffect::PauseActiveWork => app.pause_active_work_effect(),
            ShellEffect::RequestExitAbort => app.request_exit_abort_effect(),
            ShellEffect::RequestShellQuit => app.request_shell_quit(),
            ShellEffect::WaitForAbortCleanup => app.wait_for_abort_cleanup_effect(),
            _ => unreachable!("control effect dispatch"),
        }
    }

    fn execute_review_effect(app: &mut ShellApp, effect: ShellEffect) {
        match effect {
            ShellEffect::ApplyReviewedPatch(apply) => app.apply_reviewed_patch_effect(apply),
            ShellEffect::ApplyThreatPatch(apply) => app.apply_threat_patch_effect(apply),
            _ => unreachable!("review effect dispatch"),
        }
    }

    fn execute_auth_effect(app: &mut ShellApp, effect: ShellEffect) {
        match effect {
            ShellEffect::ShowAuthStatus(show) => app.show_auth_status_effect(show),
            _ => unreachable!("auth effect dispatch"),
        }
    }

    fn execute_worker_effect(app: &mut ShellApp, effect: ShellEffect) {
        match effect {
            ShellEffect::DispatchAgent(dispatch) => app.dispatch_agent(dispatch),
            ShellEffect::RefreshDeterministicRecommendations(refresh) => {
                app.refresh_deterministic_recommendations_effect(refresh)
            }
            ShellEffect::StartPlanner(start) => app.dispatch_planner(start),
            ShellEffect::StartScan(request) => app.start_prepared_scan(request),
            ShellEffect::StartThreat(start) => app.dispatch_threat_worker(start),
            _ => unreachable!("worker effect dispatch"),
        }
    }

    fn execute_content_effect(app: &mut ShellApp, effect: ShellEffect) {
        match effect {
            ShellEffect::DiffPromptOverride(diff) => app.diff_prompt_override_effect(diff),
            ShellEffect::EditPromptOverride(edit) => app.edit_prompt_override_effect(edit),
            ShellEffect::ListPromptOverrides(list) => app.list_prompt_overrides_effect(list),
            ShellEffect::RecordPromptMutation(record) => app.record_prompt_mutation_effect(record),
            ShellEffect::RefreshHouseRules(refresh) => app.refresh_house_rules_effect(refresh),
            ShellEffect::ResetHouseRules(reset) => app.reset_house_rules_effect(reset),
            ShellEffect::ResetPromptOverride(reset) => app.reset_prompt_override_effect(reset),
            ShellEffect::ShowHouseRules(show) => app.show_house_rules_effect(show),
            ShellEffect::ShowPromptOverride(show) => app.show_prompt_override_effect(show),
            ShellEffect::UpdatePromptMutationStatus(update) => {
                app.update_prompt_mutation_status_effect(update)
            }
            ShellEffect::WriteHouseRules(write) => app.write_house_rules_effect(write),
            ShellEffect::WritePromptOverride(write) => app.write_prompt_override_effect(write),
            _ => unreachable!("content effect dispatch"),
        }
    }

    fn execute_shell_effect(app: &mut ShellApp, effect: ShellEffect) {
        match effect {
            effect @ (ShellEffect::ShowKnowledgeBase(_)
            | ShellEffect::AttachKnowledgeBaseSource(_)
            | ShellEffect::DetachKnowledgeBaseSource(_)
            | ShellEffect::ReparseKnowledgeBaseSource(_)) => {
                Self::execute_knowledge_base_effect(app, effect)
            }
            ShellEffect::OpenActivity(open) => app.open_activity_effect(open),
            ShellEffect::OpenFilePicker => app.open_file_picker(),
            ShellEffect::LoadDynamicModule(load) => app.load_dynamic_module_effect(load),
            effect @ (ShellEffect::PersistCommandHistory
            | ShellEffect::PersistGlobalModelSelection(_)
            | ShellEffect::PersistPlanningOptionOverride(_)
            | ShellEffect::PersistOptions(_)
            | ShellEffect::RecordAgentRun(_)
            | ShellEffect::RecordScanRun(_)
            | ShellEffect::RecordScanStageTrace(_)
            | ShellEffect::RecordToolRun(_)) => Self::execute_persistence_effect(app, effect),
            ShellEffect::ResumeSession(resume) => app.resume_session_effect(resume),
            other => Self::execute_secondary_shell_effect(app, other),
        }
    }

    fn execute_secondary_shell_effect(app: &mut ShellApp, effect: ShellEffect) {
        match effect {
            effect @ (ShellEffect::RefreshContextView
            | ShellEffect::RefreshFindings(_)
            | ShellEffect::ReportFilteredFindingMovement(_)
            | ShellEffect::FinalizeWorkbenchOpen(_)
            | ShellEffect::FinalizeOpenFinding(_)
            | ShellEffect::FinalizeSastTaskCommand(_)
            | ShellEffect::HydrateSceneSnapshots(_)
            | ShellEffect::FinalizeScanCompletion(_)
            | ShellEffect::RefreshPwnState
            | ShellEffect::RefreshProgramScope
            | ShellEffect::OpenRunArtifact(_)
            | ShellEffect::ShowContextStatus
            | ShellEffect::ShowWorkspaceStatus) => Self::execute_status_effect(app, effect),
            ShellEffect::SetSessionEnv(env) => set_session_env_effect(env),
            ShellEffect::StartOfflineDemoFixtureScan => {
                unreachable!("handled before terminal effects")
            }
            effect @ ShellEffect::WorkspaceExportFindings(_) => {
                Self::execute_workspace_effect(app, effect)
            }
            effect @ ShellEffect::WorkspaceReindex(_) => {
                Self::execute_workspace_effect(app, effect)
            }
            _ => unreachable!("secondary shell effect dispatch"),
        }
    }

    fn execute_workspace_effect(app: &mut ShellApp, effect: ShellEffect) {
        match effect {
            ShellEffect::WorkspaceExportFindings(export) => {
                app.export_workspace_findings_effect(export)
            }
            ShellEffect::WorkspaceReindex(reindex) => app.reindex_workspace_effect(reindex),
            _ => unreachable!("workspace effect dispatch"),
        }
    }

    fn execute_status_effect(app: &mut ShellApp, effect: ShellEffect) {
        match effect {
            ShellEffect::RefreshContextView => {
                let _ = app.refresh_context_view();
            }
            ShellEffect::RefreshFindings(refresh) => match refresh.filter {
                Some(expression) => app.refresh_findings_filtered(&expression),
                None => app.refresh_findings(refresh.announce),
            },
            ShellEffect::ReportFilteredFindingMovement(notice) => {
                app.report_filtered_finding_movement_effect(notice)
            }
            ShellEffect::FinalizeWorkbenchOpen(open) => app.finalize_workbench_open_effect(open),
            ShellEffect::FinalizeOpenFinding(open) => app.finalize_open_finding_effect(open),
            ShellEffect::FinalizeSastTaskCommand(finalize) => {
                app.finalize_sast_task_command_effect(finalize)
            }
            ShellEffect::HydrateSceneSnapshots(hydration) => {
                app.hydrate_persisted_scene_snapshots(hydration.target.as_deref())
            }
            ShellEffect::FinalizeScanCompletion(finalize) => {
                app.finalize_scan_completion_effect(finalize)
            }
            ShellEffect::RefreshPwnState => app.refresh_pwn_state_from_disk(),
            ShellEffect::RefreshProgramScope => app.refresh_program_scope(),
            ShellEffect::OpenRunArtifact(open) => app.open_run_artifact_effect(open),
            ShellEffect::ShowContextStatus => app.show_context_status(),
            ShellEffect::ShowWorkspaceStatus => app.show_workspace_status(),
            _ => unreachable!("status effect dispatch"),
        }
    }

    fn execute_knowledge_base_effect(app: &mut ShellApp, effect: ShellEffect) {
        match effect {
            ShellEffect::ShowKnowledgeBase(show) => app.show_kb(show.module),
            ShellEffect::AttachKnowledgeBaseSource(attach) => app.attach_kb_source(&attach.source),
            ShellEffect::DetachKnowledgeBaseSource(source) => app.detach_kb_source(&source.id),
            ShellEffect::ReparseKnowledgeBaseSource(source) => app.reparse_kb_source(&source.id),
            _ => unreachable!("knowledge-base effect dispatch"),
        }
    }

    fn execute_persistence_effect(app: &mut ShellApp, effect: ShellEffect) {
        match effect {
            ShellEffect::PersistCommandHistory => app.persist_command_history(),
            ShellEffect::RecordAgentRun(record) => app.record_agent_run_effect(record),
            ShellEffect::RecordScanRun(record) => app.record_scan_run_effect(record),
            ShellEffect::RecordScanStageTrace(record) => app.record_scan_stage_trace_effect(record),
            ShellEffect::RecordToolRun(record) => app.record_tool_run_effect(record),
            ShellEffect::PersistGlobalModelSelection(selection) => {
                app.persist_global_model_selection_effect(selection)
            }
            ShellEffect::PersistPlanningOptionOverride(persist) => {
                app.persist_planning_option_override_effect(persist)
            }
            ShellEffect::PersistOptions(scope) => app.persist_option_store(scope),
            _ => unreachable!("persistence effect dispatch"),
        }
    }
}

fn set_session_env_effect(env: SessionEnvVar) {
    unsafe {
        std::env::set_var(env.key, env.value);
    }
}
