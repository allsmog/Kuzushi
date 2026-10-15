//! Kuzushi UI view-model boundary.
//!
//! View models are the shaped state consumed by renderers. They are intentionally
//! separate from stores, scanners, and runtime dispatch.

use crate::ShellApp;
mod answers;
pub(crate) mod goal_review;
pub(crate) mod source_review;
pub(crate) use answers::*;

mod active_stage;
mod allowance_review;
pub(crate) mod context_generation;
pub(crate) mod context_goal;
mod context_matrix;
pub(crate) mod review_study;
pub(crate) mod scope_review;
pub(crate) mod study_config;
pub(crate) use context_matrix::{
    case_name_notice, case_name_plain_lines, context_matrix_conditions, context_matrix_lines,
};
pub(crate) use context_matrix::{matrix_result_lines, matrix_result_state};
pub(crate) mod scope_context;
pub(crate) mod study_context;
pub(crate) mod study_engines;
pub(crate) use allowance_review::{
    allowance_review_model, allowance_review_width, allowance_work_summary, AllowanceReviewModel,
    AllowanceWorkSummary,
};
mod activity_dag_rows;
mod activity_empty_state;
mod activity_feed_pause;
mod activity_feed_placeholder;
mod activity_feed_rows;
mod activity_footer;
mod activity_header;
mod activity_layout;
mod activity_observability;
mod activity_pane_chrome;
mod activity_scroll;
mod activity_view;
mod actor_detail;
mod advisory_chrome;
mod ambient_progress;
mod attack_surface;
mod auth;
mod boot_splash;
mod campaign_job;
mod catalog;
pub(crate) mod study_resource_picker;
pub(crate) use campaign_job::{
    campaign_job_cost_label, campaign_job_detail_lines, campaign_job_scope_label,
};
mod chrome_layout;
mod command_palette;
mod config;
mod confirm_card;
mod confirm_dialog;
pub(crate) mod context_edit;
pub(crate) mod context_history;
mod context_snapshot;
mod context_strip;
mod cost;
mod display_text;
mod failure_handoff;
pub(crate) mod finding_review_source;
mod finding_search;
mod finding_source_history;
mod finding_summary;
mod findings;
mod health;
mod help;
mod home_cockpit;
mod jobs_registry;
mod journey;
mod report_investigation;
mod report_summary;
pub(crate) use report_investigation::{report_investigation_lines, report_source_notice};
pub(crate) use report_summary::{
    report_cost_coverage, report_export_campaign, report_investigation_state,
    report_review_summary, report_source_history_coverage,
};
mod keybindings;
mod keymap;
mod knowledge_base;
mod live_activity;
mod model_failure;
mod module_detail;
mod module_progress;
mod module_run;
pub(crate) use model_failure::model_failure_text;
mod options;
mod patch_review;
mod permission_policy;
mod phase_cockpit;
mod plan_card;
mod planning_overview;
mod prereq_prompt;
mod project_model;
mod prompt;
mod prompt_tuning;
mod pwn;
mod quit_confirm;
mod rail;
mod recent_module_activity;
mod recommendation;
mod report_preview;
mod retry_card;
pub(crate) mod review_conflicts;
mod review_queue;
mod review_state;
mod review_yield;
mod routing;
mod run_diff;
mod run_paths;
mod run_status;
mod run_timeline;
mod run_trace;
mod sast_tasks;
mod screen_context;
mod session_story;
mod setup;
mod severity_tone;
mod status_footer;
mod strategy_queue;
mod target_facts;
mod terminal_title;
mod theme_picker;
mod threat_dfd_diagram;
mod threat_impact;
mod threat_model;
mod threat_navigation;
mod threat_patch;
mod threat_scope;
mod threat_stories;
mod threat_stride;
mod tools;
mod transcript;
mod update_available;
mod view_status;
mod viz_data;
mod workbench;
mod workspace;
pub(crate) use active_stage::active_stage_label;
pub(crate) use activity_dag_rows::ActivityDagRowTone;
pub(crate) use activity_empty_state::ActivityEmptyStateModel;
pub(crate) use activity_feed_rows::ActivityFeedRowTone;
pub(crate) use activity_footer::ActivityFooterHint;
pub(crate) use activity_header::ActivityHeaderModel;
pub(crate) use activity_layout::{
    activity_frame_layout, activity_pane_layout, ActivityFrameLayout, ActivityPaneLayout,
};
pub(crate) use activity_observability::{ActivityHeartbeatModel, ActivityHeartbeatTone};
pub(crate) use activity_pane_chrome::{ActivityPaneChromeModel, ActivityPaneTitle};
pub(crate) use activity_view::{
    activity_execution_model_label, activity_view_model, run_focus_is_terminal, ActivityViewModel,
    OperatorQuestionKeyHints, RunFocusModel,
};
pub(crate) use actor_detail::{actor_detail_model, ActorDetailModel, ActorTranscriptRow};
pub(crate) use advisory_chrome::{
    cost_cap_halt_model, notice_banner_model, throttle_banner_model, CostCapHaltModel,
    NoticeBannerModel,
};
pub(crate) use ambient_progress::ambient_progress_chip;
pub(crate) use attack_surface::{
    attack_surface_risk_model, AttackSurfaceRiskModel, AttackSurfaceRow,
};
pub(crate) use auth::{
    auth_env_summary, auth_login_model, auth_provider_rows, model_auth_status, oauth_model_status,
    oauth_summary, AuthLoginModel, AuthProviderRow, AuthProviderTone,
};
pub(crate) use boot_splash::{boot_splash_model, BootSplashModel};
pub(crate) use catalog::{
    catalog_model, catalog_selected_action_hint, catalog_uses_collapsed_layout, CatalogModel,
    CatalogModuleGroup,
};
pub(crate) use chrome_layout::{
    compact_document_notice, compact_map_reading, compact_phase_reading, compact_review_reading,
    keybind_footer_chrome_height, rail_width, status_footer_chrome_height,
    transcript_chrome_height, RAIL_AUTO_MIN_WIDTH, RAIL_FORCE_MIN_WIDTH, RAIL_WIDTH,
};
pub(crate) use command_palette::{command_palette_model, CommandPaletteModel, PaletteRow};
pub(crate) use config::{
    config_model, plain_config_model, ConfigModel, ConfigModelRow, ConfigModelTable,
    ConfigSummaryRow, PlainConfigModel, PlainConfigModelRow,
};
pub(crate) use confirm_card::{confirm_card_model, ConfirmCardModel};
pub(crate) use confirm_dialog::{confirm_dialog_model, ConfirmDialogModel};
pub(crate) use context_snapshot::{
    context_snapshot_model, context_snapshot_relative_path, context_snapshot_state,
    plain_context_model, ContextSnapshotDetails, ContextSnapshotModel, ContextSnapshotRunning,
    PlainContextModel,
};
pub(crate) use context_strip::{context_strip_model, ContextStripModel, ContextStripSegment};
pub(crate) use cost::{cost_model, CostBudgetRow, CostBudgetStatus, CostModel, CostTone};
pub(crate) use display_text::{
    active_project_scope_label, compact_target_path, format_runtime_cost, format_session_cost,
    recorded_timestamp_label, scoped_target_path_label, workspace_artifact_path_label,
};
pub(crate) use failure_handoff::{failure_handoff_model, FailureHandoffModel};
pub(crate) use finding_search::{finding_facet_values, FindingSearch};
pub(crate) use finding_summary::{
    ci_result_findings_summary, compact_status_footer_findings_summary_from_counts,
    compact_status_footer_findings_summary_with_total, findings_count_summary_with_total,
    status_footer_findings_summary, status_footer_findings_summary_from_counts,
    status_footer_findings_summary_with_total, FindingsNarrowing, SeverityCounts,
};
#[cfg(test)]
pub(crate) use findings::projected_visible_finding_pairs;
pub(crate) use findings::{
    baseline_sorted_finding_alias_indices, current_finding_for_detail,
    finding_detail_model_for_projection, findings_model, review_backlog_active,
    selected_finding_detail_model, selected_finding_out_of_window_notice,
    visible_finding_at_cursor, visible_finding_at_index, visible_finding_position_for,
    visible_findings_cache_key, visible_findings_len, visible_sorted_finding_alias_indices,
    CleanScanEmptyState, DecisionHistoryRow, FilteredFindingsEmptyState, FindingDetailModel,
    FindingEvidenceRow, FindingListRow, FindingsEmptyState, FindingsModel, ProofTier,
    SourceSnippetModel, TriageSummaryModel, SNIPPET_CONTEXT_AFTER, SNIPPET_CONTEXT_BEFORE,
};
pub(crate) use health::{
    health_display_model, health_model, HealthDisplayModel, HealthModel, HealthRow, HealthTone,
};
pub(crate) use help::{
    help_model, plain_help_model, quickstart_model, HelpCommandRow, PlainHelpCategoryModel,
    PlainHelpModel, QuickstartStep,
};
pub(crate) use home_cockpit::{
    attack_surface_artifact_state, attack_surface_artifact_version, attack_surface_model,
    home_cockpit_model, AttackSurfaceArtifactState, HomeArtifactRow, HomeCockpitModel,
    HomeFindingsCard, HomeNextCard, HomeRunArtifactChip, HomeRunCard, HomeTopRiskRow,
};
pub(crate) use jobs_registry::{
    jobs_registry_model, JobHistoryState, JobRow, JobRunStatus, JobSource, JobsRegistryModel,
};
pub(crate) use journey::{
    attach_proof_deferral_counts, attach_remediation_counts, autonomy_footer_segment,
    finding_ledger_counts, journey_destination_after_selection, journey_footer_segment,
    journey_model, journey_phase_segment, journey_reality_projection, phase_verb_opens_page,
    CheckpointDrift, JourneyDestination, JourneyModel, JourneyPhaseAccess, JourneyPhaseState,
    JourneyPhaseStatus, JourneyPhaseTone, JourneyRealityProjection, ReportReason,
};
pub(crate) use keybindings::{footer_keybindings, review_queue_navigation_footer};
pub(crate) use keymap::{keymap_model, KeymapModel};
pub(crate) use knowledge_base::{
    knowledge_base_model, plain_knowledge_base_model, KnowledgeBaseArtifactRow,
    KnowledgeBaseAttachmentRow, KnowledgeBaseModel, KnowledgeBaseSummaryRow,
    PlainKnowledgeBaseArtifactRow, PlainKnowledgeBaseArtifacts, PlainKnowledgeBaseAttachmentRow,
    PlainKnowledgeBaseAttachments, PlainKnowledgeBaseModel,
};
pub(crate) use live_activity::{
    plain_live_activity_model, plain_run_projection_model, PlainLiveActivityModel,
    PlainRunProjectionModel,
};
pub(crate) use module_detail::{
    focused_module_detail_model, module_detail_model, ModuleDetailModel, ModuleKeyValueSection,
};
pub(crate) use module_progress::{
    module_progress_model, ModuleProgressKind, ModuleProgressModel, ModuleProgressRow,
    ModuleProgressSection,
};
pub(crate) use module_run::{
    module_run_live_activity, module_run_summary, ModuleRunLiveActivity, ModuleRunStatusKind,
    ModuleRunSummary,
};
pub(crate) use options::{
    option_display_name, options_model, plain_options_model, OptionsBody, OptionsModel,
    OptionsSummaryRow, OptionsTable, OptionsTableRow, PlainOptionRow, PlainOptionsBody,
    PlainOptionsModel, PlainOptionsTable,
};
pub(crate) use patch_review::{patch_review_model, PatchReviewModel, PatchReviewTestRow};
pub(crate) use permission_policy::{
    permission_policy_model, PermissionPolicyModel, PermissionPolicyRow,
};
pub(crate) use phase_cockpit::investigation_verify_command;
#[cfg(test)]
pub(crate) use phase_cockpit::phase_cockpit_model;
pub(crate) use phase_cockpit::{
    map_context_fit, map_gallery_is_canvas, phase_cockpit_model_for_phase, phase_presentation_plan,
    phase_surface_specs, ready_map_gallery_is_primary, AttentionMode, ChainArtifactsModel,
    ChainCandidateModel, ChainLinkModel, Composition, DrawerSize, DrawerSpec,
    EngagementHeaderModel, FixPhaseModel, InvestigationPlanModel, LayoutDensity, LiveScanModel,
    MapPhaseModel, NextScanRow, NextScansState, PhaseCockpitBody, PhaseCockpitModel,
    PhasePresentationPlan, PhaseResultCardModel, PhaseSurfaceId, PlannedPhaseSurface,
    ProofReplayModel, ProvePhaseModel, RemediationLifecycleModel, RemediationLifecycleStage,
    RemediationLoadState, ReviewPhaseModel, ScanAttemptModel, ScanEngineOutcomeModel,
    ScanPhaseModel, SelectionDisclosureModel, SurfaceInteraction, SurfaceRole, SurfaceState,
    TraceEvidenceModel, TraceHopModel,
};
pub(crate) use plan_card::{plan_card_model, PlanCardModel, PlanChangeRow};
pub(crate) use planning_overview::{
    enter_plan, format_relative_age, latest_cached_modified, row_outcome, workspace_history,
    EnterPlan, PriorState, RowOutcome, WorkspaceHistory,
};
pub(crate) use prereq_prompt::{
    plain_prereq_plan_model, prereq_prompt_model, PlainPrereqPlanModel, PrereqPromptModel,
    PrereqPromptStepModel,
};
pub(crate) use project_model::{
    project_context_columns, project_model, project_revision_label, ProjectContextCell,
    ProjectContextRow, ProjectContextSegment, ProjectContextTable, ProjectModel,
    ProjectModelOrigin, ProjectModelRow, CONTEXT_COLUMN_RULE,
};
pub(crate) use prompt::{
    navigation_prompt_label, prompt_model, prompt_text, workbench_prompt_mode,
    workbench_prompt_token,
};
pub(crate) use prompt_tuning::{
    prompts_model, tune_model, PromptRow, PromptStackLayer, PromptStackModel, TuneActionRow,
    TuneHouseRules, TuneModel,
};
pub(crate) use pwn::{
    pwn_dashboard_model, PwnDashboardModel, PwnPrimitiveRow, PwnReverseObservationRow, PwnRoundRow,
};
pub(crate) use quit_confirm::{has_volatile_session_state, quit_confirm_model, QuitConfirmModel};
pub(crate) use rail::{rail_sections, RailSection};
pub(crate) use recent_module_activity::{
    recent_module_activity_model, ModuleActivityKind, ModuleActivityModel, ModuleActivityRow,
    ModuleActivityTone,
};
pub(crate) use recommendation::{
    recommendation_artifact_needs_refresh, recommendation_components, recommendation_model,
    recommendation_run_id, ComponentRecommendationRow, RecommendationModel, RecommendationRow,
    NO_REASON_RECORDED,
};
pub(crate) use report_preview::{
    report_preview_model, ReportPreviewCounts, ReportPreviewModel, ReportPreviewRow,
};
pub(crate) use retry_card::{retry_card_model, RetryCardModel, RetryCardRow};
pub(crate) use review_queue::{
    review_queue_model, ReviewFacetCount, ReviewFacetGroup, ReviewOccurrence, ReviewQueueMode,
    ReviewQueueModel, ReviewQueueRow, ReviewWorkflowGroup, LEARN_ORDERING_INDICATOR,
};
pub(crate) use review_yield::{
    review_yield_detail_for, ReviewYieldDetailModel, ReviewYieldSignalViewModel,
    REVIEW_YIELD_ADVISORY_LINE_1, REVIEW_YIELD_ADVISORY_LINE_2, REVIEW_YIELD_LEARN_CONTEXT,
};
pub(crate) use routing::{
    has_run_activity, plain_render_mode, routing_mode, routing_mode_segment, uses_activity_frame,
    uses_scene_frame, uses_workbench_frame, PlainInteractiveOnlyModel, PlainRenderMode,
    RoutingMode,
};
pub(crate) use run_diff::{
    run_diff_model, RunDiffChangedRow, RunDiffDecisionSummary, RunDiffFindingRow,
    RunDiffFindingState, RunDiffModel, RunDiffUncertainMatchRow,
};
#[cfg(test)]
pub(crate) use run_paths::ui_latest_run_path;
pub(crate) use run_paths::{
    ui_latest_run_relative_path, ui_run_artifact_relative_path, ui_run_dir, ui_runs_root,
    ui_runs_root_relative_path,
};
pub(crate) use run_status::scan_status;
pub(crate) use run_timeline::{run_timeline_model, PastRunStatus, RunTimelineRow};
pub(crate) use run_trace::{
    alias_reference_model, replay_can_lead_with_results, replay_model, replay_reading_rows,
    trace_model, ReplayIssueModel, ReplayModel, RunArtifactDetail, TraceModel, TraceStep,
};
pub(crate) use sast_tasks::{
    plain_sast_tasks_model, sast_tasks_model, PlainSastTaskRow, PlainSastTasksModel, SastTasksModel,
};
#[cfg(test)]
pub(crate) use screen_context::threat_model_scene_context;
pub(crate) use screen_context::{
    capture_threat_model_scene_snapshot, screen_context_model,
    threat_model_scene_context_from_snapshot, ScreenContext, ThreatModelSceneContext,
    ThreatModelSceneSnapshot,
};
pub(crate) use session_story::{
    session_history_model, session_story_model, CommandHistoryModel, SessionStoryModel,
};
pub(crate) use setup::{
    configured_model_credential_readiness, credential_readiness_for_provider,
    setup_readiness_model, CredentialReadiness, SetupReadinessModel, SetupReadinessRow,
    SetupReadinessTone,
};
pub(crate) use severity_tone::SeverityTone;
pub(crate) use status_footer::status_footer_model;
pub(crate) use strategy_queue::{
    strategy_queue_model, StrategyQueueDetailRow, StrategyQueueEmptyState, StrategyQueueModel,
    StrategyQueueRow,
};
pub(crate) use target_facts::target_fact_detail_lines;
pub(crate) use terminal_title::terminal_title;
pub(crate) use theme_picker::{theme_picker_model, ThemePickerModel};
pub(crate) use threat_model::{
    map_context_run_refs, threat_model_absence_hint, threat_model_doc, threat_model_relative_path,
    threat_summary_review, ThreatSummaryReview,
};
pub(crate) use threat_model::{
    threat_model_freshness, threat_model_picker, ThreatModelFreshnessModel, ThreatModelHeadRow,
    ThreatModelPickerModel,
};
pub(crate) use threat_navigation::{threat_nav_model, threat_panel_model, ThreatPanel};
pub(crate) use threat_patch::{threat_patch_card_model, ThreatPatchCardModel};
#[cfg(test)]
pub(crate) use threat_scope::threat_scope_model_from_doc;
pub(crate) use threat_scope::{threat_scope_model, ThreatScopeBucket, ThreatScopeTone};
#[cfg(test)]
pub(crate) use threat_stories::threat_story_model_from_doc;
pub(crate) use threat_stories::{threat_story_model, ThreatStoryTone};
#[cfg(test)]
pub(crate) use threat_stride::threat_stride_rollup_from_doc;
pub(crate) use threat_stride::{
    threat_stride_rollup, ThreatStrideMember, ThreatStrideRow, ThreatStrideTone,
};
pub(crate) use tools::{tools_model, ToolGroup, ToolRow, ToolsModel};
pub(crate) use transcript::{
    logs_model, plain_command_result_model, transcript_model, transcript_model_from_log_index,
    LogsModel, PlainCommandResultModel,
};
pub(crate) use update_available::{update_available_model, UpdateAvailableModel};
pub(crate) use view_status::view_status_segment;
#[cfg(test)]
pub(crate) use viz_data::selected_taint_flow_path;
pub(crate) use viz_data::{
    attack_tree, cached_findings_heatmap, cached_findings_heatmap_with_selection,
    cached_risk_by_module, component_stack, dfd_model, dfd_model_is_empty, dfd_overview,
    dfd_overview_component_at, dfd_overview_component_count, dfd_security_items_for_selection,
    dfd_selectable_count, dfd_selected_item, dfd_selection_for_key, display_target,
    entry_point_breakdown, risk_by_module, taint_flow_path, taint_flow_path_for_finding,
    worklist_artifact_version, worklist_model, AttackChain, AttackTree, ComponentItem,
    ComponentScope, ComponentSource, ComponentSourceKind, ComponentStack, DfdBoundaryModel,
    DfdContextCounts, DfdFlowModel, DfdKind, DfdLinkState, DfdModel, DfdNodeModel, DfdOverview,
    DfdOverviewComponent, DfdOverviewFlow, DfdOverviewZone, DfdSecurityItem, DfdSecurityKind,
    DfdSelected, DfdZoneFlow, EntryPointArtifactStatus, EntryPointBreakdown, EntryPointComposition,
    EntryPointCounts, EntryPointDisposition, EntryPointFreshness, EntryPointGroup, EntryPointItem,
    EntryPointReceipt, EntryPointTarget, FindingsHeatmap, LegendEntry, ModuleRisk, RiskByModule,
    TaintFlowPath, TaintStageModel, WorklistRowModel, WorklistViewModel,
};
pub(crate) use workbench::{
    active_review_queue_mode, active_workbench_page, active_workbench_page_with_reality_phase,
    work_liveness, workbench_presentation_snapshot, workbench_report_command,
    workbench_reverify_control_hint, WorkLiveness, WorkbenchChromeModel, WorkbenchHint,
    WorkbenchPresentationSnapshot, WorkbenchState, WorkbenchTopBar, WORKBENCH_REPORT_COMMAND,
};
pub(crate) use workspace::{
    findings_db_relative_path, plain_workspace_projection, workspace_model,
    PlainWorkspaceProjection, WorkspaceModel, WorkspaceRollupRow,
};

pub use crate::{
    ActivityRouteState, ActivitySession, OptionsFilter, OptionsView, PaneFocus, ReconSnapshot,
    ScanPanelState, ShellView, ThreatView,
};
