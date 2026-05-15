//! Kuzushi UI view-model boundary.
//!
//! View models are the shaped state consumed by renderers. They are intentionally
//! separate from stores, scanners, and runtime dispatch.

use crate::ShellApp;
use std::path::Path;

mod active_stage;
mod activity_dag_rows;
mod activity_empty_state;
mod activity_feed_pause;
mod activity_feed_placeholder;
mod activity_feed_rows;
mod activity_footer;
mod activity_header;
mod activity_layout;
mod activity_pane_chrome;
mod activity_plain_rows;
mod activity_scroll;
mod actor_detail;
mod advisory_chrome;
mod agent_chat;
mod attack_surface;
mod auth;
mod catalog;
mod chrome_layout;
mod config;
mod confirm_card;
mod context_snapshot;
mod context_strip;
mod cost;
mod display_text;
mod failure_handoff;
mod finding_summary;
mod findings;
mod help;
mod home_cockpit;
mod keybindings;
mod knowledge_base;
mod live_activity;
mod module_detail;
mod module_progress;
mod module_run;
mod options;
mod patch_review;
mod plan_card;
mod prereq_prompt;
mod prompt;
mod prompt_tuning;
mod recent_module_activity;
mod recommendation;
mod routing;
mod run_status;
mod run_timeline;
mod run_trace;
mod sast_tasks;
mod session_story;
mod status_footer;
mod threat_dfd;
mod threat_impact;
mod threat_model;
mod threat_navigation;
mod threat_patch;
mod threat_scope;
mod threat_stories;
mod threat_stride;
mod tools;
mod transcript;
mod view_status;
mod workspace;
pub(crate) use active_stage::active_stage_label;
pub(crate) use activity_dag_rows::{activity_dag_pane_rows, ActivityDagRowTone};
pub(crate) use activity_empty_state::activity_empty_state_model;
pub(crate) use activity_feed_pause::activity_feed_pause_model;
pub(crate) use activity_feed_placeholder::activity_feed_placeholder_model;
pub(crate) use activity_feed_rows::{activity_feed_pane_rows, ActivityFeedRowTone};
pub(crate) use activity_footer::{activity_footer_model, ActivityFooterHint};
pub(crate) use activity_header::activity_header_model;
pub(crate) use activity_layout::{activity_frame_layout, activity_plain_pane_widths};
pub(crate) use activity_pane_chrome::{
    activity_pane_chrome_model, activity_plain_pane_header_model, ActivityPaneTitle,
    ActivityPlainPaneHeaderCell,
};
pub(crate) use activity_plain_rows::{
    activity_plain_pane_rows, ActivityPlainDagCell, ActivityPlainFeedCell, ActivityPlainPaneRow,
};
pub(crate) use activity_scroll::{activity_feed_scroll_offset, activity_task_scroll_offset};
pub(crate) use actor_detail::{actor_detail_model, ActorDetailModel, ActorTranscriptRow};
pub(crate) use advisory_chrome::{cost_cap_halt_model, throttle_banner_model, CostCapHaltModel};
pub(crate) use agent_chat::{agent_chat_model, AgentChatModel, AgentChatSession, AgentChatTurn};
pub(crate) use attack_surface::{attack_surface_risk_model, AttackSurfaceRiskModel};
pub(crate) use auth::{
    auth_env_summary, auth_provider_rows, model_auth_status, oauth_summary, AuthProviderRow,
    AuthProviderTone,
};
pub(crate) use catalog::{
    catalog_model, catalog_uses_collapsed_layout, CatalogActionModule, CatalogModel,
    CatalogModuleGroup,
};
pub(crate) use chrome_layout::transcript_chrome_height;
pub(crate) use config::{
    config_model, plain_config_model, ConfigModel, ConfigModelRow, ConfigModelTable,
    ConfigSummaryRow, PlainConfigModel, PlainConfigModelRow,
};
pub(crate) use confirm_card::{confirm_card_model, ConfirmCardModel};
pub(crate) use context_snapshot::{
    context_snapshot_model, plain_context_model, ContextSnapshotDetails, ContextSnapshotModel,
    PlainContextModel,
};
pub(crate) use context_strip::{
    context_strip_model, plain_context_strip_model, ContextStripModel, ContextStripSegment,
    PlainContextStripModel,
};
pub(crate) use cost::{cost_model, CostBudgetRow, CostBudgetStatus, CostModel, CostTone};
pub(crate) use display_text::{compact_target_path, format_session_cost};
pub(crate) use failure_handoff::{failure_handoff_model, FailureHandoffModel};
pub(crate) use finding_summary::{
    findings_count_summary, status_footer_findings_summary, SeverityCounts,
};
pub(crate) use findings::{
    findings_model, selected_finding_detail_model, FindingDetailModel, FindingEvidenceRow,
    FindingListRow, FindingsModel, TriageSummaryModel,
};
pub(crate) use help::{
    help_model, plain_help_model, quickstart_model, HelpCommandRow, PlainHelpCategoryModel,
    PlainHelpModel,
};
pub(crate) use home_cockpit::{home_cockpit_model, HomeArtifactRow, HomeCockpitModel};
pub(crate) use keybindings::footer_keybindings;
pub(crate) use knowledge_base::{
    knowledge_base_model, plain_knowledge_base_model, KnowledgeBaseArtifactRow,
    KnowledgeBaseAttachmentRow, KnowledgeBaseModel, KnowledgeBaseSummaryRow,
    PlainKnowledgeBaseArtifactRow, PlainKnowledgeBaseArtifacts, PlainKnowledgeBaseAttachmentRow,
    PlainKnowledgeBaseAttachments, PlainKnowledgeBaseModel,
};
pub(crate) use live_activity::{plain_live_activity_model, PlainLiveActivityModel};
pub(crate) use module_detail::{
    focused_module_detail_model, module_detail_model, ModuleDetailModel,
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
    options_model, plain_options_model, OptionsBody, OptionsSummaryRow, OptionsTable,
    OptionsTableRow, PlainOptionRow, PlainOptionsBody, PlainOptionsModel, PlainOptionsTable,
};
pub(crate) use patch_review::{patch_review_model, PatchReviewModel, PatchReviewTestRow};
pub(crate) use plan_card::{plan_card_model, PlanCardModel, PlanChangeRow};
pub(crate) use prereq_prompt::{
    plain_prereq_plan_model, prereq_prompt_model, PlainPrereqPlanModel, PrereqPromptModel,
    PrereqPromptStepModel,
};
pub(crate) use prompt::{prompt_model, prompt_text};
pub(crate) use prompt_tuning::{
    prompts_model, tune_model, PromptRow, TuneActionRow, TuneHouseRules, TuneModel,
};
pub(crate) use recent_module_activity::{
    recent_module_activity_model, ModuleActivityKind, ModuleActivityModel, ModuleActivityRow,
    ModuleActivityTone,
};
pub(crate) use recommendation::{recommendation_model, RecommendationModel, RecommendationRow};
pub(crate) use routing::{
    plain_render_mode, routing_mode, routing_mode_segment, uses_activity_frame, PlainRenderMode,
    RoutingMode,
};
pub(crate) use run_status::scan_status;
pub(crate) use run_timeline::{run_timeline_model, PastRunStatus, RunTimelineRow};
pub(crate) use run_trace::{
    alias_reference_model, replay_model, trace_model, ReplayModel, RunArtifactDetail, TraceModel,
    TraceStep,
};
pub(crate) use sast_tasks::{
    plain_sast_tasks_model, sast_tasks_model, PlainSastTaskRow, PlainSastTasksModel, SastTasksModel,
};
pub(crate) use session_story::{
    session_history_model, session_story_model, CommandHistoryModel, SessionStoryModel,
};
pub(crate) use status_footer::status_footer_model;
pub(crate) use threat_dfd::threat_dfd_model;
#[cfg(test)]
pub(crate) use threat_dfd::threat_dfd_model_from_doc;
pub(crate) use threat_model::{threat_model_doc, threat_summary_review, ThreatSummaryReview};
pub(crate) use threat_navigation::{threat_nav_model, threat_panel_model, ThreatPanel};
pub(crate) use threat_patch::threat_patch_card_model;
#[cfg(test)]
pub(crate) use threat_scope::threat_scope_buckets_from_doc;
pub(crate) use threat_scope::{threat_scope_buckets, ThreatScopeBucket, ThreatScopeTone};
#[cfg(test)]
pub(crate) use threat_stories::threat_story_model_from_doc;
pub(crate) use threat_stories::{threat_story_model, ThreatStoryTone};
#[cfg(test)]
pub(crate) use threat_stride::threat_stride_rollup_from_doc;
pub(crate) use threat_stride::{threat_stride_rollup, ThreatStrideRow, ThreatStrideTone};
pub(crate) use tools::{tools_model, ToolRow};
pub(crate) use transcript::{
    plain_command_result_model, transcript_model, PlainCommandResultModel,
};
pub(crate) use view_status::view_status_segment;
pub(crate) use workspace::{
    plain_workspace_model, workspace_model, PlainWorkspaceModel, WorkspaceModel, WorkspaceRollupRow,
};

pub use crate::{
    ActivitySession, OptionsFilter, OptionsView, PaneFocus, ReconSnapshot, ScanPanelState,
    ShellView, ThreatView,
};

pub(super) fn read_latest_run_id(root: &Path) -> Option<String> {
    std::fs::read_to_string(root.join(".kuzushi/latest"))
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}
