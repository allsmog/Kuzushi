//! Kuzushi UI view-model boundary.
//!
//! View models are the shaped state consumed by renderers. They are intentionally
//! separate from stores, scanners, and runtime dispatch.

use crate::ShellApp;
use std::path::{Path, PathBuf};

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
    AuthProviderState,
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
pub(crate) use cost::{cost_model, CostBudgetRow, CostBudgetStatus, CostModel};
pub(crate) use display_text::{compact_target_path, format_session_cost};
pub(crate) use failure_handoff::failure_handoff_context;
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
    options_model, plain_options_model, OptionRow, OptionsModelStatus, OptionsSummaryRow,
    PlainOptionRow, PlainOptionsBody, PlainOptionsModel, PlainOptionsTable,
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
    recent_module_activity_model, ModuleActivityModel, ModuleActivityRow,
};
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
pub(crate) use threat_dfd::threat_dfd_nodes;
#[cfg(test)]
pub(crate) use threat_dfd::threat_dfd_nodes_from_doc;
pub(crate) use threat_model::{threat_model_doc, threat_summary_review, ThreatSummaryReview};
pub(crate) use threat_navigation::{threat_nav_model, threat_panel_model, ThreatPanel};
pub(crate) use threat_patch::threat_patch_card_model;
pub(crate) use threat_scope::threat_scope_buckets;
#[cfg(test)]
pub(crate) use threat_scope::threat_scope_buckets_from_doc;
pub(crate) use threat_stories::threat_story_rows;
#[cfg(test)]
pub(crate) use threat_stories::threat_story_rows_from_doc;
pub(crate) use threat_stride::threat_stride_rollup;
#[cfg(test)]
pub(crate) use threat_stride::threat_stride_rollup_from_doc;
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

#[derive(Debug, Clone, PartialEq)]
pub struct RecommendationModel {
    pub source_path: String,
    pub source_detail: String,
    pub run_id: Option<String>,
    pub attack_surface: Option<AttackSurfaceRiskModel>,
    pub summary: Option<String>,
    pub recommendations: Vec<RecommendationRow>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecommendationRow {
    pub tool: String,
    pub priority: Option<String>,
    pub reason: String,
    pub requires_runtime: bool,
}

pub fn recommendation_model(app: &ShellApp) -> RecommendationModel {
    let source = RecommendationSource::from_app(app);
    let source_path = source.path.display().to_string();
    let report = read_recommendations(&source.path);
    RecommendationModel {
        source_detail: artifact_detail_label(&source.path),
        source_path,
        run_id: source.run_id,
        attack_surface: source.path.parent().and_then(attack_surface_risk_model),
        summary: report.as_ref().and_then(|view| view.summary.clone()),
        recommendations: report.map(|view| view.recommendations).unwrap_or_default(),
    }
}

fn artifact_detail_label(path: &Path) -> String {
    let display = path.display().to_string();
    if path.exists() {
        display
    } else {
        format!("{display} (missing)")
    }
}

pub(super) fn read_latest_run_id(root: &Path) -> Option<String> {
    std::fs::read_to_string(root.join(".kuzushi/latest"))
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
}

fn read_recommendations(path: &Path) -> Option<RecommendationView> {
    let text = std::fs::read_to_string(path).ok()?;
    let value = serde_json::from_str::<serde_json::Value>(&text).ok()?;
    Some(RecommendationView {
        summary: string_field(&value, "summary"),
        recommendations: recommendation_values(&value)
            .into_iter()
            .filter_map(recommendation_from_value)
            .collect(),
    })
}

fn recommendation_values(value: &serde_json::Value) -> Vec<serde_json::Value> {
    if let Some(items) = value.as_array() {
        return items.clone();
    }
    value
        .get("recommendations")
        .or_else(|| value.pointer("/data/recommendations"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn recommendation_from_value(value: serde_json::Value) -> Option<RecommendationRow> {
    Some(RecommendationRow {
        tool: string_field(&value, "tool")?,
        priority: string_field(&value, "priority"),
        reason: string_field(&value, "reason").unwrap_or_else(|| "No reason recorded.".to_string()),
        requires_runtime: value
            .get("requiresRuntime")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    })
}

fn string_field(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

struct RecommendationSource {
    run_id: Option<String>,
    path: PathBuf,
}

impl RecommendationSource {
    fn from_app(app: &ShellApp) -> Self {
        let root = app.target.as_deref().unwrap_or_else(|| Path::new("."));
        let run_id = read_latest_run_id(root);
        let run_dir = run_id
            .as_ref()
            .map(|id| root.join(".kuzushi").join("runs").join(id))
            .unwrap_or_else(|| root.join(".kuzushi/runs/latest"));
        Self {
            run_id,
            path: run_dir.join("recommendations.json"),
        }
    }
}

struct RecommendationView {
    summary: Option<String>,
    recommendations: Vec<RecommendationRow>,
}
