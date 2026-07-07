use super::*;
pub(crate) use super::*;

pub(crate) use agent_chat::*;
pub(crate) use agent_session::*;
pub(crate) use approval::*;
pub(crate) use artifacts::*;
pub(crate) use background_events::*;
pub(crate) use catalog::*;
pub(crate) use command_router::*;
pub(crate) use ctrl_c_arm_window::*;
pub(crate) use domain_cache::*;
pub(crate) use editor_state::*;
pub(crate) use effect_runtime::*;
pub(crate) use effects::*;
pub(crate) use file_picker::*;
pub(crate) use findings::*;
pub(crate) use jobs::*;
pub(crate) use line_editor::*;
pub(crate) use live_activity::*;
pub(crate) use log::*;
pub(crate) use options::*;
pub(crate) use plan::*;
pub(crate) use prereq_chain::*;
pub(crate) use prompts::*;
pub(crate) use pwn::*;
pub(crate) use runtime::*;
pub(crate) use runtime_state::*;
pub(crate) use sast_tasks::*;
pub(crate) use scan::*;
pub(crate) use scan_state::ScanState;
pub(crate) use services::*;
pub(crate) use session::*;
pub(crate) use session_state::*;
pub(crate) use settings::*;
pub(crate) use shell_lifecycle::{auth_ready_for_provider, *};
pub(crate) use shellapp::*;
pub(crate) use strategy::*;
pub(crate) use threats::*;
pub(crate) use tool_run_state::*;
pub(crate) use tool_runner::*;
pub(crate) use ui_prefs::*;
pub(crate) use update::*;
pub use view_state::*;
pub(crate) use with_next_step::*;
pub(crate) use workers::*;
pub(crate) use workspace_context::*;
mod agent_chat;
mod agent_chat_state;
mod agent_session;
mod approval;
mod artifacts;
mod background_events;
mod catalog;
mod command_palette;
mod command_router;
mod editor_state;
mod effect_runtime;
mod effects;
mod file_picker;
mod findings;
mod jobs;
mod line_editor;
mod live_activity;
mod log;
mod options;
mod plan;
mod prereq_chain;
mod pwn;
#[cfg(test)]
use self::runtime::{mouse_capture_setting_enabled, render_plain_scripted_session};
use self::settings::{preferred_model_choice_index, thinking_level_from_input};
use self::workers::{
    merge_json, planner_worker, threat_ask_worker, threat_regen_worker, AgentEvent, PlanEvent,
    ScanEvent, ThreatPatchEvent, ToolEvent,
};
use self::workers::{parse_plan_json, parse_threat_patch_json};
use self::workspace_context::{default_context_snapshot_view, default_workspace_view};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::modules::ModuleKind;
use kuzushi_core::{
    AgenticSastReport, CarliniThreatHuntReport, Finding, ModuleRegistry, RunTraceStep,
    ScanCancellation, ScanProgress, ToolOptionStore, V2Config, WorkspaceTarget,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
mod onboarding;
mod prompts;
mod reducers;
mod runtime;
mod runtime_state;
mod sast_tasks;
mod scan;
mod scan_state;
mod services;
mod session;
mod session_state;
mod settings;
mod state;
pub(crate) mod state_transitions;
mod strategy;
mod task_durations;
mod threats;
mod tool_run_state;
mod tool_runner;
mod ui_prefs;
mod update;
mod view_state;
mod workers;
mod workspace_context;

mod ctrl_c_arm_window;
mod domain_cache;
mod shell_lifecycle;
mod shellapp;
#[cfg(test)]
mod tests;
mod with_next_step;
pub use agent_chat::AgentChatView;
pub use agent_chat::ChatTurn;
pub(crate) use agent_chat_state::AgentChatState;
pub use approval::{ConfirmKind, PendingConfirm, PendingPatch};
pub use live_activity::{LiveActivity, LiveActivityPhase};
pub use log::LogLine;
pub(crate) use log::{LogState, LOG_LINE_CAPACITY};
pub(crate) use onboarding::PlanningRunStep;
pub use onboarding::{
    applicable_tasks_for_phase, artifact_state as planning_artifact_state, auth_method_row_kinds,
    auth_method_rows, build_execution_plan, cli_is_on_path, direct_dependencies, direct_dependents,
    discover_target_candidates, initial_onboarding_phase, initial_onboarding_phase_for,
    model_recommended_in_phase, provider_has_multiple_auth_methods, recommended_tasks_for_phase,
    record_recent_target, AuthMethodRow, AuthMethodRowKind,
    row_disposition, skip_onboarding_env, toggle_planning_row, topological_order,
    transitive_dependencies, ArtifactState as PlanningArtifactState, FailedPlanningTask,
    InitialOnboardingPhase, OnboardingInputs, PendingRetry, PickerFocus, PlanningOptionEdit,
    PlanningOptionOverrides, PlanningTaskId, PlanningTaskRow, RetryAdjustment, RowDisposition,
    TargetCandidate, TargetCandidateScope, TargetProfile, ToggleOutcome, WorkflowPhase,
};
pub use prereq_chain::{
    PendingPrereqPrompt, PrereqArtifactState, PrereqChain, PrereqPlanAction, PrereqPlanStep,
    PrereqStep,
};
pub use runtime::{run_shell, run_shell_with_plain};
pub(crate) use settings::{
    api_key_model_choice_for_provider, bridge_command_status, display_model_selector,
    model_choices, oauth_model_choice_for_provider, oauth_provider_status, runtime_backend_label,
    validate_shell_model_id, ModelChoice,
};
pub use shellapp::ShellApp;
pub(crate) use task_durations::compact_secs;
pub use task_durations::TaskDurationStore;
pub use view_state::{
    ActivityRouteState, ActivitySession, ActorDetailFilter, AdvisoryState, AuthLoginView,
    AuthScreenFooter, AuthScreenSnapshot, AuthScreenStatus, BudgetHalt, CommandPaletteFooter,
    CommandPaletteSnapshot, CommandPaletteStatus, CompletionCycle, ConfigScreenFooter,
    ConfigScreenSnapshot, ConfigScreenStatus, ContextScreenFooter, ContextScreenSnapshot,
    ContextScreenStatus, ContextSnapshotView, CostScreenFooter, CostScreenSnapshot,
    CostScreenStatus, DagTaskDetail, DagTaskDetailState, DagTaskRow, DagTaskState, ExploitChain,
    HelpScreenFooter, HelpScreenSnapshot, HelpScreenStatus, HistorySearch, InputMode,
    InterruptionView, KnowledgeBaseView, Notice, NoticeSeverity, OptionsFilter,
    OptionsScreenFooter, OptionsScreenSnapshot, OptionsScreenStatus, OptionsView, PaneFocus,
    PlanChange, PlanProposal, PromptsAction, PwnView, ReconSnapshot, RecordedTraceEvent,
    SastTasksFooter, SastTasksSnapshot, SastTasksStatus, ScanPanelState, ShellView,
    SubsystemAggregate, ThreatPatch, ThreatView, ThrottleAdvisory, TuneAction, WorkbenchPage,
    WorkbenchPane, WorkbenchPaneScroll, WorkspaceView,
};
pub use view_state::{
    BoundedScroll, DrawerTab, FindingPane, NavBounds, NavEffect, WorkbenchDepth, WorkbenchNav,
};
pub(crate) use view_state::{PlanningPickerRouteState, SastTaskMode, SastTaskRow};
