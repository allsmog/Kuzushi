use super::*;
pub(crate) use super::*;

pub(crate) use abort_reason::*;
pub(crate) use agent_chat::*;
pub(crate) use agent_session::*;
pub(crate) use approval::*;
pub(crate) use artifacts::*;
pub(crate) use attention::*;
pub(crate) use attention_notify::*;
pub(crate) use background_events::*;
pub(crate) use batch_scan::*;
pub(crate) use catalog::*;
pub(crate) use command_palette::*;
pub(crate) use command_router::*;
pub(crate) use devex_phase_fixture::*;
pub(crate) use domain_cache::*;
pub(crate) use editor_state::*;
pub(crate) use effect_runtime::*;
pub(crate) use effects::*;
pub(crate) use file_picker::*;
pub(crate) use findings::*;
pub(crate) use guided_scan::*;
pub(crate) use jobs::*;
pub(crate) use line_editor::*;
pub(crate) use live_activity::*;
pub(crate) use log::*;
pub(crate) use operator_questions::*;
pub(crate) use options::*;
pub(crate) use phase_results::*;
pub(crate) use plan::*;
pub(crate) use prereq_chain::*;
pub(crate) use project_scope_discovery::*;
pub(crate) use prompts::*;
pub(crate) use pwn::*;
pub(crate) use review_yield::*;
pub(crate) use run_reference::*;
pub(crate) use runtime::*;
pub(crate) use runtime_keymap::*;
pub(crate) use runtime_state::*;
pub(crate) use sast_scan_policy::*;
pub(crate) use sast_tasks::*;
pub(crate) use scan::*;
pub(crate) use scan_state::ScanState;
pub(crate) use services::*;
pub(crate) use session::*;
pub(crate) use session_state::*;
pub(crate) use session_transcript::*;
pub(crate) use settings::*;
pub(crate) use shell_lifecycle::{auth_ready_for_provider, *};
pub(crate) use shellapp::*;
pub(crate) use steer_queue::*;
pub(crate) use strategy::*;
pub(crate) use target_candidate_discovery::*;
pub(crate) use threats::*;
pub(crate) use tool_run_state::*;
pub(crate) use tool_runner::*;
pub(crate) use ui_constants::*;
pub(crate) use ui_prefs::*;
pub(crate) use update::*;
pub(crate) use view_hydration::*;
pub use view_state::*;
pub(crate) use with_next_step::*;
pub(crate) use workers::*;
pub(crate) use workspace_context::*;
mod abort_reason;
mod agent_chat;
mod agent_chat_state;
mod agent_session;
mod approval;
mod artifacts;
mod attention;
mod attention_notify;
mod autonomy;
mod background_events;
mod batch_scan;
mod campaign;
mod catalog;
mod command_palette;
mod command_router;
mod coverage;
mod editor_state;
mod effect_runtime;
mod effects;
mod file_picker;
mod findings;
mod guided_scan;
mod jobs;
mod line_editor;
mod live_activity;
pub(crate) mod log;
mod operator_questions;
mod options;
mod phase_results;
mod plan;
mod prereq_chain;
mod project_scope_discovery;
mod pwn;
#[cfg(test)]
use self::runtime::{mouse_capture_setting_enabled, render_plain_scripted_session};
use self::settings::{preferred_model_choice_index, thinking_level_from_input};
#[cfg(test)]
use self::workers::parse_plan_json;
use self::workers::parse_threat_patch_json;
use self::workers::{
    merge_json, planner_worker, threat_regen_worker, AgentEvent, PlanEvent, ScanEvent,
    ThreatPatchEvent, ToolEvent,
};
use self::workspace_context::{default_context_snapshot_view, default_workspace_view};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::modules::ModuleKind;
use kuzushi_core::{
    AgenticSastReport, CarliniThreatHuntReport, ExecutionAuthorization, Finding, ModuleRegistry,
    PreparedToolInput, ScanCancellation, ScanProgress, ToolOptionStore, V2Config, WorkspaceTarget,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod onboarding;
mod prompts;
mod review_session;
mod review_yield;
mod run_reference;
mod runtime;
mod runtime_keymap;
mod runtime_state;
mod sast_scan_policy;
mod sast_tasks;
mod scan;
mod scan_state;
mod services;
mod session;
mod session_state;
mod session_transcript;
mod settings;
pub(crate) mod state_transitions;
mod steer_queue;
mod strategy;
mod target_candidate_discovery;
mod task_durations;
mod threats;
mod tool_run_state;
mod tool_runner;
mod ui_constants;
mod ui_prefs;
mod update;
mod view_hydration;
mod view_state;
mod workers;
mod workspace_context;

mod devex_phase_fixture;
mod domain_cache;
mod shell_lifecycle;
mod shellapp;
#[cfg(test)]
mod tests;
mod with_next_step;
pub use agent_chat::AgentChatView;
pub use agent_chat::ChatTurn;
pub use agent_chat::ThreadContextKey;
pub(crate) use agent_chat_state::AgentChatState;
pub use approval::{ConfirmKind, PendingConfirm, PendingPatch};
pub use live_activity::{LiveActivity, LiveActivityPhase};
pub use log::LogLine;
pub(crate) use log::{LogState, LOG_LINE_CAPACITY};
pub(crate) use onboarding::PlanningRunStep;
pub use onboarding::{
    applicable_tasks_for_phase, artifact_state as planning_artifact_state, auth_method_row_kinds,
    auth_method_rows, build_execution_plan, cli_is_on_path, credential_recovery_row_kinds,
    credential_recovery_rows, cycle_planning_row, direct_dependencies, direct_dependents,
    discover_target_candidates, initial_onboarding_phase, initial_onboarding_phase_for,
    model_recommended_in_phase, recommended_tasks_for_phase, record_recent_target, row_disposition,
    skip_onboarding_env, toggle_planning_row, topological_order, transitive_dependencies,
    ArtifactState as PlanningArtifactState, AuthMethodRow, AuthMethodRowKind, FailedPlanningTask,
    InitialOnboardingPhase, LastAttempt, OnboardingInputs, PendingRetry, PickerFocus,
    PlanningOptionEdit, PlanningOptionOverrides, PlanningTaskId, PlanningTaskRow, RowDisposition,
    TargetCandidate, TargetCandidateScope, TargetProfile, ToggleOutcome, WorkflowPhase,
};
pub(crate) use onboarding::{
    bound_target_candidate, eligible_leaf_scopes, immediate_target_candidate,
    large_repository_needs_decomposition, owning_leaf_scope, planning_task_explicit_input,
    scoped_regeneration_input, MapRunConfigSummary, PlanningOperation, ALL_LEAF_SCOPES,
    ALL_SCOPES_HARD_CAP, ALL_SCOPES_REVIEW_THRESHOLD, DECOMPOSE_FIRST_FILE_THRESHOLD,
};
pub use prereq_chain::{
    PendingPrereqPrompt, PrereqArtifactState, PrereqChain, PrereqFinalInput, PrereqPlanAction,
    PrereqPlanStep, PrereqStep,
};
pub use runtime::{
    run_shell, run_shell_with_context, run_shell_with_context_and_config_diagnostics,
    run_shell_with_plain, ShellLaunchContext, ShellTargetSource,
};
pub(crate) use settings::{
    auth_provider_label, bridge_command_status, display_model_selector, env_credential_is_ready,
    model_choice_index_by_id, model_choices, oauth_credential_is_ready,
    oauth_model_switch_for_provider, oauth_provider_status, preferred_visible_model_choice_cursor,
    runtime_backend_label, validate_shell_model_id, AuthProvider, ModelChoice,
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
    PlanChange, PlanProposal, PromptDocumentMode, PromptDocumentState, PromptsAction, PwnView,
    ReconSnapshot, SastTasksFooter, SastTasksSnapshot, SastTasksStatus, ScanPanelState,
    SetupEditor, SetupRouteState, SetupRowId, ShellView, SubsystemAggregate, ThreatPatch,
    ThreatView, ThrottleAdvisory, TuneAction, WorkbenchPage, WorkbenchSurfaceScroll, WorkspaceView,
};
pub(crate) use view_state::{SastTaskMode, SastTaskRow};
