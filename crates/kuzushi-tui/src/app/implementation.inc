#[path = "agent_chat/implementation.inc"]
mod agent_chat;
#[path = "agent_session/implementation.inc"]
mod agent_session;
#[path = "approval/implementation.inc"]
mod approval;
#[path = "artifacts/implementation.inc"]
mod artifacts;
#[path = "background_events/implementation.inc"]
mod background_events;
#[path = "catalog/implementation.inc"]
mod catalog;
#[path = "command_router/implementation.inc"]
mod command_router;
#[path = "findings/implementation.inc"]
mod findings;
#[path = "line_editor/implementation.inc"]
mod line_editor;
#[path = "log/implementation.inc"]
mod log;
#[path = "options/implementation.inc"]
mod options;
#[path = "plan/implementation.inc"]
mod plan;
#[path = "prereq_chain/implementation.inc"]
mod prereq_chain;
#[path = "prompts/implementation.inc"]
mod prompts;
#[path = "runtime/implementation.inc"]
mod runtime;
#[path = "sast_tasks/implementation.inc"]
mod sast_tasks;
#[path = "scan/implementation.inc"]
mod scan;
#[path = "session/implementation.inc"]
mod session;
#[path = "settings/implementation.inc"]
mod settings;
#[path = "state_transitions/implementation.inc"]
pub(crate) mod state_transitions;
#[path = "threats/implementation.inc"]
mod threats;
#[path = "tool_runner/implementation.inc"]
mod tool_runner;
#[path = "view_state/implementation.inc"]
mod view_state;
#[path = "workers/implementation.inc"]
mod workers;
#[path = "workspace_context/implementation.inc"]
mod workspace_context;

pub use agent_chat::AgentChatView;
pub use agent_chat::ChatTurn;
pub use approval::{ConfirmKind, PendingConfirm, PendingPatch};
pub use prereq_chain::{PendingPrereqPrompt, PrereqChain};
pub use log::LogLine;
#[cfg(test)]
use runtime::{mouse_capture_setting_enabled, render_plain_scripted_session};
pub use runtime::{run_shell, run_shell_with_plain};
pub(crate) use settings::{
    bridge_command_status, model_choices, oauth_provider_status, runtime_backend_label,
    validate_shell_model_id, ModelChoice,
};
use settings::{parse_budget_env, preferred_model_choice_index, thinking_level_from_input};
pub use view_state::{
    ActorDetailFilter, AdvisoryState, BudgetHalt, CompletionCycle, ContextSnapshotView,
    ExploitChain, KnowledgeBaseView, OptionsFilter, OptionsView, PlanChange, PlanProposal,
    PromptsAction, ReconSnapshot, ScanPanelState, ShellView, ThreatPatch, ThreatView,
    ThrottleAdvisory, TuneAction, WorkspaceView,
};
pub(crate) use view_state::{SastTaskMode, SastTaskRow};
use workers::{
    merge_json, planner_worker, threat_ask_worker, threat_regen_worker, AgentEvent, PlanEvent,
    ScanEvent, ThreatPatchEvent, ToolEvent,
};
#[cfg(test)]
use workers::{parse_plan_json, parse_threat_patch_json};
use workspace_context::{default_context_snapshot_view, default_workspace_view};

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

const CTRL_C_ARM_WINDOW: Duration = Duration::from_secs(2);
const THROTTLE_STALE_AFTER: Duration = Duration::from_secs(30);
const SPINNER_FRAME: Duration = Duration::from_millis(80);
const VIEWPORT_PAGE_LINES: usize = 10;
const FINDINGS_PAGE_ROWS: usize = 10;

#[cfg(test)]
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use kuzushi_core::{
    AgenticSastReport, CarliniThreatHuntReport, Finding, ModuleRegistry, ScanCancellation,
    ScanProgress, ToolOptionStore, V2Config, WorkspaceTarget,
};
#[cfg(test)]
pub(crate) use state_transitions::{HotkeyTrigger, ViewHotkeyAction};

#[derive(Debug)]
pub struct ShellApp {
    pub input: String,
    pub cursor: usize,
    pub history_index: Option<usize>,
    pub history_draft: String,
    pub last_cleared_input: Option<String>,
    pub completion_cycle: Option<CompletionCycle>,
    pub log: Vec<LogLine>,
    pub target: Option<PathBuf>,
    pub focused_module: Option<String>,
    pub shell_view: ShellView,
    pub prev_shell_view: Option<ShellView>,
    pub catalog_expanded: bool,
    /// Index of the catalog row the operator's cursor is on.  `j`/`k`
    /// move the cursor; `Enter` runs `use <module>` for that row.  Per
    /// `design/mockups/catalog.jsx` the cursor is the bright `▌` on a
    /// `c-sel` background, set in `catalog_module_row`.
    pub catalog_cursor: usize,
    /// Patch staged for human approval — populated when a tool
    /// produces a `pending_patch` artefact.  See `ShellView::Patch`.
    pub pending_patch: Option<PendingPatch>,
    /// Session-scoped allowlist of `<tool> <target>` strings approved
    /// via `Y` (allow + remember).  `confirm_gate_for_tool` checks this
    /// before raising a fresh gate so re-runs don't re-prompt.
    pub confirm_allowlist: std::collections::BTreeSet<String>,
    /// Session-scoped denylist of `<tool> <target>` strings rejected
    /// via `N` (deny + add to denylist).  Re-runs are auto-refused.
    pub confirm_denylist: std::collections::BTreeSet<String>,
    pub config: V2Config,
    pub registry: ModuleRegistry,
    pub option_store: ToolOptionStore,
    pub command_history: Vec<String>,
    pub session_cost_usd: f64,
    pub last_tool_cost_usd: Option<f64>,
    pub selected_model_index: usize,
    pub context_view: ContextSnapshotView,
    pub workspace_view: WorkspaceView,
    pub kb_view: KnowledgeBaseView,
    pub agent_chat: Option<AgentChatView>,
    pub session_thinking_level: Option<String>,
    pub findings: Vec<Finding>,
    pub selected_finding: Option<Finding>,
    pub scan: Option<ScanPanelState>,
    pub should_quit: bool,
    pub ctrl_c_armed_at: Option<Instant>,
    pub session_budget_usd: Option<f64>,
    pub advisory: AdvisoryState,
    /// Active multi-step prerequisite chain (e.g. context:build →
    /// threat-model:build → carlini-threat-hunt:run).  Populated by
    /// `run_tool` when the requested tool has prereqs and cleared once
    /// the final tool dispatches.
    pub pending_chain: Option<PrereqChain>,
    /// Operator-facing reuse-or-regenerate prompt for an existing
    /// prereq artifact.  Mutually exclusive with the dispatch
    /// path: while this is `Some`, the chain is paused.
    pub pending_prereq_prompt: Option<PendingPrereqPrompt>,
    pub pending_plan: Option<PlanProposal>,
    pub plan_cursor: usize,
    pub plan_skipped: BTreeSet<usize>,
    pub tune_cursor: usize,
    pub prompts_cursor: usize,
    pub actor_detail_filter: ActorDetailFilter,
    pub planner_running: bool,
    pub plan_abort_requested: bool,
    pub pending_threat_patch: Option<ThreatPatch>,
    pub threat_worker_running: bool,
    pub threat_abort_requested: bool,
    pub chains: Vec<ExploitChain>,
    pub story_return_view: Option<ShellView>,
    pub findings_cursor: usize,
    pub help_scroll: usize,
    pub tools_scroll: usize,
    pub modules_scroll: usize,
    pub history_scroll: usize,
    pub kb_scroll: usize,
    pub last_char_at: Option<Instant>,
    pub scroll_offset: u16,
    pub spinner_phase: u8,
    pub last_spinner_advance: Option<Instant>,
    pub force_full_redraw: bool,
    pub recon_snapshot: Option<ReconSnapshot>,
    pub carlini_snapshot: Option<CarliniThreatHuntReport>,
    pub agentic_sast_snapshot: Option<AgenticSastReport>,
    pub scan_progress: Option<ScanProgress>,
    scan_rx: Option<Receiver<ScanEvent>>,
    scan_cancel: Option<ScanCancellation>,
    tool_rx: Option<Receiver<ToolEvent>>,
    tool_running: Option<String>,
    tool_run_id: Option<String>,
    tool_abort_requested: bool,
    agent_rx: Option<Receiver<AgentEvent>>,
    plan_rx: Option<Receiver<PlanEvent>>,
    threat_rx: Option<Receiver<ThreatPatchEvent>>,
}

impl ShellApp {
    pub fn new(config: V2Config, target: Option<&WorkspaceTarget>) -> Self {
        let selected_model_index = preferred_model_choice_index(&config);
        let mut app = Self {
            input: String::new(),
            cursor: 0,
            history_index: None,
            history_draft: String::new(),
            last_cleared_input: None,
            completion_cycle: None,
            log: Vec::new(),
            target: target.map(|target| target.root().to_path_buf()),
            focused_module: None,
            shell_view: ShellView::Catalog,
            prev_shell_view: None,
            catalog_expanded: false,
            catalog_cursor: 0,
            pending_patch: None,
            confirm_allowlist: std::collections::BTreeSet::new(),
            confirm_denylist: std::collections::BTreeSet::new(),
            config,
            registry: ModuleRegistry::with_v2_builtins(),
            option_store: ToolOptionStore::new(),
            command_history: Vec::new(),
            session_cost_usd: 0.0,
            last_tool_cost_usd: None,
            selected_model_index,
            context_view: default_context_snapshot_view(
                target.map(|target| target.root().join(".kuzushi/context-snapshot.json")),
            ),
            workspace_view: default_workspace_view(target),
            kb_view: KnowledgeBaseView {
                module_id: "context".to_string(),
                store_path: None,
                attachments: Vec::new(),
                artifacts: Vec::new(),
            },
            agent_chat: None,
            session_thinking_level: None,
            findings: Vec::new(),
            selected_finding: None,
            scan: None,
            should_quit: false,
            ctrl_c_armed_at: None,
            session_budget_usd: parse_budget_env(),
            advisory: AdvisoryState::default(),
            pending_chain: None,
            pending_prereq_prompt: None,
            pending_plan: None,
            plan_cursor: 0,
            plan_skipped: BTreeSet::new(),
            tune_cursor: 0,
            prompts_cursor: 0,
            actor_detail_filter: ActorDetailFilter::All,
            planner_running: false,
            plan_abort_requested: false,
            pending_threat_patch: None,
            threat_worker_running: false,
            threat_abort_requested: false,
            chains: Vec::new(),
            story_return_view: None,
            findings_cursor: 0,
            help_scroll: 0,
            tools_scroll: 0,
            modules_scroll: 0,
            history_scroll: 0,
            kb_scroll: 0,
            last_char_at: None,
            scroll_offset: 0,
            spinner_phase: 0,
            last_spinner_advance: None,
            force_full_redraw: false,
            recon_snapshot: None,
            carlini_snapshot: None,
            agentic_sast_snapshot: None,
            scan_progress: None,
            scan_rx: None,
            scan_cancel: None,
            tool_rx: None,
            tool_running: None,
            tool_run_id: None,
            tool_abort_requested: false,
            agent_rx: None,
            plan_rx: None,
            threat_rx: None,
        };
        app.log("system", "kuzushi shell");
        app.log("startup", app.startup_summary_line());
        // The first-finding hint is rendered in the catalog body via
        // `next_action_line` + `first_finding_hint`; keeping a duplicate
        // copy in the transcript wasted one of only two visible log rows.
        app.log(
            "help",
            "type help for commands · ? <text> to ask · scan to start",
        );
        if target.is_some() {
            app.refresh_findings(false);
        }
        app
    }

    pub fn log(&mut self, prefix: impl Into<String>, body: impl Into<String>) {
        self.log.push(LogLine::new(prefix, body));
        if self.log.len() > 500 {
            let overflow = self.log.len() - 500;
            self.log.drain(0..overflow);
        }
    }

    pub fn scroll_up(&mut self, amount: u16) {
        self.scroll_offset = self.scroll_offset.saturating_sub(amount);
    }

    pub fn scroll_down(&mut self, amount: u16) {
        self.scroll_offset = self.scroll_offset.saturating_add(amount);
    }

    pub fn scroll_to_top(&mut self) {
        self.scroll_offset = 0;
    }

    pub fn scroll_to_bottom(&mut self) {
        self.scroll_offset = u16::MAX;
    }

    fn sync_view_change(&mut self) -> bool {
        let current = Some(self.shell_view.clone());
        if self.prev_shell_view != current {
            self.scroll_offset = 0;
            self.prev_shell_view = current;
            true
        } else {
            false
        }
    }

    pub fn first_finding_scan_command(&self) -> &'static str {
        if self.target.is_some() {
            "scan"
        } else {
            "scan ."
        }
    }

    pub fn first_finding_hint(&self) -> String {
        format!(
            "First finding: run `{}`, then `findings`.",
            self.first_finding_scan_command()
        )
    }

    fn startup_summary_line(&self) -> String {
        let target = self
            .target
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "ready: {} module(s), {} tool(s), target {target}",
            self.registry.modules().count(),
            self.registry.tools().count()
        )
    }
}

fn with_next_step(message: impl Into<String>, next: &str) -> String {
    let message = message.into();
    if message.contains("Next:") {
        return message;
    }
    let separator = if message.ends_with('.') || message.ends_with('!') || message.ends_with('?') {
        " "
    } else {
        ". "
    };
    format!("{message}{separator}Next: {next}")
}

const ASK_SYSTEM_PROMPT: &str = r#"You are Kuzushi's Rust shell assistant.
Answer operator questions about the current repository and Kuzushi workflow.
Do not claim that scans, tools, or model work have run unless the prompt provides that evidence.
Prefer concrete next commands that are routed by the Rust shell."#;

#[cfg(test)]
mod tests;
