use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{self, IsTerminal, Read, Stdout};
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

const CTRL_C_ARM_WINDOW: Duration = Duration::from_secs(2);
const THROTTLE_STALE_AFTER: Duration = Duration::from_secs(30);
const PASTE_GUARD_WINDOW: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, Default)]
pub struct AdvisoryState {
    pub throttle: Option<ThrottleAdvisory>,
    pub budget_halt: Option<BudgetHalt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThrottleAdvisory {
    pub source: String,
    pub message: String,
    pub since: Instant,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BudgetHalt {
    pub limit_usd: f64,
    pub spent_usd: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExploitChain {
    pub id: String,
    pub severity: ChainSeverity,
    pub title: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainSeverity {
    Critical,
    High,
    Medium,
}

impl ChainSeverity {
    fn rank(self) -> u8 {
        match self {
            ChainSeverity::Critical => 0,
            ChainSeverity::High => 1,
            ChainSeverity::Medium => 2,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            ChainSeverity::Critical => "CRIT",
            ChainSeverity::High => "HIGH",
            ChainSeverity::Medium => "MED",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlanProposal {
    pub goal: String,
    pub summary: String,
    pub changes: Vec<PlanChange>,
    pub unsupported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PlanChange {
    SetOption {
        global: bool,
        tool: Option<String>,
        name: String,
        value: String,
    },
    Ask {
        question: String,
    },
    Note {
        text: String,
    },
}

impl PlanChange {
    pub fn label(&self) -> String {
        match self {
            PlanChange::SetOption {
                global,
                tool,
                name,
                value,
            } => {
                let scope = if *global { "setg" } else { "set" };
                let tool_part = tool
                    .as_deref()
                    .map(|tool| format!("{tool} "))
                    .unwrap_or_default();
                format!("{scope} {tool_part}{name}={value}")
            }
            PlanChange::Ask { question } => format!("ask {question}"),
            PlanChange::Note { text } => format!("note {text}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ThreatPatch {
    pub goal: String,
    pub summary: String,
    pub patch: serde_json::Value,
    pub unsupported: Vec<String>,
}

use anyhow::{Context, Result};
use crossterm::cursor::MoveTo;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType};
use kuzushi_core::modules::{OptionSpec, OptionType, ToolDescriptor, ToolExecutionContext};
use kuzushi_core::{
    attach_source, attachment_store_path, default_scan_engines, detach_source,
    export_workspace_findings, is_supported_attachment_module, known_artifacts, list_attachments,
    load_persistent_threat_model, reparse_source, save_persistent_threat_model, AgentQueryRequest,
    AgentRuntime, AttachmentRecord, Finding, FindingListFilter, FindingStore, KnownArtifact,
    ModuleRegistry, OptionScope, OptionTarget, RuntimeKind, ScanCancellation, ScanRunOptions,
    Severity, ToolOptionStore, V2Config, WorkspaceTarget, SUPPORTED_ATTACHMENT_MODULES,
};
use kuzushi_openai::PiAgentCoreRuntime;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use uuid::Uuid;

use crate::commands::{
    parse_command, shell_command_specs, ContextCommand, SastTaskCommand, SastTaskModeCommand,
    ShellCommand, WorkspaceCommand,
};
use crate::renderer::{render_app, render_plain_app};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub prefix: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanPanelState {
    pub run_id: Option<String>,
    pub target: PathBuf,
    pub stage: String,
    pub findings_count: usize,
    pub running: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionsView {
    pub tool_name: String,
    pub filter: OptionsFilter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionsFilter {
    Standard,
    Advanced,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SastTaskMode {
    Auto,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SastTaskRow {
    pub id: &'static str,
    pub scan_task: &'static str,
    pub cost: &'static str,
    pub notes: &'static str,
    pub toggleable: bool,
    pub selected: bool,
    pub state: &'static str,
    pub source: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnowledgeBaseView {
    pub module_id: String,
    pub store_path: Option<PathBuf>,
    pub attachments: Vec<AttachmentRecord>,
    pub artifacts: Vec<KnownArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSnapshotView {
    pub snapshot_path: Option<PathBuf>,
    pub exists: bool,
    pub status: String,
    pub target: Option<String>,
    pub discovery: Option<String>,
    pub files_indexed: Option<u64>,
    pub total_files: Option<u64>,
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
    pub generated_slices: Vec<String>,
    pub stale_slices: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceView {
    pub root: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub findings_db: Option<PathBuf>,
    pub findings_count: Option<usize>,
    pub last_export: Option<PathBuf>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentChatView {
    pub question: String,
    pub answer: Option<String>,
    pub running: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ModelChoice {
    pub index: usize,
    pub id: &'static str,
    pub label: &'static str,
    pub provider: &'static str,
    pub auth: &'static str,
    pub thinking_level: &'static str,
}

const MODEL_CHOICES: &[ModelChoice] = &[
    ModelChoice {
        index: 1,
        id: "openai:gpt-5.5",
        label: "GPT-5.5",
        provider: "openai",
        auth: "OPENAI_API_KEY",
        thinking_level: "xhigh",
    },
    ModelChoice {
        index: 2,
        id: "openai:gpt-5.5-mini",
        label: "GPT-5.5 mini",
        provider: "openai",
        auth: "OPENAI_API_KEY",
        thinking_level: "high",
    },
    ModelChoice {
        index: 3,
        id: "openai-codex:gpt-5.5",
        label: "Codex GPT-5.5",
        provider: "openai-codex",
        auth: "OAuth",
        thinking_level: "xhigh",
    },
    ModelChoice {
        index: 4,
        id: "openai-codex:gpt-5.5-mini",
        label: "Codex GPT-5.5 mini",
        provider: "openai-codex",
        auth: "OAuth",
        thinking_level: "high",
    },
    ModelChoice {
        index: 5,
        id: "anthropic:claude-sonnet-4-6",
        label: "Claude Sonnet 4.6",
        provider: "anthropic",
        auth: "ANTHROPIC_API_KEY or OAuth",
        thinking_level: "high",
    },
    ModelChoice {
        index: 6,
        id: "anthropic:claude-opus-4-7",
        label: "Claude Opus 4.7",
        provider: "anthropic",
        auth: "ANTHROPIC_API_KEY or OAuth",
        thinking_level: "xhigh",
    },
];

pub(crate) fn model_choices() -> &'static [ModelChoice] {
    MODEL_CHOICES
}

fn preferred_model_choice_index(config: &V2Config) -> usize {
    if let Some(model) = config.model.as_deref() {
        if let Some(index) = MODEL_CHOICES.iter().position(|choice| choice.id == model) {
            return index;
        }
    }

    if oauth_provider_status("openai-codex").starts_with("stored") {
        if let Some(index) = MODEL_CHOICES
            .iter()
            .position(|choice| choice.provider == "openai-codex")
        {
            return index;
        }
    }

    if env::var_os("OPENAI_API_KEY").is_some() {
        if let Some(index) = MODEL_CHOICES
            .iter()
            .position(|choice| choice.provider == "openai")
        {
            return index;
        }
    }

    if env::var_os("ANTHROPIC_API_KEY").is_some()
        || oauth_provider_status("anthropic").starts_with("stored")
    {
        if let Some(index) = MODEL_CHOICES
            .iter()
            .position(|choice| choice.provider == "anthropic")
        {
            return index;
        }
    }

    0
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellView {
    Catalog,
    Module,
    ModuleRun,
    Findings,
    Finding,
    Tune,
    Threat(ThreatView),
    ThreatEditor,
    PromptsEditor,
    ActorDetail(usize),
    Runs,
    Replay(String),
    Trace(String),
    Help,
    Config,
    Tools,
    Options(OptionsView),
    SastTasks,
    Context,
    Workspace,
    KnowledgeBase,
    AgentChat,
    History,
    Story,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatView {
    Dfd,
    Stride,
    Stories,
    Scope,
    Summary,
}

#[derive(Debug)]
pub struct ShellApp {
    pub input: String,
    pub log: Vec<LogLine>,
    pub target: Option<PathBuf>,
    pub focused_module: Option<String>,
    pub shell_view: ShellView,
    pub catalog_expanded: bool,
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
    pub pending_plan: Option<PlanProposal>,
    pub planner_running: bool,
    pub pending_threat_patch: Option<ThreatPatch>,
    pub threat_worker_running: bool,
    pub chains: Vec<ExploitChain>,
    pub story_return_view: Option<ShellView>,
    pub findings_cursor: usize,
    pub last_char_at: Option<Instant>,
    scan_rx: Option<Receiver<ScanEvent>>,
    scan_cancel: Option<ScanCancellation>,
    agent_rx: Option<Receiver<AgentEvent>>,
    plan_rx: Option<Receiver<PlanEvent>>,
    threat_rx: Option<Receiver<ThreatPatchEvent>>,
}

impl ShellApp {
    pub fn new(config: V2Config, target: Option<&WorkspaceTarget>) -> Self {
        let selected_model_index = preferred_model_choice_index(&config);
        let mut app = Self {
            input: String::new(),
            log: Vec::new(),
            target: target.map(|target| target.root().to_path_buf()),
            focused_module: None,
            shell_view: ShellView::Catalog,
            catalog_expanded: false,
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
            pending_plan: None,
            planner_running: false,
            pending_threat_patch: None,
            threat_worker_running: false,
            chains: Vec::new(),
            story_return_view: None,
            findings_cursor: 0,
            last_char_at: None,
            scan_rx: None,
            scan_cancel: None,
            agent_rx: None,
            plan_rx: None,
            threat_rx: None,
        };
        app.log("system", "kuzushi shell");
        app.log(
            "help",
            "/scan, /run <tool>, /ask <question>, ?text, /workspace, /context build, /tasks, /options [tool], /auth login openai-codex|anthropic, /provider, /backend, /model, /cost, /kb, /history, /clear, /load <specifier>, /findings, /modules, /tools, /quit",
        );
        if target.is_some() {
            app.refresh_findings(false);
        }
        app
    }

    pub fn log(&mut self, prefix: impl Into<String>, body: impl Into<String>) {
        self.log.push(LogLine {
            prefix: prefix.into(),
            body: body.into(),
        });
        if self.log.len() > 500 {
            let overflow = self.log.len() - 500;
            self.log.drain(0..overflow);
        }
    }

    pub fn handle_command(&mut self, command: ShellCommand) {
        match command {
            ShellCommand::Help => {
                self.shell_view = ShellView::Help;
                self.log("help", compact_help_summary());
            }
            ShellCommand::Back => self.go_back(),
            ShellCommand::Modules => {
                self.shell_view = ShellView::Catalog;
                self.catalog_expanded = true;
                self.log(
                    "module",
                    format!("showing {} module(s)", self.registry.modules().count()),
                );
            }
            ShellCommand::Tools => {
                self.shell_view = ShellView::Tools;
                self.log(
                    "tool",
                    format!("showing {} tool(s)", self.registry.tools().count()),
                );
            }
            ShellCommand::Findings => self.show_findings(),
            ShellCommand::Open(id) => self.open_finding(&id),
            ShellCommand::Scan(target) => self.start_scan(target),
            ShellCommand::Model(model) => self.handle_model_command(model),
            ShellCommand::Auth => self.show_auth_status(),
            ShellCommand::AuthLogin(provider) => self.handle_auth_login_command(provider),
            ShellCommand::Provider(provider) => self.handle_provider_command(provider),
            ShellCommand::Backend(backend) => self.handle_backend_command(backend),
            ShellCommand::Cost => self.show_cost_status(),
            ShellCommand::Config => {
                self.shell_view = ShellView::Config;
                self.sync_selected_model_index();
                self.log(
                    "config",
                    format!(
                        "runtime={} provider={} model={}",
                        runtime_backend_label(&self.config),
                        self.provider_label(),
                        self.config.model.as_deref().unwrap_or("unconfigured")
                    ),
                );
            }
            ShellCommand::Use(module) => {
                if self
                    .registry
                    .modules()
                    .any(|entry| entry.metadata().id == module)
                {
                    self.focused_module = Some(module.clone());
                    self.shell_view = ShellView::Module;
                    self.log("use", module);
                } else {
                    self.log("error", format!("unknown module {module}"));
                }
            }
            ShellCommand::Tune => {
                self.shell_view = ShellView::Tune;
                self.log("view", "tune");
            }
            ShellCommand::Threat(view) => {
                self.shell_view = ShellView::Threat(view);
                self.log("view", format!("threats {}", threat_view_label(view)));
            }
            ShellCommand::ThreatRegen => self.start_threat_regen(),
            ShellCommand::ThreatAsk(question) => self.start_threat_ask(&question),
            ShellCommand::ThreatApply => self.apply_pending_threat_patch(),
            ShellCommand::ThreatReject => self.discard_pending_threat_patch(),
            ShellCommand::ThreatEditor => {
                self.shell_view = ShellView::ThreatEditor;
                self.log("view", "threats edit");
            }
            ShellCommand::Prompts => {
                self.shell_view = ShellView::PromptsEditor;
                self.log("view", "prompts");
            }
            ShellCommand::Prompt(raw) => {
                self.shell_view = ShellView::PromptsEditor;
                self.handle_prompt_verb(&raw);
            }
            ShellCommand::Actor(index) => {
                self.shell_view = ShellView::ActorDetail(index);
                self.log("actor", index.to_string());
            }
            ShellCommand::ShowRuns => {
                self.shell_view = ShellView::Runs;
                self.log("runs", "recent runs");
            }
            ShellCommand::ShowAliases(prefix) => {
                self.show_aliases(prefix.as_deref());
            }
            ShellCommand::Since(reference) => {
                self.shell_view = ShellView::Findings;
                self.log("since", reference);
            }
            ShellCommand::Replay(run_id) => {
                self.shell_view = ShellView::Replay(run_id.clone());
                self.log("replay", run_id);
            }
            ShellCommand::Trace(run_id) => {
                self.shell_view = ShellView::Trace(run_id.clone());
                self.log("trace", run_id);
            }
            ShellCommand::Plan(goal) => self.start_planner(&goal),
            ShellCommand::PlanApply => self.apply_pending_plan(),
            ShellCommand::PlanDiscard => self.discard_pending_plan(),
            ShellCommand::Quickstart => self.show_quickstart(),
            ShellCommand::Target(path) => self.handle_target_command(path.as_deref()),
            ShellCommand::Ask(question) => self.ask_agent(&question),
            ShellCommand::Options { tool, filter } => self.show_options(tool, filter),
            ShellCommand::SetOption {
                global,
                name,
                value,
            } => self.set_option(global, &name, &value),
            ShellCommand::UnsetOption { global, name } => self.unset_option(global, &name),
            ShellCommand::Tasks => self.show_sast_tasks(),
            ShellCommand::Task(command) => self.handle_sast_task_command(command),
            ShellCommand::Context(command) => self.handle_context_command(command),
            ShellCommand::Workspace(command) => self.handle_workspace_command(command),
            ShellCommand::KnowledgeBase(module) => self.show_kb(module),
            ShellCommand::Attach(source) => self.attach_kb_source(&source),
            ShellCommand::Detach(id) => self.detach_kb_source(&id),
            ShellCommand::Reparse(id) => self.reparse_kb_source(&id),
            ShellCommand::History => self.show_history(),
            ShellCommand::Clear => self.clear_conversation(),
            ShellCommand::Load(specifier) => self.handle_load_command(specifier),
            ShellCommand::Resume(run_id) => self.handle_resume_command(run_id),
            ShellCommand::Pause => self.handle_pause_command(),
            ShellCommand::Story => self.show_story(),
            ShellCommand::RunTool { tool, input } => self.run_tool(tool, input),
            ShellCommand::Quit => {
                self.request_exit();
            }
            ShellCommand::Empty => {}
            ShellCommand::Unknown(raw) => self.log("error", unknown_command_message(&raw)),
        }
    }

    pub fn submit_line(&mut self, raw: &str) {
        self.log(">", raw.to_string());
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            self.command_history.push(trimmed.to_string());
            if self.command_history.len() > 200 {
                let overflow = self.command_history.len() - 200;
                self.command_history.drain(0..overflow);
            }
        }
        if matches!(self.shell_view, ShellView::PromptsEditor)
            && !trimmed.is_empty()
            && !trimmed.starts_with('/')
            && self.is_bare_prompt_verb(trimmed)
        {
            self.handle_prompt_verb(trimmed);
            return;
        }
        if matches!(self.shell_view, ShellView::Tune)
            && !trimmed.is_empty()
            && !trimmed.starts_with('/')
            && self.is_bare_tune_verb(trimmed)
        {
            self.handle_tune_verb(trimmed);
            return;
        }
        self.handle_command(parse_command(raw));
    }

    fn is_bare_prompt_verb(&self, raw: &str) -> bool {
        let head = raw.split_whitespace().next().unwrap_or("");
        matches!(head, "edit" | "show" | "diff" | "reset" | "set" | "list")
    }

    fn is_bare_tune_verb(&self, raw: &str) -> bool {
        let head = raw.split_whitespace().next().unwrap_or("");
        matches!(head, "show" | "set" | "reset")
    }

    pub fn completion_candidates(&self, input: &str) -> Vec<String> {
        let raw = input.trim_start();
        let slash = raw.starts_with('/');
        let normalized = raw.strip_prefix('/').unwrap_or(raw);
        let ends_with_space = normalized.chars().last().is_some_and(char::is_whitespace);
        let words = normalized.split_whitespace().collect::<Vec<_>>();

        if words.is_empty() {
            return command_completion_candidates("", slash);
        }
        if words.len() == 1 && !ends_with_space {
            return command_completion_candidates(words[0], slash);
        }

        let current = if ends_with_space {
            ""
        } else {
            words.last().copied().unwrap_or_default()
        };
        let prefix_words = if ends_with_space {
            words.as_slice()
        } else {
            &words[..words.len().saturating_sub(1)]
        };

        match words.first().copied().unwrap_or_default() {
            "use" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.module_completion_values(),
            ),
            "run" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.tool_completion_values(),
            ),
            "options" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.tool_completion_values(),
            ),
            "set" | "setg" | "unset" | "unsetg" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.option_completion_values(),
            ),
            "task" => self.task_completion_candidates(slash, prefix_words, current),
            "context" => self.context_completion_candidates(slash, prefix_words, current),
            "workspace" => self.workspace_completion_candidates(slash, prefix_words, current),
            "kb" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                SUPPORTED_ATTACHMENT_MODULES
                    .iter()
                    .map(|module| (*module).to_string())
                    .collect(),
            ),
            "detach" | "reparse" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.attachment_id_completion_values(),
            ),
            "open" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.finding_completion_values(),
            ),
            "replay" | "trace" | "resume" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.run_id_completion_values(),
            ),
            "config" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                config_completion_keys()
                    .iter()
                    .map(|key| (*key).to_string())
                    .collect(),
            ),
            "model" => complete_value_candidates(
                slash,
                prefix_words,
                current,
                MODEL_CHOICES
                    .iter()
                    .flat_map(|choice| [choice.index.to_string(), choice.id.to_string()])
                    .collect(),
            ),
            "auth" => self.auth_completion_candidates(slash, prefix_words, current),
            "show" => self.show_completion_candidates(slash, prefix_words, current),
            _ => Vec::new(),
        }
    }

    fn apply_completion(&mut self) {
        if let Some(candidate) = self.completion_candidates(&self.input).into_iter().next() {
            self.input = candidate;
        }
    }

    fn module_completion_values(&self) -> Vec<String> {
        self.registry
            .modules()
            .map(|module| module.metadata().id.clone())
            .collect()
    }

    fn tool_completion_values(&self) -> Vec<String> {
        let mut values = self
            .registry
            .tools()
            .map(|tool| tool.name.clone())
            .collect::<Vec<_>>();
        if let Some(module) = self.focused_module.as_ref() {
            let prefix = format!("{module}:");
            values.extend(self.registry.tools().filter_map(|tool| {
                tool.name
                    .strip_prefix(&prefix)
                    .map(|short_name| short_name.to_string())
            }));
        }
        values
    }

    fn option_completion_values(&self) -> Vec<String> {
        self.resolve_options_tool(None)
            .ok()
            .and_then(|tool_name| self.registry.resolve_tool(&tool_name))
            .map(|tool| tool.options.iter().map(|spec| spec.name.clone()).collect())
            .unwrap_or_default()
    }

    fn task_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        match prefix_words {
            ["task"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["block", "allow", "toggle", "mode", "reset"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            ["task", "mode"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["auto", "manual", "toggle"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            ["task", "block" | "allow" | "toggle" | "deny" | "unblock"] => {
                complete_value_candidates(
                    slash,
                    prefix_words,
                    current,
                    valid_sast_task_ids()
                        .iter()
                        .map(|id| (*id).to_string())
                        .collect(),
                )
            }
            _ => Vec::new(),
        }
    }

    fn context_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        match prefix_words {
            ["context"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["build", "status", "regen"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            ["context", "regen"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["all", "repo", "app-model"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            _ => Vec::new(),
        }
    }

    fn workspace_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        match prefix_words {
            ["workspace"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["status", "export"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            ["workspace", "export"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["findings"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            _ => Vec::new(),
        }
    }

    fn auth_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        match prefix_words {
            ["auth"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["status", "login", "codex", "anthropic"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            ["auth", "login"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                ["openai-codex", "anthropic"]
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            _ => Vec::new(),
        }
    }

    fn show_completion_candidates(
        &self,
        slash: bool,
        prefix_words: &[&str],
        current: &str,
    ) -> Vec<String> {
        match prefix_words {
            ["show"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                [
                    "modules", "tools", "options", "advanced", "missing", "aliases", "runs",
                    "prompts",
                ]
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            ),
            ["show", "options"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.tool_completion_values(),
            ),
            ["show", "aliases"] => complete_value_candidates(
                slash,
                prefix_words,
                current,
                self.finding_completion_values(),
            ),
            _ => Vec::new(),
        }
    }

    fn attachment_id_completion_values(&self) -> Vec<String> {
        self.kb_view
            .attachments
            .iter()
            .map(|record| record.id.clone())
            .collect()
    }

    fn finding_completion_values(&self) -> Vec<String> {
        let mut findings = self.findings.clone();
        if findings.is_empty() {
            if let Some(target) = self.target.as_ref() {
                if let Ok(workspace) = WorkspaceTarget::new(target) {
                    if let Ok(store) = FindingStore::open(workspace.findings_db_path()) {
                        if let Ok(stored) = store.list_findings(200) {
                            findings = stored;
                        }
                    }
                }
            }
        }

        let mut values = Vec::new();
        for (index, finding) in findings.iter().enumerate() {
            values.push(format_finding_alias(index));
            values.push(short_fingerprint(&finding.fingerprint));
            values.push(finding.fingerprint.clone());
        }
        values
    }

    fn run_id_completion_values(&self) -> Vec<String> {
        let mut values = Vec::new();
        if let Some(run_id) = self.scan.as_ref().and_then(|scan| scan.run_id.clone()) {
            values.push(run_id);
        }
        if let Some(target) = self.target.as_ref() {
            let runs_dir = target.join(".kuzushi/runs");
            if let Ok(entries) = fs::read_dir(runs_dir) {
                values.extend(entries.flatten().filter_map(|entry| {
                    entry
                        .file_type()
                        .ok()
                        .filter(|file_type| file_type.is_dir())
                        .and_then(|_| entry.file_name().into_string().ok())
                }));
            }
        }
        values
    }

    pub fn drain_background_events(&mut self) {
        let mut events = Vec::new();
        if let Some(rx) = &self.scan_rx {
            while let Ok(event) = rx.try_recv() {
                events.push(event);
            }
        }

        for event in events {
            self.apply_scan_event(event);
        }

        if self.scan.as_ref().is_some_and(|scan| !scan.running) {
            self.scan_rx = None;
            self.scan_cancel = None;
        }

        let mut agent_events = Vec::new();
        if let Some(rx) = &self.agent_rx {
            while let Ok(event) = rx.try_recv() {
                agent_events.push(event);
            }
        }

        for event in agent_events {
            self.apply_agent_event(event);
        }

        if self.agent_chat.as_ref().is_some_and(|agent| !agent.running) {
            self.agent_rx = None;
        }

        let mut plan_events = Vec::new();
        if let Some(rx) = &self.plan_rx {
            while let Ok(event) = rx.try_recv() {
                plan_events.push(event);
            }
        }
        for event in plan_events {
            self.apply_plan_event(event);
        }
        if !self.planner_running {
            self.plan_rx = None;
        }

        let mut threat_events = Vec::new();
        if let Some(rx) = &self.threat_rx {
            while let Ok(event) = rx.try_recv() {
                threat_events.push(event);
            }
        }
        for event in threat_events {
            self.apply_threat_patch_event(event);
        }
        if !self.threat_worker_running {
            self.threat_rx = None;
        }
    }

    fn apply_threat_patch_event(&mut self, event: ThreatPatchEvent) {
        self.threat_worker_running = false;
        match event {
            ThreatPatchEvent::Proposed(patch) => {
                self.log(
                    "threats",
                    format!(
                        "patch proposed; {} unsupported note(s); review with /threats apply or /threats reject",
                        patch.unsupported.len()
                    ),
                );
                self.pending_threat_patch = Some(patch);
            }
            ThreatPatchEvent::Answer { text } => {
                self.log("threats", text);
            }
            ThreatPatchEvent::Failed { error } => {
                self.log("error", format!("threats worker failed: {error}"));
            }
        }
    }

    pub fn start_threat_regen(&mut self) {
        if self.threat_worker_running {
            self.log("threats", "regen already running; wait for the proposal");
            return;
        }
        if self.pending_threat_patch.is_some() {
            self.log(
                "threats",
                "discard the pending patch first with /threats reject",
            );
            return;
        }
        let Some(model) = self.config.model.clone() else {
            self.log(
                "error",
                "/threats regen requires an explicit model. Next: model",
            );
            return;
        };
        if let Err(message) = validate_shell_model_id(&model) {
            self.log("error", message);
            return;
        }
        let cwd = self
            .target
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let existing = load_persistent_threat_model(&cwd).unwrap_or(serde_json::Value::Null);
        let config = self.config.clone();
        let thinking_level = self.session_thinking_level.clone();
        let (tx, rx) = mpsc::channel();
        self.threat_rx = Some(rx);
        self.threat_worker_running = true;
        self.log("threats", "regenerating threat-model patch");

        thread::spawn(move || {
            threat_regen_worker(config, model, thinking_level, cwd, existing, tx)
        });
    }

    pub fn start_threat_ask(&mut self, question: &str) {
        if self.threat_worker_running {
            self.log("threats", "regen already running; wait first");
            return;
        }
        let question = question.trim();
        if question.is_empty() {
            self.log(
                "error",
                "/threats ask requires a question. Next: /threats ask what attack surface is in admin?",
            );
            return;
        }
        let Some(model) = self.config.model.clone() else {
            self.log(
                "error",
                "/threats ask requires an explicit model. Next: model",
            );
            return;
        };
        if let Err(message) = validate_shell_model_id(&model) {
            self.log("error", message);
            return;
        }
        let cwd = self
            .target
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let existing = load_persistent_threat_model(&cwd).unwrap_or(serde_json::Value::Null);
        let config = self.config.clone();
        let thinking_level = self.session_thinking_level.clone();
        let question = question.to_string();
        let (tx, rx) = mpsc::channel();
        self.threat_rx = Some(rx);
        self.threat_worker_running = true;
        self.log("threats", format!("asking: {question}"));

        thread::spawn(move || {
            threat_ask_worker(config, model, thinking_level, cwd, existing, question, tx)
        });
    }

    pub fn apply_pending_threat_patch(&mut self) {
        let Some(patch) = self.pending_threat_patch.take() else {
            self.log("threats", "no pending patch; run /threats regen first");
            return;
        };
        let cwd = self
            .target
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let mut document =
            load_persistent_threat_model(&cwd).unwrap_or_else(|| serde_json::json!({}));
        merge_json(&mut document, &patch.patch);
        match save_persistent_threat_model(&cwd, &document, true) {
            Ok(_) => {
                self.log(
                    "threats",
                    format!(
                        "applied patch ({} unsupported note(s))",
                        patch.unsupported.len()
                    ),
                );
                for note in patch.unsupported {
                    self.log("threats-skip", note);
                }
            }
            Err(error) => self.log("error", format!("failed to write threat model: {error}")),
        }
    }

    pub fn discard_pending_threat_patch(&mut self) {
        if self.pending_threat_patch.take().is_some() {
            self.log("threats", "discarded pending patch");
        }
    }

    pub fn set_pending_threat_patch(&mut self, patch: ThreatPatch) {
        self.pending_threat_patch = Some(patch);
        self.threat_worker_running = false;
    }

    fn apply_plan_event(&mut self, event: PlanEvent) {
        self.planner_running = false;
        match event {
            PlanEvent::Proposed(plan) => {
                self.log(
                    "plan",
                    format!(
                        "{} change(s); press [y] to apply, [n] to discard",
                        plan.changes.len()
                    ),
                );
                self.pending_plan = Some(plan);
            }
            PlanEvent::Failed { error } => {
                self.log("error", format!("planner failed: {error}"));
            }
        }
    }

    pub fn set_pending_plan(&mut self, plan: PlanProposal) {
        self.planner_running = false;
        self.pending_plan = Some(plan);
    }

    pub fn start_planner(&mut self, goal: &str) {
        let goal = goal.trim();
        if goal.is_empty() {
            self.log(
                "error",
                "/plan requires a goal. Next: /plan focus on SSRF in admin routes",
            );
            return;
        }
        if self.planner_running {
            self.log("plan", "planner already running; wait for the proposal");
            return;
        }
        if self.pending_plan.is_some() {
            self.log("plan", "discard the current pending plan first with /no");
            return;
        }

        let Some(model) = self.config.model.clone() else {
            self.log(
                "error",
                "/plan requires an explicit model. Next: model, then choose a pi-agent-core provider/model",
            );
            return;
        };
        if let Err(message) = validate_shell_model_id(&model) {
            self.log("error", message);
            return;
        }

        let cwd = self
            .target
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let config = self.config.clone();
        let thinking_level = self.session_thinking_level.clone();
        let goal_owned = goal.to_string();
        let (tx, rx) = mpsc::channel();
        self.plan_rx = Some(rx);
        self.planner_running = true;
        self.log("plan", format!("planning: {goal_owned}"));

        thread::spawn(move || planner_worker(config, model, thinking_level, cwd, goal_owned, tx));
    }

    pub fn apply_pending_plan(&mut self) {
        let Some(plan) = self.pending_plan.take() else {
            return;
        };
        let total = plan.changes.len();
        let mut applied = 0usize;
        for change in plan.changes {
            match change {
                PlanChange::SetOption {
                    global,
                    tool,
                    name,
                    value,
                } => {
                    if let Some(tool_name) = tool {
                        self.handle_command(ShellCommand::Options {
                            tool: Some(tool_name),
                            filter: OptionsFilter::Standard,
                        });
                    }
                    self.handle_command(ShellCommand::SetOption {
                        global,
                        name,
                        value,
                    });
                    applied += 1;
                }
                PlanChange::Ask { question } => {
                    self.handle_command(ShellCommand::Ask(question));
                    applied += 1;
                }
                PlanChange::Note { text } => {
                    self.log("plan-note", text);
                    applied += 1;
                }
            }
        }
        self.log("plan", format!("applied {applied}/{total} change(s)"));
        for line in plan.unsupported {
            self.log("plan-skip", line);
        }
    }

    pub fn discard_pending_plan(&mut self) {
        if self.pending_plan.take().is_some() {
            self.log("plan", "discarded pending plan");
        }
    }

    pub fn show_aliases(&mut self, prefix: Option<&str>) {
        self.shell_view = ShellView::Findings;
        let filter = prefix.map(|raw| raw.trim().to_ascii_uppercase());
        let table = format_alias_table(&self.findings, &self.chains, filter.as_deref());
        for line in table.lines() {
            self.log("aliases", line.to_string());
        }
    }

    fn ask_agent(&mut self, question: &str) {
        let question = question.trim();
        if question.is_empty() {
            self.log(
                "error",
                "ask requires a question. Next: /ask what should I inspect?",
            );
            return;
        }
        if self.agent_chat.as_ref().is_some_and(|agent| agent.running) {
            self.log(
                "agent",
                "question already active; wait for the current answer",
            );
            return;
        }

        let Some(model) = self.config.model.clone() else {
            self.shell_view = ShellView::AgentChat;
            self.agent_chat = Some(AgentChatView {
                question: question.to_string(),
                answer: None,
                running: false,
                error: Some(
                    "ask requires an explicit model. Next: model, then choose a pi-agent-core provider/model".to_string(),
                ),
            });
            self.log(
                "error",
                "ask requires an explicit model. Next: model, then choose a pi-agent-core provider/model",
            );
            return;
        };
        if let Err(message) = validate_shell_model_id(&model) {
            self.shell_view = ShellView::AgentChat;
            self.agent_chat = Some(AgentChatView {
                question: question.to_string(),
                answer: None,
                running: false,
                error: Some(message.clone()),
            });
            self.log("error", message);
            return;
        }

        let cwd = self
            .target
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        let config = self.config.clone();
        let thinking_level = self.session_thinking_level.clone();
        let question = question.to_string();
        let (tx, rx) = mpsc::channel();
        self.agent_chat = Some(AgentChatView {
            question: question.clone(),
            answer: None,
            running: true,
            error: None,
        });
        self.agent_rx = Some(rx);
        self.shell_view = ShellView::AgentChat;
        self.log(
            "agent",
            format!(
                "asking {model}{}",
                thinking_level
                    .as_deref()
                    .map(|level| format!(" / {level}"))
                    .unwrap_or_default()
            ),
        );

        thread::spawn(move || agent_worker(config, model, thinking_level, cwd, question, tx));
    }

    fn handle_context_command(&mut self, command: ContextCommand) {
        match command {
            ContextCommand::Show | ContextCommand::Status => self.show_context_status(),
            ContextCommand::Build => self.build_context_snapshot(None),
            ContextCommand::Regen(slice) => self.regen_context_slice(&slice),
        }
    }

    fn handle_workspace_command(&mut self, command: WorkspaceCommand) {
        match command {
            WorkspaceCommand::Status => self.show_workspace_status(),
            WorkspaceCommand::ExportFindings { output } => self.export_workspace_findings(&output),
            WorkspaceCommand::Unsupported(raw) => {
                self.shell_view = ShellView::Workspace;
                self.log(
                    "error",
                    format!(
                        "{raw} is not supported by the Rust workspace bridge yet. Supported: workspace status, workspace export findings <path>.json"
                    ),
                );
            }
        }
    }

    fn show_history(&mut self) {
        self.shell_view = ShellView::History;
        self.log(
            "history",
            format!(
                "showing {} command(s). Next: clear or run <tool>",
                self.command_history.len()
            ),
        );
    }

    fn clear_conversation(&mut self) {
        self.log.clear();
        self.selected_finding = None;
        self.agent_chat = None;
        self.agent_rx = None;
        self.shell_view = ShellView::Catalog;
        self.log(
            "system",
            "Conversation cleared. Command history retained. Next: history or help",
        );
    }

    fn handle_load_command(&mut self, specifier: Option<String>) {
        self.shell_view = ShellView::Tools;
        let Some(specifier) = specifier
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        else {
            self.log(
                "error",
                "load requires a module specifier. Next: load builtin:sast or modules",
            );
            return;
        };

        let module_id = specifier
            .strip_prefix("builtin:")
            .unwrap_or(specifier.as_str())
            .trim();
        if !module_id.contains(':')
            && self
                .registry
                .modules()
                .any(|module| module.metadata().id == module_id)
        {
            self.log(
                "load",
                format!(
                    "{specifier} is already available in the Rust static registry. Next: use {module_id}"
                ),
            );
            return;
        }

        self.log(
            "error",
            format!(
                "dynamic module loading is not supported by the Rust shell; {specifier:?} was not loaded. Next: modules"
            ),
        );
    }

    fn handle_resume_command(&mut self, run_id: Option<String>) {
        if let Some(run_id) = run_id.filter(|value| !value.trim().is_empty()) {
            self.shell_view = ShellView::Replay(run_id.clone());
            self.log(
                "resume",
                format!(
                    "checkpoint resume not implemented; opening replay {run_id}. Next: /replay {run_id}"
                ),
            );
            return;
        }
        if self.is_scan_paused() {
            if let Some(cancel) = &self.scan_cancel {
                cancel.resume();
            }
            if let Some(scan) = &mut self.scan {
                scan.stage = "running".to_string();
            }
            self.log("resume", "scan resumed");
            return;
        }
        self.shell_view = ShellView::Runs;
        self.log(
            "resume",
            "no paused scan to resume. Next: show runs, replay <runId>, or scan <target>",
        );
    }

    pub fn is_scan_paused(&self) -> bool {
        self.scan_cancel
            .as_ref()
            .map(|cancel| cancel.is_paused())
            .unwrap_or(false)
    }

    fn handle_pause_command(&mut self) {
        if self.scan.as_ref().is_some_and(|scan| scan.running) {
            if let Some(cancel) = &self.scan_cancel {
                cancel.pause();
                if let Some(scan) = &mut self.scan {
                    scan.stage = "paused".to_string();
                }
                self.log(
                    "pause",
                    "scan paused; in-flight scanner may finish its current step. Resume with /resume",
                );
                return;
            }
        }
        if self.agent_chat.as_ref().is_some_and(|agent| agent.running) {
            self.log(
                "pause",
                "pause is intentionally absent for Rust agent chat. Wait for the answer or start a new question after it finishes.",
            );
            return;
        }
        self.log(
            "pause",
            "no live pause/resume control is active in the Rust shell. Next: scan <target> or run <tool>",
        );
    }

    pub fn house_rules_path(&self) -> Option<PathBuf> {
        let module = self.focused_module.as_ref()?;
        let target = self.target.as_ref()?;
        Some(
            target
                .join(".kuzushi")
                .join("house-rules")
                .join(format!("{module}.md")),
        )
    }

    pub fn read_house_rules(&self) -> Option<String> {
        let path = self.house_rules_path()?;
        std::fs::read_to_string(path).ok()
    }

    pub fn handle_tune_verb(&mut self, raw: &str) {
        let raw = raw.trim();
        if raw.is_empty() {
            self.log("tune", "verbs: show | set \"<text>\" | reset");
            return;
        }
        let mut parts = raw.splitn(2, char::is_whitespace);
        let verb = parts.next().unwrap_or("");
        let rest = parts.next().unwrap_or("").trim();
        match verb {
            "show" => match self.read_house_rules() {
                Some(text) if !text.trim().is_empty() => {
                    self.log("tune", "house rules:".to_string());
                    for line in text.lines().take(40) {
                        self.log("tune", line.to_string());
                    }
                }
                _ => self.log("tune", "no house rules set"),
            },
            "set" => {
                if rest.is_empty() {
                    self.log(
                        "tune",
                        "set requires a quoted value: tune set \"focus on auth\"",
                    );
                    return;
                }
                let value = rest
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or(rest);
                let Some(path) = self.house_rules_path() else {
                    self.log(
                        "tune",
                        "tune set requires a focused module and a workspace target",
                    );
                    return;
                };
                if let Some(parent) = path.parent() {
                    if let Err(error) = std::fs::create_dir_all(parent) {
                        self.log(
                            "error",
                            format!("could not create {}: {error}", parent.display()),
                        );
                        return;
                    }
                }
                match std::fs::write(&path, value) {
                    Ok(_) => self.log(
                        "tune",
                        format!("wrote {} ({} bytes)", path.display(), value.len()),
                    ),
                    Err(error) => self.log(
                        "error",
                        format!("could not write {}: {error}", path.display()),
                    ),
                }
            }
            "reset" => {
                let Some(path) = self.house_rules_path() else {
                    self.log("tune", "tune reset requires a focused module and workspace");
                    return;
                };
                if !path.exists() {
                    self.log("tune", format!("no house rules at {}", path.display()));
                    return;
                }
                match std::fs::remove_file(&path) {
                    Ok(_) => self.log("tune", format!("removed {}", path.display())),
                    Err(error) => self.log(
                        "error",
                        format!("could not remove {}: {error}", path.display()),
                    ),
                }
            }
            other => self.log(
                "tune",
                format!("unknown tune verb {other:?}; try show/set/reset"),
            ),
        }
    }

    pub fn handle_prompt_verb(&mut self, raw: &str) {
        let raw = raw.trim();
        if raw.is_empty() {
            self.log(
                "prompt",
                "verbs: edit <name> | show <name> | diff <name> | reset <name> | set <name> \"value\"",
            );
            return;
        }
        let mut parts = raw.splitn(2, char::is_whitespace);
        let verb = parts.next().unwrap_or("");
        let rest = parts.next().unwrap_or("").trim();
        match verb {
            "edit" => self.prompt_edit(rest),
            "show" => self.prompt_show(rest),
            "diff" => self.prompt_diff(rest),
            "reset" => self.prompt_reset(rest),
            "set" => self.prompt_set(rest),
            "list" => self.prompt_list(),
            other => self.log(
                "prompt",
                format!("unknown prompt verb {other:?}; try edit/show/diff/reset/set/list"),
            ),
        }
    }

    fn prompt_path_for(&self, name: &str) -> Option<PathBuf> {
        let module = self.focused_module.as_ref()?;
        let target = self.target.clone()?;
        let safe = name.trim().replace(['/', '\\'], "");
        if safe.is_empty() {
            return None;
        }
        Some(
            target
                .join(".kuzushi")
                .join("prompts")
                .join(module)
                .join(format!("{safe}.md")),
        )
    }

    fn prompt_edit(&mut self, name: &str) {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt edit requires a focused module and a workspace target. Next: /use <module>, then prompt edit <name>",
            );
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                self.log(
                    "error",
                    format!("could not create {}: {error}", parent.display()),
                );
                return;
            }
        }
        if !path.exists() {
            if let Err(error) = std::fs::write(&path, "") {
                self.log(
                    "error",
                    format!("could not seed {}: {error}", path.display()),
                );
                return;
            }
        }
        let editor = std::env::var("EDITOR").unwrap_or_else(|_| "${EDITOR}".to_string());
        self.log(
            "prompt",
            format!(
                "edit override at {}; suspend the shell and run `{editor} {0}` (Ctrl+C twice to exit when done)",
                path.display()
            ),
        );
    }

    fn prompt_show(&mut self, name: &str) {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt show requires a focused module and workspace. Next: /use <module>",
            );
            return;
        };
        match std::fs::read_to_string(&path) {
            Ok(text) if text.trim().is_empty() => {
                self.log(
                    "prompt",
                    format!("override {} is empty (using default)", path.display()),
                );
            }
            Ok(text) => {
                self.log(
                    "prompt",
                    format!("override {} ({} bytes):", path.display(), text.len()),
                );
                for line in text.lines().take(40) {
                    self.log("prompt", line.to_string());
                }
            }
            Err(_) => {
                self.log(
                    "prompt",
                    format!("no override at {}; using built-in default", path.display()),
                );
            }
        }
    }

    fn prompt_diff(&mut self, name: &str) {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt diff requires a focused module and workspace",
            );
            return;
        };
        if path.exists() {
            self.log(
                "prompt",
                format!("diff candidate: git diff -- {}", path.display()),
            );
        } else {
            self.log(
                "prompt",
                format!("no override file to diff at {}", path.display()),
            );
        }
    }

    fn prompt_reset(&mut self, name: &str) {
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt reset requires a focused module and workspace",
            );
            return;
        };
        if !path.exists() {
            self.log(
                "prompt",
                format!("no override at {} to reset", path.display()),
            );
            return;
        }
        match std::fs::remove_file(&path) {
            Ok(_) => self.log("prompt", format!("removed override {}", path.display())),
            Err(error) => self.log(
                "error",
                format!("could not remove {}: {error}", path.display()),
            ),
        }
    }

    fn prompt_set(&mut self, args: &str) {
        let mut parts = args.splitn(2, char::is_whitespace);
        let name = parts.next().unwrap_or("").trim();
        let value = parts.next().unwrap_or("").trim();
        if name.is_empty() || value.is_empty() {
            self.log(
                "prompt",
                "set requires a name and quoted value: prompt set triage \"focus on auth\"",
            );
            return;
        }
        // Strip outer quotes if present.
        let value = value
            .strip_prefix('"')
            .and_then(|stripped| stripped.strip_suffix('"'))
            .unwrap_or(value);
        let Some(path) = self.prompt_path_for(name) else {
            self.log(
                "prompt",
                "prompt set requires a focused module and workspace",
            );
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                self.log(
                    "error",
                    format!("could not create {}: {error}", parent.display()),
                );
                return;
            }
        }
        match std::fs::write(&path, value) {
            Ok(_) => self.log(
                "prompt",
                format!("wrote {} ({} bytes)", path.display(), value.len()),
            ),
            Err(error) => self.log(
                "error",
                format!("could not write {}: {error}", path.display()),
            ),
        }
    }

    fn prompt_list(&mut self) {
        let Some(module) = self.focused_module.clone() else {
            self.log(
                "prompt",
                "list requires a focused module. Next: /use <module>",
            );
            return;
        };
        let Some(target) = self.target.clone() else {
            self.log("prompt", "list requires a workspace target");
            return;
        };
        let dir = target.join(".kuzushi").join("prompts").join(&module);
        match std::fs::read_dir(&dir) {
            Ok(entries) => {
                let mut names: Vec<String> = entries
                    .flatten()
                    .filter_map(|entry| {
                        entry
                            .file_name()
                            .into_string()
                            .ok()
                            .and_then(|name| name.strip_suffix(".md").map(str::to_string))
                    })
                    .collect();
                names.sort();
                if names.is_empty() {
                    self.log("prompt", format!("no overrides in {}", dir.display()));
                } else {
                    self.log("prompt", format!("overrides in {}:", dir.display()));
                    for name in names {
                        self.log("prompt", format!("  - {name}"));
                    }
                }
            }
            Err(_) => self.log(
                "prompt",
                format!("no override directory at {}", dir.display()),
            ),
        }
    }

    pub fn show_quickstart(&mut self) {
        self.shell_view = ShellView::Help;
        let lines = [
            "Welcome to kuzushi! Quickstart:",
            "  1. /target <path>           — point the shell at a repo",
            "  2. /model openai:gpt-5.5    — pick a provider/model",
            "  3. /scan ./repo             — run configured scanners",
            "  4. /findings                — browse persisted findings",
            "  5. /threats                 — review or regenerate the threat model",
            "  6. /plan <english>          — Haiku-driven natural-language plans",
            "Press Ctrl+O to toggle the live event timeline.",
        ];
        for line in lines {
            self.log("quickstart", line);
        }
    }

    pub fn handle_target_command(&mut self, raw: Option<&str>) {
        let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
            let current = self
                .target
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<unset>".to_string());
            self.log("target", format!("current target: {current}"));
            return;
        };
        let path = PathBuf::from(raw);
        match WorkspaceTarget::new(&path) {
            Ok(workspace) => {
                let root = workspace.root().to_path_buf();
                self.target = Some(root.clone());
                if let Err(error) = workspace.ensure_state_dir() {
                    self.log(
                        "target",
                        format!("set {} but state dir init failed: {error}", root.display()),
                    );
                } else {
                    self.log("target", format!("set {}", root.display()));
                }
                self.refresh_findings(false);
            }
            Err(error) => self.log("error", format!("invalid target {raw:?}: {error}")),
        }
    }

    fn show_story(&mut self) {
        if matches!(self.shell_view, ShellView::Story) {
            return;
        }
        self.story_return_view = Some(self.shell_view.clone());
        self.shell_view = ShellView::Story;
    }

    pub fn toggle_story_overlay(&mut self) {
        if matches!(self.shell_view, ShellView::Story) {
            if let Some(previous) = self.story_return_view.take() {
                self.shell_view = previous;
            } else {
                self.shell_view = ShellView::Catalog;
            }
        } else {
            self.show_story();
        }
    }

    fn handle_model_command(&mut self, raw: Option<String>) {
        self.shell_view = ShellView::Config;
        let Some(raw) = raw
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        else {
            self.show_model_catalog();
            return;
        };

        let mut parts = raw.split_whitespace().collect::<Vec<_>>();
        if matches!(
            parts.first().copied(),
            Some("list") | Some("models") | Some("choices")
        ) {
            self.show_model_catalog();
            return;
        }

        let force_global = matches!(parts.first().copied(), Some("global") | Some("session"));
        let force_module = matches!(parts.first().copied(), Some("module"));
        if force_global || force_module {
            parts.remove(0);
        }

        let Some(selector) = parts.first().copied() else {
            self.show_model_catalog();
            return;
        };
        let explicit_effort = parts.get(1).copied();
        let (model, default_effort) = match resolve_model_selector(selector) {
            Some(choice) => (choice.id.to_string(), Some(choice.thinking_level)),
            None if selector.contains(':') => (selector.to_string(), None),
            None => {
                self.log(
                    "error",
                    format!(
                        "unknown model choice {selector:?}. Next: model, or model provider:model-id"
                    ),
                );
                return;
            }
        };
        if let Err(message) = validate_shell_model_id(&model) {
            self.log("error", message);
            return;
        }
        let thinking_level = match explicit_effort
            .or(default_effort)
            .map(normalize_thinking_level)
        {
            Some(Some(level)) => Some(level.to_string()),
            Some(None) => {
                self.log(
                    "error",
                    format!(
                        "unknown reasoning effort {:?}. Valid: low, medium, high, xhigh",
                        explicit_effort.unwrap_or_default()
                    ),
                );
                return;
            }
            None => None,
        };

        if force_module || (!force_global && self.focused_module.is_some()) {
            let Some(module_id) = self.focused_module.clone() else {
                self.log(
                    "error",
                    "model module requires a focused module. Next: use <module>, then model module <choice>",
                );
                return;
            };
            self.option_store.set_value(
                OptionScope::Session,
                OptionTarget::Module(module_id.clone()),
                "model",
                serde_json::json!(model.clone()),
            );
            if let Some(level) = &thinking_level {
                self.option_store.set_value(
                    OptionScope::Session,
                    OptionTarget::Module(module_id.clone()),
                    "effort",
                    serde_json::json!(level),
                );
            }
            self.log(
                "model",
                format!(
                    "module {module_id} uses {}{} via pi-agent-core (session only)",
                    model,
                    thinking_level
                        .as_deref()
                        .map(|level| format!(" / {level}"))
                        .unwrap_or_default()
                ),
            );
            return;
        }

        self.config.model = Some(model.clone());
        self.session_thinking_level = thinking_level.clone();
        self.sync_selected_model_index();
        self.log(
            "model",
            format!(
                "{model}{} via pi-agent-core (session only; no fallback model will be selected)",
                thinking_level
                    .as_deref()
                    .map(|level| format!(" / {level}"))
                    .unwrap_or_default()
            ),
        );
    }

    fn show_model_catalog(&mut self) {
        self.shell_view = ShellView::Config;
        self.sync_selected_model_index();
        let active = self
            .config
            .model
            .clone()
            .unwrap_or_else(|| "unconfigured".to_string());
        let effort = self.session_thinking_level.as_deref().unwrap_or("default");
        self.log(
            "model",
            format!("active {active} / {effort}. Select with: model <n> [low|medium|high|xhigh]"),
        );
        for choice in MODEL_CHOICES {
            self.log(
                "model",
                format!(
                    "{}. {}  {}  {}  auth {}",
                    choice.index, choice.id, choice.thinking_level, choice.label, choice.auth
                ),
            );
        }
        if self.focused_module.is_some() {
            self.log(
                "model",
                "focused module detected: model <n> sets this module; use model global <n> for global ask/defaults",
            );
        }
    }

    fn show_auth_status(&mut self) {
        self.shell_view = ShellView::Config;
        let api_key_env = self.config.runtime.api_key_env.as_str();
        let env_status = if env::var_os(api_key_env).is_some() {
            "set"
        } else {
            "missing"
        };
        let anthropic_env = if env::var_os("ANTHROPIC_API_KEY").is_some() {
            "set"
        } else {
            "missing"
        };
        self.log(
            "auth",
            format!(
                "pi-agent-core auth: {api_key_env}={env_status}; ANTHROPIC_API_KEY={anthropic_env}; openai-codex oauth {}; anthropic oauth {}; secret values hidden. Next: auth login openai-codex or auth login anthropic",
                oauth_provider_status("openai-codex"),
                oauth_provider_status("anthropic")
            ),
        );
    }

    fn handle_auth_login_command(&mut self, provider: Option<String>) {
        self.shell_view = ShellView::Config;
        let provider = match normalize_auth_provider(provider.as_deref().unwrap_or("openai-codex"))
        {
            Ok(provider) => provider,
            Err(message) => {
                self.log("error", message);
                return;
            }
        };
        self.log("auth", format!("starting {provider} OAuth login"));

        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let command = match PiAgentCoreRuntime::from_config(&self.config, &cwd) {
            Ok(runtime) => runtime.command().to_vec(),
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let Some(program) = command.first() else {
            self.log("error", "pi-agent-core bridge command is empty");
            return;
        };

        let raw_mode_was_disabled = disable_raw_mode().is_ok();
        let status = ProcessCommand::new(program)
            .args(&command[1..])
            .arg("--oauth-login")
            .arg(provider)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
        if raw_mode_was_disabled {
            let _ = enable_raw_mode();
        }

        match status {
            Ok(status) if status.success() => self.log(
                "auth",
                format!(
                    "{provider} OAuth stored at {}. Next: model {}",
                    oauth_credentials_path()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|| "~/.kuzushi/oauth-credentials.json".to_string()),
                    if provider == "anthropic" { "5" } else { "3" }
                ),
            ),
            Ok(status) => self.log(
                "error",
                format!("{provider} OAuth login exited with {status}. Next: auth status"),
            ),
            Err(error) => self.log(
                "error",
                format!("could not start {provider} OAuth login: {error}. Next: auth status"),
            ),
        }
    }

    fn handle_provider_command(&mut self, provider: Option<String>) {
        self.shell_view = ShellView::Config;
        if let Some(provider) = provider {
            let provider = provider.trim();
            if provider.is_empty() || provider.contains(':') {
                self.log(
                    "error",
                    "provider expects only the provider prefix. Next: model 1, model 5, or model provider:model-id",
                );
                return;
            }
            self.log(
                "provider",
                format!(
                    "{provider} requested. Rust uses pi-agent-core only; providers are selected through explicit model ids. Next: model {provider}:<model-id>"
                ),
            );
            return;
        }

        self.log(
            "provider",
            format!(
                "{} via pi-agent-core. Supported selectors: openai, openai-codex, anthropic. Next: model",
                self.provider_label()
            ),
        );
    }

    fn handle_backend_command(&mut self, backend: Option<String>) {
        self.shell_view = ShellView::Config;
        if let Some(backend) = backend {
            let normalized = backend.trim().to_ascii_lowercase();
            if normalized == "pi-agent-core" || normalized == "pi_agent_core" {
                self.log("backend", "pi-agent-core already selected");
            } else {
                self.log(
                    "error",
                    format!(
                        "unsupported Rust backend {backend:?}. Supported: pi-agent-core. Next: backend pi-agent-core"
                    ),
                );
            }
            return;
        }

        self.log(
            "backend",
            format!(
                "{}; bridge {}",
                runtime_backend_label(&self.config),
                bridge_command_status(&self.config)
            ),
        );
    }

    fn show_cost_status(&mut self) {
        self.shell_view = ShellView::Config;
        let message = if let Some(last) = self.last_tool_cost_usd {
            format!(
                "session estimate ${:.4}; last tool ${:.4}. Scanner-only work may report no LLM cost.",
                self.session_cost_usd, last
            )
        } else {
            "cost unavailable until a Rust tool reports costUsd; scanner-only work may report no LLM cost. Next: run <tool>"
                .to_string()
        };
        self.log("cost", message);
    }

    pub(crate) fn provider_label(&self) -> String {
        self.config
            .model
            .as_deref()
            .and_then(|model| model.split_once(':').map(|(provider, _)| provider))
            .filter(|provider| !provider.trim().is_empty())
            .unwrap_or("unconfigured")
            .to_string()
    }

    fn sync_selected_model_index(&mut self) {
        self.selected_model_index = preferred_model_choice_index(&self.config);
    }

    fn move_model_selection(&mut self, delta: isize) {
        let len = MODEL_CHOICES.len();
        if len == 0 {
            self.selected_model_index = 0;
            return;
        }
        let current = self.selected_model_index.min(len - 1) as isize;
        self.selected_model_index = (current + delta).rem_euclid(len as isize) as usize;
    }

    fn select_current_model_choice(&mut self) {
        let Some(choice) = MODEL_CHOICES.get(self.selected_model_index) else {
            self.log("error", "no model choices are available");
            return;
        };
        self.config.model = Some(choice.id.to_string());
        self.session_thinking_level = Some(choice.thinking_level.to_string());
        self.shell_view = ShellView::Config;
        self.log(
            "model",
            format!(
                "{} / {} selected via onboarding (session only; no fallback model will be selected)",
                choice.id, choice.thinking_level
            ),
        );
    }

    fn show_workspace_status(&mut self) {
        self.workspace_view = self.build_workspace_view(None);
        self.shell_view = ShellView::Workspace;
        self.focused_module = Some("workspace".to_string());
        self.log("workspace", self.workspace_view.status.clone());
    }

    fn export_workspace_findings(&mut self, output: &PathBuf) {
        let workspace = match self.explicit_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.workspace_view = self.build_workspace_view(None);
                self.shell_view = ShellView::Workspace;
                self.log("error", error.to_string());
                return;
            }
        };
        let output = if output.is_absolute() {
            output.clone()
        } else {
            workspace.root().join(output)
        };

        match export_workspace_findings(&workspace, &output, None) {
            Ok(report) => {
                self.workspace_view = self.build_workspace_view(Some(report.output_path.clone()));
                self.shell_view = ShellView::Workspace;
                self.focused_module = Some("workspace".to_string());
                self.log(
                    "export",
                    format!(
                        "wrote {} finding(s) to {} ({})",
                        report.count,
                        report.output_path.display(),
                        report.format.as_str()
                    ),
                );
            }
            Err(error) => {
                self.workspace_view = self.build_workspace_view(None);
                self.shell_view = ShellView::Workspace;
                self.log(
                    "error",
                    format!("{error}. Next: workspace export findings findings.json"),
                );
            }
        }
    }

    fn build_workspace_view(&self, last_export: Option<PathBuf>) -> WorkspaceView {
        let Some(target) = self.target.clone() else {
            return WorkspaceView {
                root: None,
                state_dir: None,
                findings_db: None,
                findings_count: None,
                last_export,
                status: "no active workspace. Next: scan <target> or start shell with --target ."
                    .to_string(),
            };
        };

        match WorkspaceTarget::new(&target) {
            Ok(workspace) => {
                let findings_db = workspace.findings_db_path();
                let findings_count = if findings_db.exists() {
                    FindingStore::open(&findings_db)
                        .and_then(|store| store.list_findings(FindingListFilter::MAX_LIMIT))
                        .map(|findings| findings.len())
                        .ok()
                } else {
                    Some(0)
                };
                let count_label = findings_count
                    .map(|count| count.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                WorkspaceView {
                    root: Some(workspace.root().to_path_buf()),
                    state_dir: Some(workspace.state_dir()),
                    findings_db: Some(findings_db),
                    findings_count,
                    last_export,
                    status: format!(
                        "workspace ready; {count_label} finding(s). Next: workspace export findings findings.json"
                    ),
                }
            }
            Err(error) => WorkspaceView {
                root: None,
                state_dir: None,
                findings_db: None,
                findings_count: None,
                last_export,
                status: format!("{error}. Next: scan <target>"),
            },
        }
    }

    fn show_context_status(&mut self) {
        match self.refresh_context_view() {
            Ok(()) => {
                self.focused_module = Some("context".to_string());
                self.shell_view = ShellView::Context;
                self.log("context", self.context_view.status.clone());
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    fn build_context_snapshot(&mut self, scope: Option<&str>) {
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        self.target = Some(workspace.root().to_path_buf());

        let mut input = serde_json::Map::new();
        if let Some(scope) = scope {
            input.insert("scope".to_string(), serde_json::json!(scope));
        }
        let input = match self.registry.prepare_tool_input(
            "context:build",
            serde_json::Value::Object(input),
            Some(&self.option_store),
        ) {
            Ok(input) => input,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let ctx = ToolExecutionContext {
            config: &self.config,
            workspace: Some(&workspace),
            findings_store: None,
        };
        match self.registry.execute_tool("context:build", input, &ctx) {
            Ok(result) => {
                let rendered = result
                    .get("output")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("context:build complete")
                    .to_string();
                let _ = self.refresh_context_view();
                self.focused_module = Some("context".to_string());
                self.shell_view = ShellView::Context;
                self.log("result", rendered);
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    fn regen_context_slice(&mut self, slice: &str) {
        match slice {
            "all" | "repo" | "app-model" => self.build_context_snapshot(Some(slice)),
            "enrichment" => self.log(
                "error",
                "context regen enrichment is not supported by the native Rust context builder yet. Next: context build",
            ),
            other => self.log(
                "error",
                format!(
                    "unknown context slice {other:?}. Valid slices: all, repo, app-model. Next: context regen repo"
                ),
            ),
        }
    }

    fn refresh_context_view(&mut self) -> Result<()> {
        let workspace = self.current_workspace()?;
        let snapshot_path = workspace.root().join(".kuzushi/context-snapshot.json");
        self.context_view = load_context_snapshot_view(snapshot_path)?;
        Ok(())
    }

    fn show_sast_tasks(&mut self) {
        if self.registry.resolve_tool("sast:scan").is_none() {
            self.log("error", "SAST module is not loaded. Next: modules");
            return;
        }
        self.focused_module = Some("sast".to_string());
        self.shell_view = ShellView::SastTasks;
        self.log("tasks", self.sast_task_summary_line());
    }

    fn show_kb(&mut self, module: Option<String>) {
        let module_id = match self.resolve_kb_module(module) {
            Ok(module_id) => module_id,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        match self.refresh_kb_view(&module_id) {
            Ok(()) => {
                self.focused_module = Some(module_id.clone());
                self.shell_view = ShellView::KnowledgeBase;
                self.log(
                    "kb",
                    format!(
                        "{} attachment(s) for {module_id}. Next: attach <path-or-url>",
                        self.kb_view
                            .attachments
                            .iter()
                            .filter(|record| record.module_id == module_id)
                            .count()
                    ),
                );
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    fn attach_kb_source(&mut self, source: &str) {
        let module_id = match self.resolve_kb_module(None) {
            Ok(module_id) => module_id,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        match attach_source(&workspace, &module_id, source) {
            Ok(record) => {
                let _ = self.refresh_kb_view(&module_id);
                self.focused_module = Some(module_id);
                self.shell_view = ShellView::KnowledgeBase;
                self.log(
                    "attach",
                    format!(
                        "{} {} ({})",
                        record.id,
                        record.source,
                        if record.metadata_only {
                            "metadata-only"
                        } else {
                            "local"
                        }
                    ),
                );
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    fn detach_kb_source(&mut self, id: &str) {
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        match detach_source(&workspace, id) {
            Ok(record) => {
                let module_id = record.module_id.clone();
                let _ = self.refresh_kb_view(&module_id);
                self.focused_module = Some(module_id);
                self.shell_view = ShellView::KnowledgeBase;
                self.log("detach", format!("removed {} {}", record.id, record.source));
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    fn reparse_kb_source(&mut self, id: &str) {
        let workspace = match self.current_workspace() {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        match reparse_source(&workspace, id) {
            Ok(record) => {
                let module_id = record.module_id.clone();
                let _ = self.refresh_kb_view(&module_id);
                self.focused_module = Some(module_id);
                self.shell_view = ShellView::KnowledgeBase;
                self.log("reparse", format!("{} {}", record.id, record.status));
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    fn refresh_kb_view(&mut self, module_id: &str) -> Result<()> {
        let workspace = self.current_workspace()?;
        let attachments = list_attachments(&workspace)?;
        let artifacts = known_artifacts(&workspace, module_id)?;
        self.kb_view = KnowledgeBaseView {
            module_id: module_id.to_string(),
            store_path: Some(attachment_store_path(&workspace)),
            attachments,
            artifacts,
        };
        Ok(())
    }

    fn resolve_kb_module(&self, requested: Option<String>) -> Result<String> {
        if let Some(module_id) = requested {
            let module_id = normalize_kb_module_id(&module_id);
            if is_supported_attachment_module(&module_id) {
                return Ok(module_id);
            }
            anyhow::bail!("{}", unknown_kb_module_message(&module_id));
        }

        if let Some(module_id) = self
            .focused_module
            .as_deref()
            .map(normalize_kb_module_id)
            .filter(|module_id| is_supported_attachment_module(module_id))
        {
            return Ok(module_id);
        }

        if is_supported_attachment_module(&self.kb_view.module_id) {
            return Ok(self.kb_view.module_id.clone());
        }

        Ok("context".to_string())
    }

    fn handle_sast_task_command(&mut self, command: SastTaskCommand) {
        if self.registry.resolve_tool("sast:scan").is_none() {
            self.log("error", "SAST module is not loaded. Next: modules");
            return;
        }

        let result = match command {
            SastTaskCommand::Block(raw_id) => self.block_sast_task(&raw_id),
            SastTaskCommand::Allow(raw_id) => self.allow_sast_task(&raw_id),
            SastTaskCommand::Toggle(raw_id) => {
                let raw_id = raw_id.unwrap_or_else(|| {
                    self.sast_task_rows()
                        .into_iter()
                        .find(|row| row.toggleable)
                        .map(|row| row.id.to_string())
                        .unwrap_or_else(|| "semgrep".to_string())
                });
                self.toggle_sast_task(&raw_id)
            }
            SastTaskCommand::Mode(mode) => self.set_sast_task_mode(mode),
            SastTaskCommand::Reset => self.reset_sast_tasks(),
        };

        self.shell_view = ShellView::SastTasks;
        self.focused_module = Some("sast".to_string());
        match result {
            Ok(message) => self.log("tasks", message),
            Err(error) => self.log("error", error.to_string()),
        }
    }

    fn block_sast_task(&mut self, raw_id: &str) -> Result<String> {
        let task = resolve_sast_task(raw_id).with_context(|| unknown_sast_task_message(raw_id))?;
        let mut disabled = self.current_disabled_sast_tasks();
        disabled.insert(task.id.to_string());
        self.write_sast_task_list_option("disabledTasks", disabled.into_iter().collect());

        let mut manual = self.current_manual_sast_tasks();
        manual.remove(task.id);
        self.write_sast_task_list_option("tasks", manual.into_iter().collect());

        Ok(format!(
            "Blocked SAST task capability: {}. {}",
            task.id,
            self.sast_task_summary_line()
        ))
    }

    fn allow_sast_task(&mut self, raw_id: &str) -> Result<String> {
        let task = resolve_sast_task(raw_id).with_context(|| unknown_sast_task_message(raw_id))?;
        let mut disabled = self.current_disabled_sast_tasks();
        disabled.remove(task.id);
        self.write_sast_task_list_option("disabledTasks", disabled.into_iter().collect());

        if self.current_sast_task_mode() == SastTaskMode::Manual {
            let mut manual = self.current_manual_sast_tasks();
            manual.insert(task.id.to_string());
            self.write_sast_task_list_option("tasks", manual.into_iter().collect());
        }

        Ok(format!(
            "Allowed SAST task capability: {}. {}",
            task.id,
            self.sast_task_summary_line()
        ))
    }

    fn toggle_sast_task(&mut self, raw_id: &str) -> Result<String> {
        let task = resolve_sast_task(raw_id).with_context(|| unknown_sast_task_message(raw_id))?;
        let disabled = self.current_disabled_sast_tasks();
        let manual = self.current_manual_sast_tasks();
        if disabled.contains(task.id)
            || (self.current_sast_task_mode() == SastTaskMode::Manual && !manual.contains(task.id))
        {
            self.allow_sast_task(task.id)
        } else {
            self.block_sast_task(task.id)
        }
    }

    fn set_sast_task_mode(&mut self, mode: SastTaskModeCommand) -> Result<String> {
        let next_mode = match mode {
            SastTaskModeCommand::Auto => SastTaskMode::Auto,
            SastTaskModeCommand::Manual => SastTaskMode::Manual,
            SastTaskModeCommand::Toggle => match self.current_sast_task_mode() {
                SastTaskMode::Auto => SastTaskMode::Manual,
                SastTaskMode::Manual => SastTaskMode::Auto,
            },
        };

        match next_mode {
            SastTaskMode::Auto => {
                self.option_store.set_value(
                    OptionScope::Session,
                    OptionTarget::Tool("sast:scan".to_string()),
                    "taskMode",
                    serde_json::json!("auto"),
                );
                self.option_store.unset_value(
                    OptionScope::Session,
                    &OptionTarget::Tool("sast:scan".to_string()),
                    "tasks",
                );
            }
            SastTaskMode::Manual => {
                let manual = self.manual_tasks_or_current_auto_selection();
                if manual.is_empty() {
                    anyhow::bail!(
                        "manual SAST task mode needs at least one task. Valid task IDs: {}",
                        valid_sast_task_ids().join(", ")
                    );
                }
                self.option_store.set_value(
                    OptionScope::Session,
                    OptionTarget::Tool("sast:scan".to_string()),
                    "taskMode",
                    serde_json::json!("manual"),
                );
                self.write_sast_task_list_option("tasks", manual);
            }
        }

        Ok(format!(
            "SAST task mode: {}. {}",
            match next_mode {
                SastTaskMode::Auto => "auto + denylist",
                SastTaskMode::Manual => "manual allowlist",
            },
            self.sast_task_summary_line()
        ))
    }

    fn reset_sast_tasks(&mut self) -> Result<String> {
        let target = OptionTarget::Tool("sast:scan".to_string());
        for key in ["taskMode", "tasks", "disabledTasks"] {
            self.option_store
                .unset_value(OptionScope::Session, &target, key);
        }
        Ok(format!(
            "SAST task selection reset. {}",
            self.sast_task_summary_line()
        ))
    }

    fn show_options(&mut self, tool: Option<String>, filter: OptionsFilter) {
        let tool_name = match self.resolve_options_tool(tool) {
            Ok(tool_name) => tool_name,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };

        self.shell_view = ShellView::Options(OptionsView {
            tool_name: tool_name.clone(),
            filter,
        });
        self.log(
            "options",
            format!("showing {} for {tool_name}", options_filter_label(filter)),
        );
    }

    fn set_option(&mut self, global: bool, name: &str, value: &str) {
        let tool_name = match self.resolve_options_tool(None) {
            Ok(tool_name) => tool_name,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let Some(tool) = self.registry.resolve_tool(&tool_name) else {
            self.log("error", format!("unknown tool {tool_name:?}. Next: tools"));
            return;
        };
        let Some(spec) = find_option_spec(tool, name) else {
            self.log("error", unknown_option_message(tool, name));
            return;
        };
        let canonical_name = spec.name.clone();
        let value = match coerce_raw_option_value(spec, value) {
            Ok(value) => value,
            Err(error) => {
                self.log(
                    "error",
                    format!(
                        "invalid value for {tool_name}.{canonical_name}: {error}. Next: show options {tool_name}"
                    ),
                );
                return;
            }
        };

        let (scope, target, prefix) = if global {
            (OptionScope::Global, OptionTarget::All, "setg")
        } else {
            (
                OptionScope::Session,
                OptionTarget::Tool(tool_name.clone()),
                "set",
            )
        };
        self.option_store
            .set_value(scope, target, canonical_name.clone(), value.clone());
        let filter = self.current_options_filter();
        self.shell_view = ShellView::Options(OptionsView {
            tool_name: tool_name.clone(),
            filter,
        });
        self.log(
            prefix,
            format!(
                "{tool_name}.{canonical_name} = {}",
                format_option_value(&value)
            ),
        );
    }

    fn unset_option(&mut self, global: bool, name: &str) {
        let tool_name = match self.resolve_options_tool(None) {
            Ok(tool_name) => tool_name,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let Some(tool) = self.registry.resolve_tool(&tool_name) else {
            self.log("error", format!("unknown tool {tool_name:?}. Next: tools"));
            return;
        };
        let Some(spec) = find_option_spec(tool, name) else {
            self.log("error", unknown_option_message(tool, name));
            return;
        };

        let (scope, target, prefix) = if global {
            (OptionScope::Global, OptionTarget::All, "unsetg")
        } else {
            (
                OptionScope::Session,
                OptionTarget::Tool(tool_name.clone()),
                "unset",
            )
        };
        let removed = self.option_store.unset_value(scope, &target, &spec.name);
        let filter = self.current_options_filter();
        self.shell_view = ShellView::Options(OptionsView {
            tool_name: tool_name.clone(),
            filter,
        });
        self.log(
            prefix,
            if removed {
                format!("{tool_name}.{} cleared", spec.name)
            } else {
                format!(
                    "{tool_name}.{} was not set. Next: show options {tool_name}",
                    spec.name
                )
            },
        );
    }

    fn resolve_options_tool(&self, requested: Option<String>) -> Result<String> {
        if let Some(tool_name) = requested {
            let resolved = self.resolve_focused_tool_name(tool_name.clone());
            if self.registry.resolve_tool(&resolved).is_some() {
                return Ok(resolved);
            }
            if self.registry.resolve_tool(&tool_name).is_some() {
                return Ok(tool_name);
            }
            anyhow::bail!("unknown tool {tool_name:?}. Next: tools");
        }

        if let ShellView::Options(view) = &self.shell_view {
            return Ok(view.tool_name.clone());
        }
        if let Some(tool_name) = self.default_tool_for_focused_module() {
            return Ok(tool_name);
        }
        if self.registry.resolve_tool("sast:scan").is_some() {
            return Ok("sast:scan".to_string());
        }
        self.registry
            .tools()
            .next()
            .map(|tool| tool.name.clone())
            .context("no tools are loaded. Next: modules")
    }

    fn current_options_filter(&self) -> OptionsFilter {
        match &self.shell_view {
            ShellView::Options(view) => view.filter,
            _ => OptionsFilter::Standard,
        }
    }

    fn start_scan(&mut self, target: Option<PathBuf>) {
        if self.scan.as_ref().is_some_and(|scan| scan.running) {
            self.log("scan", "scan already running");
            return;
        }

        let target_path = target
            .or_else(|| self.target.clone())
            .unwrap_or_else(|| PathBuf::from("."));
        let workspace = match WorkspaceTarget::new(&target_path) {
            Ok(workspace) => workspace,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let scan_options = match self.scan_options_from_store() {
            Ok(options) => options,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let target_root = workspace.root().to_path_buf();
        let db_path = workspace.findings_db_path();
        let (tx, rx) = mpsc::channel();
        let cancel = ScanCancellation::default();

        self.target = Some(target_root.clone());
        self.scan = Some(ScanPanelState {
            run_id: None,
            target: target_root.clone(),
            stage: "queued".to_string(),
            findings_count: 0,
            running: true,
            error: None,
        });
        self.scan_rx = Some(rx);
        self.scan_cancel = Some(cancel.clone());
        self.findings.clear();
        self.selected_finding = None;
        self.shell_view = ShellView::ModuleRun;
        self.log("scan", format!("starting {}", target_root.display()));

        thread::spawn(move || scan_worker(target_root, db_path, tx, cancel, scan_options));
    }

    fn scan_options_from_store(&self) -> Result<ScanRunOptions> {
        let input = self.registry.prepare_tool_input(
            "sast:scan",
            serde_json::json!({}),
            Some(&self.option_store),
        )?;
        Ok(ScanRunOptions {
            severity: parse_scan_severity_filter(&input)?,
            tasks: parse_native_scan_tasks(&input)?,
        })
    }

    pub(crate) fn sast_task_rows(&self) -> Vec<SastTaskRow> {
        let mode = self.current_sast_task_mode();
        let disabled = self.current_disabled_sast_tasks();
        let manual = self.current_manual_sast_tasks();

        SAST_TASK_CAPABILITIES
            .iter()
            .map(|task| {
                let blocked = disabled.contains(task.id);
                let selected = if blocked {
                    false
                } else if mode == SastTaskMode::Manual {
                    manual.contains(task.id)
                } else {
                    task.default_enabled
                };
                let state = if blocked {
                    "[ ]"
                } else if selected {
                    "[x]"
                } else {
                    "[A]"
                };
                let source = if blocked {
                    "blocked"
                } else if mode == SastTaskMode::Manual {
                    "manual"
                } else if task.default_enabled {
                    "default"
                } else {
                    "available"
                };
                SastTaskRow {
                    id: task.id,
                    scan_task: task.scan_task,
                    cost: task.cost,
                    notes: task.notes,
                    toggleable: task.toggleable,
                    selected,
                    state,
                    source,
                }
            })
            .collect()
    }

    fn sast_task_summary_line(&self) -> String {
        let rows = self.sast_task_rows();
        let enabled = rows.iter().filter(|row| row.selected).count();
        let blocked = rows.iter().filter(|row| row.source == "blocked").count();
        let mode = match self.current_sast_task_mode() {
            SastTaskMode::Auto => "auto + denylist",
            SastTaskMode::Manual => "manual allowlist",
        };
        format!(
            "{mode}; {enabled}/{} enabled; {blocked} blocked. Next: /task toggle <id> or /scan",
            rows.len()
        )
    }

    fn current_sast_task_mode(&self) -> SastTaskMode {
        let values = self.option_store.effective_stored_values("sast:scan");
        match values.get("taskMode").and_then(serde_json::Value::as_str) {
            Some("manual") => SastTaskMode::Manual,
            _ => SastTaskMode::Auto,
        }
    }

    fn current_disabled_sast_tasks(&self) -> BTreeSet<String> {
        let values = self.option_store.effective_stored_values("sast:scan");
        read_task_list_value(values.get("disabledTasks"))
            .into_iter()
            .filter_map(|task| resolve_sast_task(&task).map(|task| task.id.to_string()))
            .collect()
    }

    fn current_manual_sast_tasks(&self) -> BTreeSet<String> {
        let values = self.option_store.effective_stored_values("sast:scan");
        read_task_list_value(values.get("tasks"))
            .into_iter()
            .filter_map(|task| resolve_sast_task(&task).map(|task| task.id.to_string()))
            .collect()
    }

    fn manual_tasks_or_current_auto_selection(&self) -> Vec<String> {
        let manual = self.current_manual_sast_tasks();
        if !manual.is_empty() {
            return manual.into_iter().collect();
        }

        let disabled = self.current_disabled_sast_tasks();
        SAST_TASK_CAPABILITIES
            .iter()
            .filter(|task| task.default_enabled && !disabled.contains(task.id))
            .map(|task| task.id.to_string())
            .collect()
    }

    fn write_sast_task_list_option(&mut self, name: &str, values: Vec<String>) {
        let target = OptionTarget::Tool("sast:scan".to_string());
        if values.is_empty() {
            self.option_store
                .unset_value(OptionScope::Session, &target, name);
        } else {
            self.option_store.set_value(
                OptionScope::Session,
                target,
                name,
                serde_json::Value::String(values.join(",")),
            );
        }
    }

    fn run_tool(&mut self, tool: Option<String>, input: Option<String>) {
        let tool_name = match tool {
            Some(tool) => tool,
            None => match self.default_tool_for_run_command() {
                Some(tool) => tool,
                None => {
                    self.log(
                        "error",
                        "run needs a tool, focused module, or loaded sast:scan. Next: modules or run <tool>",
                    );
                    return;
                }
            },
        };
        let tool_name = self.resolve_focused_tool_name(tool_name);

        let input = match input {
            Some(raw) if !raw.trim().is_empty() => match serde_json::from_str(&raw) {
                Ok(input) => input,
                Err(error) => {
                    self.log("error", format!("run input must be JSON: {error}"));
                    return;
                }
            },
            _ => serde_json::json!({}),
        };
        let input =
            match self
                .registry
                .prepare_tool_input(&tool_name, input, Some(&self.option_store))
            {
                Ok(input) => input,
                Err(error) => {
                    self.log("error", error.to_string());
                    return;
                }
            };

        let workspace = match self.current_workspace() {
            Ok(workspace) => Some(workspace),
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };
        let store = if tool_name.starts_with("findings:")
            || tool_name.starts_with("systems-hunt:")
            || tool_name.starts_with("chrome-rce:")
            || matches!(
                tool_name.as_str(),
                "triage:run"
                    | "verify:finding"
                    | "patch:finding"
                    | "agentic-sast:scan"
                    | "carlini-threat-hunt:run"
                    | "vuln-scout:audit"
                    | "tob:audit"
                    | "shinsa:scan"
                    | "shinsa:quick-check"
                    | "shinsa:nist-scan"
                    | "shinsa:nist-quick-check"
                    | "prompt-armor:scan"
                    | "prompt-armor:analyze"
                    | "prompt-armor:attack"
                    | "variant:lift-pattern"
                    | "variant:hunt"
                    | "ndiff:hunt-variants"
                    | "taint-iris:hunt"
                    | "taint-iris-next:hunt"
                    | "sast:scan"
                    | "semgrep:scan"
                    | "codeql:scan"
                    | "iac-scan:scan"
            ) {
            match workspace
                .as_ref()
                .map(|workspace| FindingStore::open(workspace.findings_db_path()))
                .transpose()
            {
                Ok(store) => store,
                Err(error) => {
                    self.log("error", error.to_string());
                    return;
                }
            }
        } else {
            None
        };
        self.shell_view = ShellView::ModuleRun;
        self.log("tool", format!("running {tool_name}"));

        let tool_thinking_level =
            thinking_level_from_input(&input).or_else(|| self.session_thinking_level.clone());
        let runtime = if matches!(
            tool_name.as_str(),
            "triage:run"
                | "verify:finding"
                | "patch:finding"
                | "agentic-sast:scan"
                | "carlini-threat-hunt:run"
                | "vendor-assessment:assess"
                | "vuln-scout:audit"
                | "tob:audit"
                | "shinsa:scan"
                | "shinsa:quick-check"
                | "shinsa:nist-scan"
                | "shinsa:nist-quick-check"
                | "prompt-armor:scan"
                | "prompt-armor:analyze"
                | "prompt-armor:attack"
                | "variant:lift-pattern"
                | "variant:hunt"
                | "ndiff:extract-fix-pattern"
                | "ndiff:hunt-variants"
                | "systems-hunt:systems-invariant-extract"
                | "systems-hunt:systems-trigger-synth"
                | "systems-hunt:systems-hunt"
                | "systems-hunt:deep-semantic-cwe-select"
                | "systems-hunt:deep-semantic-hunt"
                | "taint-iris:hunt"
                | "taint-iris-next:hunt"
                | "sast:scan"
                | "threat-model:build"
                | "randori:pasta"
                | "x-ray:run"
                | "x-ray:x-ray"
        ) {
            match PiAgentCoreRuntime::from_config(
                &self.config,
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            ) {
                Ok(runtime) => Some(runtime.with_thinking_level(tool_thinking_level)),
                Err(error) => {
                    self.log("error", error.to_string());
                    return;
                }
            }
        } else {
            None
        };
        let ctx = ToolExecutionContext {
            config: &self.config,
            workspace: workspace.as_ref(),
            findings_store: store.as_ref(),
        };
        match self.registry.execute_tool_with_runtime(
            &tool_name,
            input,
            &ctx,
            runtime.as_ref().map(|runtime| runtime as &dyn AgentRuntime),
        ) {
            Ok(result) => {
                if let Some(cost_usd) = extract_cost_usd(&result) {
                    self.record_cost(cost_usd);
                }
                if matches!(tool_name.as_str(), "context:build" | "context-lite:index") {
                    let _ = self.refresh_context_view();
                }
                let rendered = result
                    .get("output")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string)
                    .unwrap_or_else(|| {
                        serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
                    });
                self.log("result", rendered);
            }
            Err(error) => self.log("error", error.to_string()),
        }
    }

    fn default_tool_for_focused_module(&self) -> Option<String> {
        let module = self.focused_module.as_ref()?;
        let prefix = format!("{module}:");
        self.registry
            .tools()
            .find(|tool| tool.name.starts_with(&prefix))
            .map(|tool| tool.name.clone())
    }

    fn default_tool_for_run_command(&self) -> Option<String> {
        self.default_tool_for_focused_module().or_else(|| {
            self.registry
                .resolve_tool("sast:scan")
                .map(|_| "sast:scan".to_string())
        })
    }

    fn resolve_focused_tool_name(&self, tool_name: String) -> String {
        if tool_name.contains(':') {
            return tool_name;
        }
        let Some(module) = self.focused_module.as_ref() else {
            return tool_name;
        };
        let candidate = format!("{module}:{tool_name}");
        if self.registry.resolve_tool(&candidate).is_some() {
            candidate
        } else {
            tool_name
        }
    }

    fn show_findings(&mut self) {
        self.shell_view = ShellView::Findings;
        self.refresh_findings(true);
        if self.findings.is_empty() {
            self.log("findings", "no findings yet");
        }
    }

    fn open_finding(&mut self, reference: &str) {
        if let Some(index) = parse_chain_alias(reference) {
            let Some(chain) = self.chains.get(index) else {
                self.log(
                    "error",
                    format!(
                        "no chain alias {} is available. Next: /show aliases",
                        format_chain_alias(index)
                    ),
                );
                return;
            };
            self.log(
                "open",
                format!(
                    "chain {} ({}) — {}",
                    chain.id,
                    chain.severity.label(),
                    chain.title
                ),
            );
            return;
        }

        let reference = if let Some(index) = parse_finding_alias(reference) {
            self.refresh_findings(false);
            let Some(finding) = self.findings.get(index) else {
                self.log(
                    "error",
                    format!(
                        "no finding alias {} is available. Next: findings",
                        format_finding_alias(index)
                    ),
                );
                return;
            };
            finding.fingerprint.clone()
        } else {
            reference.to_string()
        };

        let store = match self.open_store() {
            Ok(store) => store,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };

        match store.get_finding_by_reference(&reference) {
            Ok(Some(finding)) => {
                self.selected_finding = Some(finding.clone());
                self.shell_view = ShellView::Finding;
                self.log(
                    "open",
                    format!(
                        "{} {}:{} {}",
                        finding.severity.as_str(),
                        finding.file_path,
                        finding.start_line,
                        finding.fingerprint
                    ),
                );
                self.log("title", finding.title);
                if let Some(triage) = &finding.triage {
                    self.log(
                        "triage",
                        format!(
                            "{} {:.2} {}",
                            triage.verdict.as_str(),
                            triage.confidence,
                            triage.rationale
                        ),
                    );
                }
            }
            Ok(None) => self.log("error", format!("no finding matches {reference:?}")),
            Err(error) => self.log("error", error.to_string()),
        }
    }

    fn refresh_findings(&mut self, announce: bool) {
        let store = match self.open_store() {
            Ok(store) => store,
            Err(error) => {
                if announce {
                    self.log("error", error.to_string());
                }
                return;
            }
        };

        match store.list_findings(200) {
            Ok(findings) => {
                self.findings = findings;
                if let Some(selected) = &self.selected_finding {
                    self.selected_finding = self
                        .findings
                        .iter()
                        .find(|finding| finding.fingerprint == selected.fingerprint)
                        .cloned();
                }
                if announce {
                    self.log(
                        "findings",
                        format!("loaded {} finding(s)", self.findings.len()),
                    );
                }
            }
            Err(error) => {
                if announce {
                    self.log("error", error.to_string());
                }
            }
        }
    }

    fn open_store(&mut self) -> Result<FindingStore> {
        let workspace = self.current_workspace()?;
        self.target = Some(workspace.root().to_path_buf());
        FindingStore::open(workspace.findings_db_path())
    }

    fn current_workspace(&self) -> Result<WorkspaceTarget> {
        let target = self.target.clone().unwrap_or_else(|| PathBuf::from("."));
        WorkspaceTarget::new(target)
    }

    fn explicit_workspace(&self) -> Result<WorkspaceTarget> {
        let Some(target) = self.target.clone() else {
            anyhow::bail!(
                "workspace export requires an active workspace. Next: scan <target> or start shell with --target ."
            );
        };
        WorkspaceTarget::new(target)
    }

    fn apply_scan_event(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Started { run_id, target } => {
                if let Some(scan) = &mut self.scan {
                    scan.run_id = Some(run_id.clone());
                    scan.target = target;
                    scan.stage = "starting scan".to_string();
                }
                self.log("scan", format!("run {}", short_fingerprint(&run_id)));
            }
            ScanEvent::Stage(stage) => {
                if let Some(scan) = &mut self.scan {
                    scan.stage = stage.clone();
                }
                self.log("scan", stage);
            }
            ScanEvent::FindingStored {
                fingerprint,
                severity,
                title,
            } => {
                if let Some(scan) = &mut self.scan {
                    scan.findings_count += 1;
                }
                self.log(
                    "finding",
                    format!(
                        "{} {} {}",
                        short_fingerprint(&fingerprint),
                        severity.as_str(),
                        truncate_ascii(&title, 72)
                    ),
                );
            }
            ScanEvent::Finished {
                run_id,
                findings_count,
            } => {
                if let Some(scan) = &mut self.scan {
                    scan.run_id = Some(run_id.clone());
                    scan.stage = "completed".to_string();
                    scan.findings_count = findings_count;
                    scan.running = false;
                    scan.error = None;
                }
                self.refresh_findings(false);
                self.log(
                    "scan",
                    format!(
                        "completed {} with {} finding(s)",
                        short_fingerprint(&run_id),
                        findings_count
                    ),
                );
            }
            ScanEvent::Failed { error } => {
                if let Some(scan) = &mut self.scan {
                    scan.stage = "failed".to_string();
                    scan.running = false;
                    scan.error = Some(error.clone());
                }
                self.log("error", error);
            }
            ScanEvent::Cancelled { run_id } => {
                if let Some(scan) = &mut self.scan {
                    scan.run_id = Some(run_id.clone());
                    scan.stage = "cancelled".to_string();
                    scan.running = false;
                    scan.error = None;
                }
                self.log("scan", format!("cancelled {}", short_fingerprint(&run_id)));
            }
        }
    }

    fn apply_agent_event(&mut self, event: AgentEvent) {
        match event {
            AgentEvent::Answered { text } => {
                if let Some(agent) = &mut self.agent_chat {
                    agent.running = false;
                    agent.answer = Some(text.clone());
                    agent.error = None;
                }
                self.log("answer", text);
            }
            AgentEvent::Failed { error } => {
                if let Some(agent) = &mut self.agent_chat {
                    agent.running = false;
                    agent.answer = None;
                    agent.error = Some(error.clone());
                }
                self.log("error", error);
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if self.is_budget_halted() && key.modifiers.is_empty() {
            if let KeyCode::Char(ch) = key.code {
                match ch.to_ascii_lowercase() {
                    'c' => {
                        self.continue_past_budget();
                        return;
                    }
                    'a' => {
                        self.abort_for_budget();
                        return;
                    }
                    _ => {}
                }
            }
        }

        if self.pending_plan.is_some() && self.input.is_empty() && key.modifiers.is_empty() {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.apply_pending_plan();
                    return;
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.discard_pending_plan();
                    return;
                }
                _ => {}
            }
        }

        let is_quit_chord = key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('d'));
        if !is_quit_chord {
            self.ctrl_c_armed_at = None;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('o') | KeyCode::Char('O'))
        {
            self.toggle_story_overlay();
            return;
        }

        match key.code {
            KeyCode::Char('c') | KeyCode::Char('d')
                if key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.handle_quit_chord();
            }
            KeyCode::Up
                if self.input.is_empty()
                    && key.modifiers.is_empty()
                    && matches!(self.shell_view, ShellView::Config) =>
            {
                self.move_model_selection(-1);
            }
            KeyCode::Down
                if self.input.is_empty()
                    && key.modifiers.is_empty()
                    && matches!(self.shell_view, ShellView::Config) =>
            {
                self.move_model_selection(1);
            }
            KeyCode::Enter
                if self.input.is_empty()
                    && key.modifiers.is_empty()
                    && matches!(self.shell_view, ShellView::Config) =>
            {
                self.select_current_model_choice();
            }
            KeyCode::Char(ch)
                if self.input.is_empty()
                    && key.modifiers.is_empty()
                    && self.handle_view_hotkey(ch) =>
            {
                self.last_char_at = Some(Instant::now());
            }
            KeyCode::Char(ch) => {
                self.input.push(ch);
                self.last_char_at = Some(Instant::now());
            }
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Tab => self.apply_completion(),
            KeyCode::PageDown
                if self.input.is_empty()
                    && key.modifiers.is_empty()
                    && matches!(self.shell_view, ShellView::Findings) =>
            {
                self.findings_cursor =
                    (self.findings_cursor + 10).min(self.findings.len().saturating_sub(1));
            }
            KeyCode::PageUp
                if self.input.is_empty()
                    && key.modifiers.is_empty()
                    && matches!(self.shell_view, ShellView::Findings) =>
            {
                self.findings_cursor = self.findings_cursor.saturating_sub(10);
            }
            KeyCode::Enter
                if self.input.is_empty()
                    && key.modifiers.is_empty()
                    && matches!(self.shell_view, ShellView::Findings)
                    && !self.findings.is_empty() =>
            {
                let cursor = self.findings_cursor.min(self.findings.len() - 1);
                let alias = format_finding_alias(cursor);
                self.handle_command(ShellCommand::Open(alias));
            }
            KeyCode::Enter => {
                if let Some(last) = self.last_char_at {
                    if Instant::now().duration_since(last) <= PASTE_GUARD_WINDOW {
                        // Likely paste-trailing newline; swallow.
                        self.last_char_at = None;
                        return;
                    }
                }
                let raw = std::mem::take(&mut self.input);
                self.submit_line(&raw);
                self.last_char_at = None;
            }
            KeyCode::Esc => {
                self.input.clear();
            }
            _ => {}
        }
    }

    fn handle_view_hotkey(&mut self, ch: char) -> bool {
        if matches!(self.shell_view, ShellView::Findings) && !self.findings.is_empty() {
            let max = self.findings.len().saturating_sub(1);
            match ch {
                'j' => {
                    self.findings_cursor = (self.findings_cursor + 1).min(max);
                    return true;
                }
                'k' => {
                    self.findings_cursor = self.findings_cursor.saturating_sub(1);
                    return true;
                }
                'g' => {
                    self.findings_cursor = 0;
                    return true;
                }
                'G' => {
                    self.findings_cursor = max;
                    return true;
                }
                _ => {}
            }
        }

        if matches!(self.shell_view, ShellView::Threat(_)) {
            let view = match ch {
                '1' => Some(ThreatView::Dfd),
                '2' => Some(ThreatView::Stride),
                '3' => Some(ThreatView::Stories),
                '4' => Some(ThreatView::Scope),
                '5' => Some(ThreatView::Summary),
                _ => None,
            };
            if let Some(view) = view {
                self.shell_view = ShellView::Threat(view);
                return true;
            }
        }

        if matches!(self.shell_view, ShellView::ModuleRun) {
            if let Some(index) = ch.to_digit(10).filter(|index| (1..=4).contains(index)) {
                self.shell_view = ShellView::ActorDetail(index as usize);
                return true;
            }
            match ch {
                'p' | 'P' => {
                    if self.scan.as_ref().is_some_and(|scan| scan.running) && !self.is_scan_paused()
                    {
                        self.handle_command(ShellCommand::Pause);
                        return true;
                    }
                }
                'r' | 'R' => {
                    if self.is_scan_paused() {
                        self.handle_command(ShellCommand::Resume(None));
                        return true;
                    }
                }
                _ => {}
            }
        }

        false
    }

    fn go_back(&mut self) {
        self.shell_view = match self.shell_view {
            ShellView::Finding => ShellView::Findings,
            ShellView::Findings
            | ShellView::Help
            | ShellView::Config
            | ShellView::Tools
            | ShellView::Runs
            | ShellView::Replay(_)
            | ShellView::Trace(_)
            | ShellView::History
            | ShellView::Story
            | ShellView::Threat(_)
            | ShellView::ThreatEditor => ShellView::Catalog,
            ShellView::Tune
            | ShellView::PromptsEditor
            | ShellView::Options(_)
            | ShellView::SastTasks
            | ShellView::Context
            | ShellView::Workspace
            | ShellView::KnowledgeBase
            | ShellView::AgentChat => {
                if self.focused_module.is_some() {
                    ShellView::Module
                } else {
                    ShellView::Catalog
                }
            }
            ShellView::ActorDetail(_) => ShellView::ModuleRun,
            ShellView::ModuleRun | ShellView::Module => ShellView::Catalog,
            ShellView::Catalog => ShellView::Catalog,
        };
    }

    fn request_exit(&mut self) {
        self.cancel_active_scan();
        self.should_quit = true;
    }

    fn cancel_active_scan(&mut self) -> bool {
        if !self.scan.as_ref().is_some_and(|scan| scan.running) {
            return false;
        }

        if let Some(cancel) = &self.scan_cancel {
            cancel.cancel();
        }
        if let Some(scan) = &mut self.scan {
            scan.stage = "cancelling".to_string();
        }
        self.log("scan", "cancelling active scan");
        true
    }

    fn handle_quit_chord(&mut self) {
        if self.cancel_active_scan() {
            self.ctrl_c_armed_at = None;
            return;
        }
        let now = Instant::now();
        if let Some(armed_at) = self.ctrl_c_armed_at {
            if now.duration_since(armed_at) <= CTRL_C_ARM_WINDOW {
                self.should_quit = true;
                return;
            }
        }
        self.ctrl_c_armed_at = Some(now);
        self.log(
            "system",
            "press Ctrl+C again within 2s to exit (any other key cancels)",
        );
    }

    pub fn tick(&mut self) {
        if let Some(armed_at) = self.ctrl_c_armed_at {
            if Instant::now().duration_since(armed_at) > CTRL_C_ARM_WINDOW {
                self.ctrl_c_armed_at = None;
            }
        }
        if let Some(throttle) = &self.advisory.throttle {
            if Instant::now().duration_since(throttle.since) > THROTTLE_STALE_AFTER {
                self.advisory.throttle = None;
            }
        }
    }

    pub fn ctrl_c_armed(&self) -> bool {
        self.ctrl_c_armed_at
            .map(|armed_at| Instant::now().duration_since(armed_at) <= CTRL_C_ARM_WINDOW)
            .unwrap_or(false)
    }

    pub fn set_throttle(&mut self, source: impl Into<String>, message: impl Into<String>) {
        let source = source.into();
        let message = message.into();
        self.log("throttle", format!("{source}: {message}"));
        self.advisory.throttle = Some(ThrottleAdvisory {
            source,
            message,
            since: Instant::now(),
        });
    }

    pub fn clear_throttle(&mut self) {
        self.advisory.throttle = None;
    }

    pub fn is_budget_halted(&self) -> bool {
        self.advisory.budget_halt.is_some()
    }

    pub fn record_cost(&mut self, cost_usd: f64) {
        self.last_tool_cost_usd = Some(cost_usd);
        self.session_cost_usd += cost_usd;
        self.maybe_trigger_budget_halt();
    }

    fn maybe_trigger_budget_halt(&mut self) {
        if self.advisory.budget_halt.is_some() {
            return;
        }
        if let Some(limit) = self.session_budget_usd {
            if limit > 0.0 && self.session_cost_usd >= limit {
                self.advisory.budget_halt = Some(BudgetHalt {
                    limit_usd: limit,
                    spent_usd: self.session_cost_usd,
                });
                self.log(
                    "budget",
                    format!(
                        "session cost ${:.4} reached cap ${:.4}; press [c] to continue or [a] to abort",
                        self.session_cost_usd, limit
                    ),
                );
            }
        }
    }

    fn continue_past_budget(&mut self) {
        if let Some(halt) = self.advisory.budget_halt.take() {
            // Bump the cap so the next halt only fires when costs significantly exceed the new spend.
            self.session_budget_usd = Some(halt.spent_usd * 2.0);
            self.log(
                "budget",
                format!(
                    "continuing past ${:.4}; new soft cap ${:.4}",
                    halt.spent_usd,
                    self.session_cost_usd * 2.0
                ),
            );
        }
    }

    fn abort_for_budget(&mut self) {
        self.advisory.budget_halt = None;
        let cancelled = self.cancel_active_scan();
        self.log(
            "budget",
            format!(
                "aborting due to cost cap (scan cancelled: {cancelled}). Next: /cost or /scan",
            ),
        );
    }
}

fn parse_budget_env() -> Option<f64> {
    env::var("KUZUSHI_BUDGET_USD")
        .ok()
        .and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value > 0.0)
}

fn compact_help_summary() -> String {
    shell_command_specs()
        .iter()
        .map(|spec| {
            if spec.command.starts_with('?') {
                spec.command.to_string()
            } else {
                format!("/{}", spec.command)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn command_completion_candidates(prefix: &str, slash: bool) -> Vec<String> {
    let mut values = Vec::new();
    for spec in shell_command_specs() {
        for form in std::iter::once(spec.command).chain(spec.aliases.iter().copied()) {
            let Some(head) = command_completion_head(form) else {
                continue;
            };
            if slash && head.starts_with('?') {
                continue;
            }
            let candidate = if slash && !head.starts_with('/') {
                format!("/{head}")
            } else {
                head
            };
            let comparable = candidate.strip_prefix('/').unwrap_or(&candidate);
            if comparable.starts_with(prefix) || candidate.starts_with(prefix) {
                values.push(candidate);
            }
        }
    }
    dedupe_sorted(values)
}

fn command_completion_head(template: &str) -> Option<String> {
    let mut parts = Vec::new();
    for part in template.split_whitespace() {
        if part.contains('<') || part.contains('[') || part.contains('|') {
            break;
        }
        parts.push(part);
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

fn complete_value_candidates(
    slash: bool,
    prefix_words: &[&str],
    current: &str,
    values: Vec<String>,
) -> Vec<String> {
    let current_lower = current.to_ascii_lowercase();
    let head = prefix_words.join(" ");
    let slash_prefix = if slash { "/" } else { "" };
    let candidates = values
        .into_iter()
        .filter(|value| {
            current_lower.is_empty() || value.to_ascii_lowercase().starts_with(&current_lower)
        })
        .map(|value| {
            if head.is_empty() {
                format!("{slash_prefix}{value}")
            } else {
                format!("{slash_prefix}{head} {value}")
            }
        })
        .collect();
    dedupe_sorted(candidates)
}

fn dedupe_sorted(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn config_completion_keys() -> &'static [&'static str] {
    &[
        "model",
        "runtime.kind",
        "runtime.api_key_env",
        "runtime.agent_bridge_command",
        "target",
        "workspace",
    ]
}

fn format_finding_alias(index: usize) -> String {
    format!("F-{:04}", index + 1)
}

fn parse_finding_alias(reference: &str) -> Option<usize> {
    let reference = reference.trim();
    let suffix = reference
        .strip_prefix("F-")
        .or_else(|| reference.strip_prefix("f-"))?;
    let index = suffix.parse::<usize>().ok()?;
    index.checked_sub(1)
}

pub fn format_chain_alias(index: usize) -> String {
    format!("C-{:02}", index + 1)
}

pub fn parse_chain_alias(reference: &str) -> Option<usize> {
    let reference = reference.trim();
    let suffix = reference
        .strip_prefix("C-")
        .or_else(|| reference.strip_prefix("c-"))?;
    let index = suffix.parse::<usize>().ok()?;
    index.checked_sub(1)
}

pub(crate) fn sorted_chain_aliases(chains: &[ExploitChain]) -> Vec<(String, ExploitChain)> {
    let mut indexed: Vec<&ExploitChain> = chains.iter().collect();
    indexed.sort_by(|a, b| {
        let by_severity = a.severity.rank().cmp(&b.severity.rank());
        if by_severity == std::cmp::Ordering::Equal {
            a.id.cmp(&b.id)
        } else {
            by_severity
        }
    });
    indexed
        .into_iter()
        .enumerate()
        .map(|(index, chain)| (format_chain_alias(index), chain.clone()))
        .collect()
}

pub(crate) fn sorted_finding_aliases(findings: &[Finding]) -> Vec<(String, Finding)> {
    let mut indexed: Vec<&Finding> = findings.iter().collect();
    indexed.sort_by(|a, b| {
        let by_severity = severity_rank(&a.severity).cmp(&severity_rank(&b.severity));
        if by_severity == std::cmp::Ordering::Equal {
            a.fingerprint.cmp(&b.fingerprint)
        } else {
            by_severity
        }
    });
    indexed
        .into_iter()
        .enumerate()
        .map(|(index, finding)| (format_finding_alias(index), finding.clone()))
        .collect()
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
        Severity::Unknown => 5,
    }
}

pub fn format_alias_table(
    findings: &[Finding],
    chains: &[ExploitChain],
    filter: Option<&str>,
) -> String {
    let chain_aliases = sorted_chain_aliases(chains);
    let finding_aliases = sorted_finding_aliases(findings);
    let mut rows: Vec<(String, String, String)> = Vec::new();
    for (alias, chain) in &chain_aliases {
        if let Some(prefix) = filter {
            if !alias.to_ascii_uppercase().starts_with(prefix) {
                continue;
            }
        }
        rows.push((alias.clone(), chain.id.clone(), chain.title.clone()));
    }
    for (alias, finding) in &finding_aliases {
        if let Some(prefix) = filter {
            if !alias.to_ascii_uppercase().starts_with(prefix) {
                continue;
            }
        }
        let target = finding.fingerprint.chars().take(12).collect::<String>();
        rows.push((alias.clone(), target, finding.title.clone()));
    }
    if rows.is_empty() {
        return match filter {
            Some(prefix) => format!("No aliases match \"{prefix}\""),
            None => "No aliases for the current run".to_string(),
        };
    }
    let alias_w = rows
        .iter()
        .map(|(a, _, _)| a.len())
        .max()
        .unwrap_or(0)
        .max(5);
    let target_w = rows
        .iter()
        .map(|(_, t, _)| t.len())
        .max()
        .unwrap_or(0)
        .max(6);
    let mut lines = Vec::new();
    lines.push(format!(
        "{:<alias_w$}  {:<target_w$}  title",
        "alias", "target",
    ));
    lines.push(format!("{:─<alias_w$}  {:─<target_w$}  ─────", "", "",));
    for (alias, target, title) in rows {
        lines.push(format!("{alias:<alias_w$}  {target:<target_w$}  {title}",));
    }
    lines.join("\n")
}

fn validate_shell_model_id(model: &str) -> std::result::Result<(), String> {
    if model.is_empty() {
        return Err("model cannot be empty. Next: model, or model provider:model-id".to_string());
    }
    let Some((provider, model_id)) = model.split_once(':') else {
        return Err(format!(
            "model must use provider:model syntax, got {model:?}. Next: model, or model openai:gpt-5.5"
        ));
    };
    if provider.trim().is_empty() || model_id.trim().is_empty() {
        return Err(format!(
            "model must include both provider and model id, got {model:?}. Next: model, or model openai:gpt-5.5"
        ));
    }
    Ok(())
}

fn resolve_model_selector(selector: &str) -> Option<&'static ModelChoice> {
    let key = selector.trim().to_ascii_lowercase().replace('_', "-");
    match key.as_str() {
        "1" | "gpt-5.5" | "5.5" | "openai:gpt-5.5" => MODEL_CHOICES.get(0),
        "2" | "gpt-5.5-mini" | "5.5-mini" | "mini" | "openai:gpt-5.5-mini" => MODEL_CHOICES.get(1),
        "3" | "codex:gpt-5.5" | "openai-codex:gpt-5.5" | "codex-5.5" => MODEL_CHOICES.get(2),
        "4" | "codex:gpt-5.5-mini" | "openai-codex:gpt-5.5-mini" | "codex-mini" => {
            MODEL_CHOICES.get(3)
        }
        "5" | "sonnet" | "claude-sonnet" | "claude-sonnet-4-6" | "anthropic:claude-sonnet-4-6" => {
            MODEL_CHOICES.get(4)
        }
        "6" | "opus" | "claude-opus" | "claude-opus-4-7" | "anthropic:claude-opus-4-7" => {
            MODEL_CHOICES.get(5)
        }
        _ => None,
    }
}

pub(crate) fn normalize_thinking_level(value: &str) -> Option<&'static str> {
    let normalized = value
        .trim()
        .to_ascii_lowercase()
        .replace(['_', '-', ' '], "");
    match normalized.as_str() {
        "low" => Some("low"),
        "medium" | "med" => Some("medium"),
        "high" => Some("high"),
        "xhigh" | "xtrahigh" | "extrahigh" => Some("xhigh"),
        _ => None,
    }
}

fn normalize_auth_provider(provider: &str) -> std::result::Result<&'static str, String> {
    match provider.trim().to_ascii_lowercase().as_str() {
        "" | "openai-codex" | "codex" => Ok("openai-codex"),
        "anthropic" | "claude" => Ok("anthropic"),
        other => Err(format!(
            "unsupported auth login provider {other:?}. Supported: openai-codex, anthropic. Next: auth login openai-codex"
        )),
    }
}

fn oauth_credentials_path() -> Option<PathBuf> {
    env::var_os("HOME").map(|home| PathBuf::from(home).join(".kuzushi/oauth-credentials.json"))
}

pub(crate) fn oauth_provider_status(provider: &str) -> String {
    let Some(path) = oauth_credentials_path() else {
        return "missing".to_string();
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return "missing".to_string();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return "unreadable".to_string();
    };
    let Some(entry) = json.get(provider) else {
        return "missing".to_string();
    };
    if entry
        .get("access")
        .and_then(serde_json::Value::as_str)
        .is_some()
        && entry
            .get("refresh")
            .and_then(serde_json::Value::as_str)
            .is_some()
    {
        "stored; value hidden".to_string()
    } else {
        "incomplete".to_string()
    }
}

fn thinking_level_from_input(input: &serde_json::Value) -> Option<String> {
    ["thinkingLevel", "reasoningEffort", "effort"]
        .iter()
        .find_map(|key| input.get(*key).and_then(serde_json::Value::as_str))
        .and_then(normalize_thinking_level)
        .map(ToString::to_string)
}

fn unknown_command_message(raw: &str) -> String {
    if raw.trim_start().starts_with('/') {
        format!("unknown command {raw:?}. Next: help")
    } else {
        format!(
            "unknown command {raw:?}. Free-form chat is explicit only. Next: /ask <question> or help"
        )
    }
}

const ASK_SYSTEM_PROMPT: &str = r#"You are Kuzushi's Rust shell assistant.
Answer operator questions about the current repository and Kuzushi workflow.
Do not claim that scans, tools, or model work have run unless the prompt provides that evidence.
Prefer concrete next commands that are routed by the Rust shell."#;

pub(crate) fn runtime_backend_label(config: &V2Config) -> &'static str {
    match config.runtime.kind {
        RuntimeKind::PiAgentCore => "pi-agent-core",
    }
}

pub(crate) fn bridge_command_status(config: &V2Config) -> &'static str {
    if config
        .runtime
        .agent_bridge_command
        .as_ref()
        .is_some_and(|command| !command.is_empty())
    {
        "configured"
    } else {
        "bundled/default"
    }
}

fn extract_cost_usd(result: &serde_json::Value) -> Option<f64> {
    result
        .get("costUsd")
        .and_then(serde_json::Value::as_f64)
        .or_else(|| {
            result
                .pointer("/data/costUsd")
                .and_then(serde_json::Value::as_f64)
        })
        .filter(|cost| cost.is_finite() && *cost >= 0.0)
}

fn default_context_snapshot_view(snapshot_path: Option<PathBuf>) -> ContextSnapshotView {
    ContextSnapshotView {
        snapshot_path,
        exists: false,
        status: "missing. Next: context build".to_string(),
        target: None,
        discovery: None,
        files_indexed: None,
        total_files: None,
        languages: Vec::new(),
        frameworks: Vec::new(),
        generated_slices: Vec::new(),
        stale_slices: Vec::new(),
    }
}

fn default_workspace_view(target: Option<&WorkspaceTarget>) -> WorkspaceView {
    match target {
        Some(workspace) => WorkspaceView {
            root: Some(workspace.root().to_path_buf()),
            state_dir: Some(workspace.state_dir()),
            findings_db: Some(workspace.findings_db_path()),
            findings_count: None,
            last_export: None,
            status: "workspace ready. Next: workspace status".to_string(),
        },
        None => WorkspaceView {
            root: None,
            state_dir: None,
            findings_db: None,
            findings_count: None,
            last_export: None,
            status: "no active workspace. Next: scan <target> or start shell with --target ."
                .to_string(),
        },
    }
}

fn load_context_snapshot_view(snapshot_path: PathBuf) -> Result<ContextSnapshotView> {
    if !snapshot_path.exists() {
        return Ok(default_context_snapshot_view(Some(snapshot_path)));
    }

    let body = fs::read_to_string(&snapshot_path)
        .with_context(|| format!("Could not read {}", snapshot_path.display()))?;
    let snapshot: serde_json::Value = serde_json::from_str(&body)
        .with_context(|| format!("Could not parse {}", snapshot_path.display()))?;
    let files_indexed = snapshot
        .get("filesIndexed")
        .and_then(serde_json::Value::as_u64);
    let total_files = snapshot
        .pointer("/fileIndex/totalFiles")
        .and_then(serde_json::Value::as_u64);
    let generated_slices = json_string_array(snapshot.get("generatedSlices"));
    let stale_slices = json_string_array(snapshot.get("staleSlices"));
    let languages = json_string_array(snapshot.pointer("/repoContext/languages"));
    let frameworks = json_string_array(snapshot.pointer("/repoContext/frameworks"));
    let target = snapshot
        .get("target")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let discovery = snapshot
        .get("discovery")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let status = format!(
        "snapshot present; {} indexed file(s). Next: context regen repo",
        files_indexed.or(total_files).unwrap_or(0)
    );

    Ok(ContextSnapshotView {
        snapshot_path: Some(snapshot_path),
        exists: true,
        status,
        target,
        discovery,
        files_indexed,
        total_files,
        languages,
        frameworks,
        generated_slices,
        stale_slices,
    })
}

fn json_string_array(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn run_shell(config: V2Config, target: Option<&WorkspaceTarget>) -> Result<()> {
    let mut stdin = io::stdin();
    let stdin_is_terminal = stdin.is_terminal();
    let stdout_is_terminal = io::stdout().is_terminal();
    if !stdin_is_terminal || !stdout_is_terminal || env::var_os("KUZUSHI_PLAIN").is_some() {
        return run_plain_shell(config, target, &mut stdin, stdin_is_terminal);
    }

    let mut terminal = setup_terminal()?;
    let mut app = ShellApp::new(config, target);

    loop {
        app.tick();
        app.drain_background_events();
        terminal.draw(|frame| render_app(frame, &app))?;
        if app.should_quit {
            break;
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                app.handle_key(key);
            }
        }
    }

    restore_terminal(&mut terminal)
}

fn run_plain_shell(
    config: V2Config,
    target: Option<&WorkspaceTarget>,
    stdin: &mut io::Stdin,
    stdin_is_terminal: bool,
) -> Result<()> {
    let mut app = ShellApp::new(config, target);
    let mut script = String::new();
    if !stdin_is_terminal {
        stdin
            .read_to_string(&mut script)
            .context("Could not read plain shell input")?;
    }

    let commands = script
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();

    if commands.is_empty() {
        print!("{}", render_plain_app(&app, 80));
        return Ok(());
    }

    for (index, command) in commands.iter().enumerate() {
        if index > 0 {
            println!();
        }
        app.submit_line(command);
        app.drain_background_events();
        print!("{}", render_plain_app(&app, 80));
        if app.should_quit {
            break;
        }
    }
    Ok(())
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode().context("Could not enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, Clear(ClearType::All), MoveTo(0, 0))
        .context("Could not reset terminal viewport")?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend).context("Could not initialize terminal")
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode().context("Could not disable raw mode")?;
    terminal
        .show_cursor()
        .context("Could not show terminal cursor")
}

#[derive(Debug)]
enum ScanEvent {
    Started {
        run_id: String,
        target: PathBuf,
    },
    Stage(String),
    FindingStored {
        fingerprint: String,
        severity: Severity,
        title: String,
    },
    Finished {
        run_id: String,
        findings_count: usize,
    },
    Failed {
        error: String,
    },
    Cancelled {
        run_id: String,
    },
}

#[derive(Debug)]
enum AgentEvent {
    Answered { text: String },
    Failed { error: String },
}

#[derive(Debug)]
pub enum PlanEvent {
    Proposed(PlanProposal),
    Failed { error: String },
}

#[derive(Debug)]
pub enum ThreatPatchEvent {
    Proposed(ThreatPatch),
    Answer { text: String },
    Failed { error: String },
}

fn agent_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    question: String,
    tx: Sender<AgentEvent>,
) {
    let result = run_agent_worker(config, model, thinking_level, cwd, question);
    let event = match result {
        Ok(text) => AgentEvent::Answered { text },
        Err(error) => AgentEvent::Failed {
            error: error.to_string(),
        },
    };
    let _ = tx.send(event);
}

fn run_agent_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    question: String,
) -> Result<String> {
    let runtime =
        PiAgentCoreRuntime::from_config(&config, &cwd)?.with_thinking_level(thinking_level);
    let response = runtime.query_blocking(AgentQueryRequest {
        model,
        cwd,
        system_prompt: ASK_SYSTEM_PROMPT.to_string(),
        prompt: question,
    })?;
    let answer = response.text.trim();
    if answer.is_empty() {
        anyhow::bail!("agent returned no answer");
    }
    Ok(answer.to_string())
}

const PLAN_SYSTEM_PROMPT: &str = r#"You are Kuzushi's planning assistant.
Translate the operator's natural-language goal into a strict JSON proposal.
Output ONLY JSON, starting with '{'. No prose, no code fences.
Schema:
{
  "summary": "one-sentence restatement of the goal",
  "changes": [
    {"kind": "set_option", "tool": "<tool name or null>", "global": false, "name": "<key>", "value": "<value>"},
    {"kind": "ask", "question": "<question to /ask the agent>"},
    {"kind": "note", "text": "<short operator-facing note>"}
  ],
  "unsupported": ["<natural-language reason something cannot be encoded>"]
}
Rules:
- Only emit set_option changes you are confident map to existing tool options.
- Otherwise add a string to "unsupported" instead.
- Prefer at most 6 changes."#;

fn planner_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    goal: String,
    tx: Sender<PlanEvent>,
) {
    let event = match run_planner_worker(config, model, thinking_level, cwd, &goal) {
        Ok(plan) => PlanEvent::Proposed(plan),
        Err(error) => PlanEvent::Failed {
            error: error.to_string(),
        },
    };
    let _ = tx.send(event);
}

fn run_planner_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    goal: &str,
) -> Result<PlanProposal> {
    let runtime =
        PiAgentCoreRuntime::from_config(&config, &cwd)?.with_thinking_level(thinking_level);
    let response = runtime.query_blocking(AgentQueryRequest {
        model,
        cwd,
        system_prompt: PLAN_SYSTEM_PROMPT.to_string(),
        prompt: goal.to_string(),
    })?;
    let body = response.text.trim();
    if body.is_empty() {
        anyhow::bail!("planner returned no content");
    }
    parse_plan_json(goal, body)
}

pub fn parse_plan_json(goal: &str, body: &str) -> Result<PlanProposal> {
    let json_start = body
        .find('{')
        .context("planner response had no JSON object")?;
    let json_end = body
        .rfind('}')
        .context("planner response had no closing JSON brace")?;
    if json_end <= json_start {
        anyhow::bail!("planner response had unbalanced JSON");
    }
    let json_slice = &body[json_start..=json_end];
    let parsed: serde_json::Value =
        serde_json::from_str(json_slice).context("planner JSON did not parse")?;
    let summary = parsed
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(goal)
        .to_string();
    let mut changes = Vec::new();
    if let Some(items) = parsed.get("changes").and_then(serde_json::Value::as_array) {
        for item in items {
            let kind = item
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            match kind {
                "set_option" => {
                    let name = item
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string);
                    let value = item.get("value").map(plan_value_to_string);
                    let global = item
                        .get("global")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    let tool = item
                        .get("tool")
                        .and_then(serde_json::Value::as_str)
                        .filter(|tool| !tool.is_empty())
                        .map(str::to_string);
                    if let (Some(name), Some(value)) = (name, value) {
                        changes.push(PlanChange::SetOption {
                            global,
                            tool,
                            name,
                            value,
                        });
                    }
                }
                "ask" => {
                    if let Some(question) = item
                        .get("question")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                    {
                        changes.push(PlanChange::Ask { question });
                    }
                }
                "note" => {
                    if let Some(text) = item
                        .get("text")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                    {
                        changes.push(PlanChange::Note { text });
                    }
                }
                _ => {}
            }
        }
    }
    let unsupported = parsed
        .get("unsupported")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(PlanProposal {
        goal: goal.to_string(),
        summary,
        changes,
        unsupported,
    })
}

fn plan_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

const THREAT_PATCH_SYSTEM_PROMPT: &str = r#"You are Kuzushi's threat-model patcher.
Given the current threat-model JSON and operator intent, output STRICT JSON:
{
  "summary": "one-sentence change description",
  "patch": { ... },         // deep-merge object — only changed/added keys
  "unsupported": [ ... ]    // operator-facing notes for changes you cannot encode
}
Rules:
- Output ONLY JSON, starting with '{'.
- Preserve existing fields you do not touch — the patch is a deep-merge, not a replacement.
- Set fields to null to delete them.
- Prefer additive changes."#;

const THREAT_REGEN_PROMPT: &str = "Regenerate the threat model with sharper coverage of likely attack surface, while preserving operator-edited stages and elements.";

fn threat_regen_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    tx: Sender<ThreatPatchEvent>,
) {
    let event = match run_threat_regen_worker(config, model, thinking_level, cwd, existing) {
        Ok(patch) => ThreatPatchEvent::Proposed(patch),
        Err(error) => ThreatPatchEvent::Failed {
            error: error.to_string(),
        },
    };
    let _ = tx.send(event);
}

fn run_threat_regen_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
) -> Result<ThreatPatch> {
    let runtime =
        PiAgentCoreRuntime::from_config(&config, &cwd)?.with_thinking_level(thinking_level);
    let prompt = format!(
        "OPERATOR INTENT:\n{}\n\nCURRENT THREAT MODEL JSON:\n{}",
        THREAT_REGEN_PROMPT,
        serde_json::to_string_pretty(&existing).unwrap_or_else(|_| "null".to_string())
    );
    let response = runtime.query_blocking(AgentQueryRequest {
        model,
        cwd,
        system_prompt: THREAT_PATCH_SYSTEM_PROMPT.to_string(),
        prompt,
    })?;
    let body = response.text.trim();
    if body.is_empty() {
        anyhow::bail!("threat regen returned no content");
    }
    parse_threat_patch_json(THREAT_REGEN_PROMPT, body)
}

fn threat_ask_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    question: String,
    tx: Sender<ThreatPatchEvent>,
) {
    let event = match run_threat_ask_worker(config, model, thinking_level, cwd, existing, &question)
    {
        Ok(answer) => ThreatPatchEvent::Answer { text: answer },
        Err(error) => ThreatPatchEvent::Failed {
            error: error.to_string(),
        },
    };
    let _ = tx.send(event);
}

fn run_threat_ask_worker(
    config: V2Config,
    model: String,
    thinking_level: Option<String>,
    cwd: PathBuf,
    existing: serde_json::Value,
    question: &str,
) -> Result<String> {
    let runtime =
        PiAgentCoreRuntime::from_config(&config, &cwd)?.with_thinking_level(thinking_level);
    let prompt = format!(
        "OPERATOR QUESTION:\n{question}\n\nCURRENT THREAT MODEL JSON:\n{}",
        serde_json::to_string_pretty(&existing).unwrap_or_else(|_| "null".to_string())
    );
    let response = runtime.query_blocking(AgentQueryRequest {
        model,
        cwd,
        system_prompt: ASK_SYSTEM_PROMPT.to_string(),
        prompt,
    })?;
    let answer = response.text.trim();
    if answer.is_empty() {
        anyhow::bail!("threat-ask returned no content");
    }
    Ok(answer.to_string())
}

pub fn parse_threat_patch_json(goal: &str, body: &str) -> Result<ThreatPatch> {
    let json_start = body
        .find('{')
        .context("threat-patch response had no JSON object")?;
    let json_end = body
        .rfind('}')
        .context("threat-patch response had no closing JSON brace")?;
    if json_end <= json_start {
        anyhow::bail!("threat-patch response had unbalanced JSON");
    }
    let json_slice = &body[json_start..=json_end];
    let parsed: serde_json::Value =
        serde_json::from_str(json_slice).context("threat-patch JSON did not parse")?;
    let summary = parsed
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(goal)
        .to_string();
    let patch = parsed
        .get("patch")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if !matches!(
        patch,
        serde_json::Value::Object(_) | serde_json::Value::Null
    ) {
        anyhow::bail!("threat-patch must be a JSON object");
    }
    let unsupported = parsed
        .get("unsupported")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(ThreatPatch {
        goal: goal.to_string(),
        summary,
        patch,
        unsupported,
    })
}

pub fn merge_json(target: &mut serde_json::Value, patch: &serde_json::Value) {
    use serde_json::Value;
    match patch {
        Value::Object(patch_map) => {
            if !target.is_object() {
                *target = Value::Object(serde_json::Map::new());
            }
            let target_map = target.as_object_mut().expect("ensured object above");
            for (key, value) in patch_map {
                if value.is_null() {
                    target_map.remove(key);
                } else if let Some(existing) = target_map.get_mut(key) {
                    merge_json(existing, value);
                } else {
                    target_map.insert(key.clone(), value.clone());
                }
            }
        }
        _ => {
            *target = patch.clone();
        }
    }
}

fn scan_worker(
    target: PathBuf,
    db_path: PathBuf,
    tx: Sender<ScanEvent>,
    cancel: ScanCancellation,
    options: ScanRunOptions,
) {
    if let Err(error) = run_scan_worker(target, db_path, &tx, &cancel, &options) {
        let _ = tx.send(ScanEvent::Failed {
            error: error.to_string(),
        });
    }
}

fn run_scan_worker(
    target: PathBuf,
    db_path: PathBuf,
    tx: &Sender<ScanEvent>,
    cancel: &ScanCancellation,
    options: &ScanRunOptions,
) -> Result<()> {
    let workspace = WorkspaceTarget::new(&target)?;
    workspace.ensure_state_dir()?;
    let store = FindingStore::open(db_path)?;
    let run_id = Uuid::new_v4().to_string();

    store.insert_scan_run(&run_id, workspace.root(), "running")?;
    let _ = tx.send(ScanEvent::Started {
        run_id: run_id.clone(),
        target: workspace.root().to_path_buf(),
    });
    let _ = tx.send(ScanEvent::Stage("running scan".to_string()));

    let scanners = match options.tasks.as_ref() {
        Some(tasks) => kuzushi_core::scan_engines_for_tasks(tasks)?,
        None => default_scan_engines(),
    };
    let mut findings = Vec::new();
    for scanner in scanners {
        cancel.wait_if_paused();
        if cancel.is_cancelled() {
            store.complete_scan_run(&run_id, "cancelled", findings.len())?;
            let _ = tx.send(ScanEvent::Cancelled { run_id });
            return Ok(());
        }
        let _ = tx.send(ScanEvent::Stage(format!("running {}", scanner.id())));
        match scanner.scan(workspace.root(), cancel) {
            Ok(mut scanner_findings) => findings.append(&mut scanner_findings),
            Err(_) if cancel.is_cancelled() => {
                store.complete_scan_run(&run_id, "cancelled", findings.len())?;
                let _ = tx.send(ScanEvent::Cancelled { run_id });
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    }
    if let Some(allowed) = &options.severity {
        findings.retain(|finding| allowed.contains(&finding.severity));
    }
    let _ = tx.send(ScanEvent::Stage(format!(
        "persisting {} finding(s)",
        findings.len()
    )));

    for finding in &findings {
        store.insert_finding(&run_id, finding)?;
        let _ = tx.send(ScanEvent::FindingStored {
            fingerprint: finding.fingerprint.clone(),
            severity: finding.severity,
            title: finding.title.clone(),
        });
    }

    store.complete_scan_run(&run_id, "completed", findings.len())?;
    let _ = tx.send(ScanEvent::Finished {
        run_id,
        findings_count: findings.len(),
    });
    Ok(())
}

fn short_fingerprint(fingerprint: &str) -> String {
    fingerprint.chars().take(8).collect()
}

fn truncate_ascii(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut truncated = value
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

fn threat_view_label(view: ThreatView) -> &'static str {
    match view {
        ThreatView::Dfd => "dfd",
        ThreatView::Stride => "stride",
        ThreatView::Stories => "stories",
        ThreatView::Scope => "scope",
        ThreatView::Summary => "summary",
    }
}

#[derive(Debug, Clone, Copy)]
struct SastTaskCapability {
    id: &'static str,
    scan_task: &'static str,
    cost: &'static str,
    notes: &'static str,
    default_enabled: bool,
    native_scan: bool,
    toggleable: bool,
}

const SAST_TASK_CAPABILITIES: &[SastTaskCapability] = &[
    SastTaskCapability {
        id: "semgrep",
        scan_task: "semgrep",
        cost: "low",
        notes: "pattern scanner",
        default_enabled: true,
        native_scan: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "codeql",
        scan_task: "codeql",
        cost: "high",
        notes: "semantic query scanner",
        default_enabled: false,
        native_scan: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "dep-hygiene",
        scan_task: "dep-hygiene",
        cost: "low",
        notes: "dependency manifest hygiene",
        default_enabled: true,
        native_scan: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "secret-scan",
        scan_task: "secret-scan",
        cost: "low",
        notes: "local secret patterns",
        default_enabled: true,
        native_scan: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "iac-scan",
        scan_task: "iac-scan",
        cost: "low",
        notes: "IaC misconfiguration scanner",
        default_enabled: true,
        native_scan: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "agentic",
        scan_task: "agentic",
        cost: "high",
        notes: "model-backed detector set; run via sast:scan",
        default_enabled: false,
        native_scan: false,
        toggleable: true,
    },
    SastTaskCapability {
        id: "carlini-threat-hunt",
        scan_task: "carlini-threat-hunt",
        cost: "high",
        notes: "actor-driven hunt; run via sast:scan",
        default_enabled: false,
        native_scan: false,
        toggleable: true,
    },
    SastTaskCapability {
        id: "taint-iris",
        scan_task: "taint-iris",
        cost: "high",
        notes: "source-to-sink analysis; run via sast:scan",
        default_enabled: false,
        native_scan: false,
        toggleable: true,
    },
    SastTaskCapability {
        id: "taint-iris-next",
        scan_task: "taint-iris-next",
        cost: "high",
        notes: "next taint workflow; run via sast:scan",
        default_enabled: false,
        native_scan: false,
        toggleable: true,
    },
    SastTaskCapability {
        id: "systems-hunt",
        scan_task: "systems-hunt",
        cost: "high",
        notes: "systems invariant hunt; run via sast:scan",
        default_enabled: false,
        native_scan: false,
        toggleable: true,
    },
];

fn valid_sast_task_ids() -> Vec<&'static str> {
    SAST_TASK_CAPABILITIES.iter().map(|task| task.id).collect()
}

fn unknown_sast_task_message(raw_id: &str) -> String {
    format!(
        "unknown SAST task {raw_id:?}. Valid task IDs: {}. Next: /tasks",
        valid_sast_task_ids().join(", ")
    )
}

fn resolve_sast_task(raw_id: &str) -> Option<&'static SastTaskCapability> {
    let normalized = raw_id.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    let normalized = match normalized.as_str() {
        "agentic-sast" | "agentic-sast:scan" => "agentic",
        "semgrep:scan" => "semgrep",
        "codeql:scan" => "codeql",
        "dep-hygiene:check" => "dep-hygiene",
        "secret-scan:scan" | "secrets" => "secret-scan",
        "iac-scan:scan" => "iac-scan",
        "carlini" | "threat-hunt" | "carlini-threat-hunt:run" => "carlini-threat-hunt",
        "taint" | "iris" | "taint-iris:hunt" => "taint-iris",
        "taint-next" | "iris-next" | "taint-iris-next:hunt" => "taint-iris-next",
        "systems" | "systems-hunt:systems-hunt" => "systems-hunt",
        other => other,
    };
    SAST_TASK_CAPABILITIES
        .iter()
        .find(|task| task.id == normalized || task.scan_task == normalized)
}

fn normalize_kb_module_id(raw_id: &str) -> String {
    match raw_id.trim().to_ascii_lowercase().as_str() {
        "tm" | "threat" | "threats" => "threat-model".to_string(),
        "carlini" | "threat-hunt" => "carlini-threat-hunt".to_string(),
        "xray" | "x_ray" => "x-ray".to_string(),
        other => other.to_string(),
    }
}

fn unknown_kb_module_message(module_id: &str) -> String {
    format!(
        "unknown KB module {module_id:?}. Supported KB modules: {}. Next: kb context",
        SUPPORTED_ATTACHMENT_MODULES.join(", ")
    )
}

fn options_filter_label(filter: OptionsFilter) -> &'static str {
    match filter {
        OptionsFilter::Standard => "options",
        OptionsFilter::Advanced => "advanced options",
        OptionsFilter::Missing => "missing options",
    }
}

fn find_option_spec<'a>(tool: &'a ToolDescriptor, name: &str) -> Option<&'a OptionSpec> {
    tool.options
        .iter()
        .find(|spec| spec.name.eq_ignore_ascii_case(name))
}

fn coerce_raw_option_value(spec: &OptionSpec, raw: &str) -> Result<serde_json::Value> {
    let raw = raw.trim();
    let value = match spec.option_type {
        OptionType::String | OptionType::Path => serde_json::Value::String(raw.to_string()),
        OptionType::StringList => serde_json::Value::String(raw.to_string()),
        OptionType::Bool => serde_json::Value::Bool(parse_bool_option(raw)?),
        OptionType::Int => {
            let parsed = raw
                .parse::<i64>()
                .with_context(|| format!("must be an integer, got {raw:?}"))?;
            serde_json::Value::Number(parsed.into())
        }
        OptionType::Float => {
            let parsed = raw
                .parse::<f64>()
                .with_context(|| format!("must be a number, got {raw:?}"))?;
            let number =
                serde_json::Number::from_f64(parsed).context("must be a finite JSON number")?;
            serde_json::Value::Number(number)
        }
        OptionType::Enum => {
            if !spec.choices.iter().any(|choice| choice == raw) {
                anyhow::bail!("must be one of {}, got {raw:?}", spec.choices.join("|"));
            }
            serde_json::Value::String(raw.to_string())
        }
    };
    Ok(value)
}

fn parse_bool_option(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "t" | "yes" | "y" | "1" | "on" => Ok(true),
        "false" | "f" | "no" | "n" | "0" | "off" => Ok(false),
        _ => anyhow::bail!("must be true or false, got {value:?}"),
    }
}

fn format_option_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Null => "null".to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<json>".to_string()),
    }
}

fn unknown_option_message(tool: &ToolDescriptor, name: &str) -> String {
    let choices = tool
        .options
        .iter()
        .map(|spec| spec.name.as_str())
        .collect::<Vec<_>>();
    let closest = closest_option_names(name, &choices);
    let closest = if closest.is_empty() {
        "none".to_string()
    } else {
        closest.join(", ")
    };
    format!(
        "unknown option {name:?} for {}. Closest: {closest}. Next: show options {}",
        tool.name, tool.name
    )
}

fn closest_option_names(name: &str, choices: &[&str]) -> Vec<String> {
    let normalized = name.to_ascii_lowercase();
    let mut scored = choices
        .iter()
        .map(|choice| {
            let choice_lower = choice.to_ascii_lowercase();
            let score =
                if choice_lower.starts_with(&normalized) || normalized.starts_with(&choice_lower) {
                    0
                } else {
                    edit_distance(&normalized, &choice_lower)
                };
            (score, (*choice).to_string())
        })
        .collect::<Vec<_>>();
    scored.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    scored
        .into_iter()
        .take(3)
        .filter(|(score, _)| *score <= normalized.len().max(3))
        .map(|(_, choice)| choice)
        .collect()
}

fn parse_native_scan_tasks(input: &serde_json::Value) -> Result<Option<Vec<String>>> {
    let mode = input
        .get("taskMode")
        .or_else(|| input.get("task_mode"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("auto");
    if !matches!(mode, "auto" | "manual") {
        anyhow::bail!("scan taskMode must be auto or manual");
    }

    let requested = read_task_list_value(input.get("tasks"));
    let disabled = read_task_list_value(
        input
            .get("disabledTasks")
            .or_else(|| input.get("disabled_tasks")),
    );
    let disabled = disabled
        .iter()
        .filter_map(|task| resolve_sast_task(task).map(|task| task.id))
        .collect::<BTreeSet<_>>();

    let selected = if !requested.is_empty() {
        requested
    } else if !disabled.is_empty() {
        SAST_TASK_CAPABILITIES
            .iter()
            .filter(|task| task.default_enabled && !disabled.contains(task.id))
            .map(|task| task.id.to_string())
            .collect()
    } else {
        Vec::new()
    };

    if mode == "manual" && selected.is_empty() {
        anyhow::bail!("scan taskMode=manual requires at least one task. Next: /task mode auto");
    }
    if selected.is_empty() {
        return Ok(None);
    }

    let mut native_tasks = Vec::new();
    let mut unsupported = Vec::new();
    for raw in selected {
        let Some(task) = resolve_sast_task(&raw) else {
            anyhow::bail!("{}", unknown_sast_task_message(&raw));
        };
        if task.native_scan {
            native_tasks.push(task.scan_task.to_string());
        } else {
            unsupported.push(task.id);
        }
    }
    if !unsupported.is_empty() {
        anyhow::bail!(
            "scan supports native tasks only; unsupported here: {}. Next: run sast:scan",
            unsupported.join(", ")
        );
    }
    if native_tasks.is_empty() {
        anyhow::bail!("scan selected no native tasks. Next: /tasks or run sast:scan");
    }

    Ok(Some(native_tasks))
}

fn read_task_list_value(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::String(value)) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn edit_distance(left: &str, right: &str) -> usize {
    let left = left.chars().collect::<Vec<_>>();
    let right = right.chars().collect::<Vec<_>>();
    let mut previous = (0..=right.len()).collect::<Vec<_>>();
    let mut current = vec![0; right.len() + 1];

    for (i, left_ch) in left.iter().enumerate() {
        current[0] = i + 1;
        for (j, right_ch) in right.iter().enumerate() {
            let substitution = previous[j] + usize::from(left_ch != right_ch);
            let insertion = current[j] + 1;
            let deletion = previous[j + 1] + 1;
            current[j + 1] = substitution.min(insertion).min(deletion);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    previous[right.len()]
}

fn parse_scan_severity_filter(input: &serde_json::Value) -> Result<Option<Vec<Severity>>> {
    let Some(raw) = input.get("severity") else {
        return Ok(None);
    };
    let values = match raw {
        serde_json::Value::String(value) => value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .context("scan severity must contain only non-empty strings")
            })
            .collect::<Result<Vec<_>>>()?,
        other => {
            anyhow::bail!("scan severity must be a string or string array, got {other}");
        }
    };
    if values.is_empty() {
        return Ok(None);
    }
    values
        .iter()
        .map(|value| match value.trim().to_ascii_lowercase().as_str() {
            "critical" => Ok(Severity::Critical),
            "high" | "error" => Ok(Severity::High),
            "medium" | "warning" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            "info" => Ok(Severity::Info),
            "unknown" => Ok(Severity::Unknown),
            other => anyhow::bail!("scan unknown severity filter {other:?}"),
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{
        OptionScope, OptionTarget, RuntimeConfig, RuntimeKind, TriageOutcome, TriageVerdict,
    };
    use std::fs;

    #[cfg(unix)]
    fn fake_semgrep_binary(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("semgrep-fixture.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
cat <<'JSON'
{
  "results": [
    {
      "check_id": "javascript.express.security.audit.xss",
      "path": "server.js",
      "start": { "line": 9 },
      "end": { "line": 11 },
      "extra": {
        "severity": "ERROR",
        "message": "Detected unescaped user input in HTML response"
      }
    }
  ]
}
JSON
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_codeql_binary(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("codeql-fixture.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
if [ "$1" = "database" ] && [ "$2" = "create" ]; then
  mkdir -p "$3"
  printf 'name: test\n' > "$3/codeql-database.yml"
  exit 0
fi
if [ "$1" = "database" ] && [ "$2" = "analyze" ]; then
  out=""
  for arg in "$@"; do
    case "$arg" in
      --output=*) out="${arg#--output=}" ;;
    esac
  done
  cat > "$out" <<'JSON'
{
  "runs": [
    {
      "tool": {
        "driver": {
          "rules": [
            {
              "id": "js/sql-injection",
              "properties": { "problem": { "severity": "error" } }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "js/sql-injection",
          "message": { "text": "User input reaches SQL sink" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "server.js" },
                "region": { "startLine": 9 }
              }
            }
          ]
        }
      ]
    }
  ]
}
JSON
  exit 0
fi
echo "unexpected codeql args: $*" >&2
exit 2
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_curl_binary(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("curl-fixture.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
cat <<'HTTP'
HTTP/1.1 200 OK
Server: nginx
X-Powered-By: Express

<html><title>Acme</title></html>
HTTP
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_nmap_binary(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("nmap-fixture.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
cat <<'OUT'
Host: 192.0.2.10 (web.example) Ports: 80/open/tcp//http//nginx/, 443/open/tcp//https//nginx TLS/
OUT
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_triage_bridge(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("triage-bridge.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"verdict":"true_positive","confidence":0.91,"rationale":"mock shell bridge"}}
JSON
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_ask_bridge(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("ask-bridge.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"What should I run first?"*)
    cat <<'JSON'
{"ok":true,"text":"Run context build, then scan ."}
JSON
    ;;
  *)
    echo '{"ok":false,"error":"unexpected ask request"}'
    exit 1
    ;;
esac
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_agentic_bridge(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("agentic-bridge.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"findings":[{"ruleId":"agentic/sql-injection","filePath":"src/db.ts","startLine":1,"severity":"ERROR","message":"User input reaches SQL query","confidence":"HIGH","evidence":"Source: req.query.q -> sink: db.query"}]}}
JSON
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_variant_bridge(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("variant-bridge.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"variant analysis agent"*)
    cat <<'JSON'
{"ok":true,"structured":{"variants":[{"filePath":"src/other.ts","startLine":9,"severity":"ERROR","message":"exec with untrusted input","confidence":"HIGH","rationale":"same source reaches exec","cwe":["CWE-78"]}]}}
JSON
    ;;
  *)
    echo '{"ok":false,"error":"unexpected variant request"}'
    exit 1
    ;;
esac
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    fn seed_true_positive_finding(workspace: &WorkspaceTarget) -> String {
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-variant", workspace.root(), "running")
            .unwrap();
        let finding = Finding::new_tool(
            "semgrep",
            "javascript.express.command-injection",
            "src/app.ts",
            1,
            None,
            Severity::High,
            "Command injection via child_process.exec",
        );
        let fingerprint = finding.fingerprint.clone();
        let finding_id = store.insert_finding("run-variant", &finding).unwrap();
        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.92,
                    rationale: "request body reaches exec".to_string(),
                },
            )
            .unwrap();
        store
            .complete_scan_run("run-variant", "completed", 1)
            .unwrap();
        fingerprint
    }

    #[cfg(unix)]
    fn fake_ndiff_bridge(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("ndiff-bridge.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"N-day variant hunter"*)
    cat <<'JSON'
{"ok":true,"structured":{"variants":[{"filePath":"src/parser.c","startLine":7,"severity":"ERROR","message":"memcpy without bounds check","confidence":"HIGH","rationale":"length reaches memcpy","cwe":["CWE-787"]}]}}
JSON
    ;;
  *)
    echo '{"ok":false,"error":"unexpected ndiff request"}'
    exit 1
    ;;
esac
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_taint_iris_bridge(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("taint-iris-bridge.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"Taint CWE selector"*)
    cat <<'JSON'
{"ok":true,"structured":{"cwes":[{"id":"CWE-89","name":"SQL Injection","reason":"database query uses request input"}]}}
JSON
    ;;
  *"IRIS-style taint analysis"*)
    cat <<'JSON'
{"ok":true,"structured":{"findings":[{"title":"Request input reaches SQL query","cwe":"CWE-89","severity":"high","filePath":"src/db.ts","startLine":1,"message":"The request query is concatenated into a SQL query.","sourceSinkTrace":"req.query.q -> db.query","taintPath":[{"filePath":"src/db.ts","line":1,"message":"source and sink","snippet":"db.query(req.query.q)"}],"confidence":"high","exploitPreconditions":"attacker controls q"}]}}
JSON
    ;;
  *)
    echo '{"ok":false,"error":"unexpected taint-iris request"}'
    exit 1
    ;;
esac
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_taint_iris_next_bridge(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("taint-iris-next-bridge.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"Taint IRIS Next agent"*)
    cat <<'JSON'
{"ok":true,"structured":{"selectedCwes":[{"cwe":"CWE-89","reason":"raw query receives request data","catalogSignals":["sink: query("],"sourceSpec":"request query parameters","sinkSpec":"database query calls","sanitizerSpec":"parameterized query APIs","customCweRationale":""}],"findings":[{"title":"Request parameter reaches raw SQL query","cwe":"CWE-89","severity":"high","confidence":"medium","evidenceLevel":"linked","filePath":"src/routes.ts","startLine":1,"message":"The query uses request-controlled data in SQL construction.","sourceSinkTrace":"req.query.id -> db.query(sql)","catalogSignals":["source: req.query","sink: query("],"customCweRationale":"","taintPath":[{"filePath":"src/routes.ts","line":1,"message":"source and SQL sink","snippet":"db.query(req.query.id)"}]}],"triage":[{"status":"finding","cwe":"CWE-89","evidenceLevel":"linked","rationale":"request data reaches raw SQL query","filePath":"src/routes.ts","line":1,"catalogSignals":["sink: query("]}],"notes":[]}}
JSON
    ;;
  *)
    echo '{"ok":false,"error":"unexpected taint-iris-next request"}'
    exit 1
    ;;
esac
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_carlini_bridge(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("carlini-bridge.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"findings":[{"ruleId":"carlini-threat-hunt/actor-xss","filePath":"src/app.ts","startLine":9,"severity":"ERROR","message":"Actor-controlled input reaches HTML response","confidence":"HIGH","evidence":"Source: request query -> sink: response HTML"}]}}
JSON
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_systems_hunt_bridge(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("systems-hunt-bridge.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
request="$(cat)"
case "$request" in
  *"Systems Hunt invariant extractor"*)
    cat <<'JSON'
{"ok":true,"structured":{"invariants":[{"id":"inv-1","surfaceId":"surface-1","kind":"length-buffer-coupling","summary":"packet length must fit the fixed buffer","statement":"length is checked before copy","rationale":"copy uses packet-controlled length","evidence":["memcpy"],"attackerControlledFields":["len"],"cheapVerifiable":true}]}}
JSON
    ;;
  *"Systems Hunt trigger synthesizer"*)
    cat <<'JSON'
{"ok":true,"structured":{"triggers":[{"id":"trig-1","surfaceId":"surface-1","orderedSteps":["send oversized packet"],"boundaryAssignments":{"len":"4096"},"statePreconditions":["connected"],"attackerControlledFields":["len"],"expectedPrimitive":"stack overwrite","cheapVerifiable":true,"rationale":"length reaches memcpy"}]}}
JSON
    ;;
  *"Systems Hunt low-level vulnerability hunter"*)
    cat <<'JSON'
{"ok":true,"structured":{"findings":[{"title":"Oversized packet length reaches fixed buffer","cwe":"CWE-787","severity":"ERROR","filePath":"src/parser.c","startLine":3,"message":"packet length is copied into a 64-byte stack buffer","reasoning":"len comes from the packet header","triggerHypothesisIds":["trig-1"],"violatedInvariantIds":["inv-1"],"triggerSequence":["send len=4096"],"attackerControlledFields":["len"],"memoryPrimitive":"stack overwrite","cheapVerifiable":true}]}}
JSON
    ;;
  *)
    echo '{"ok":false,"error":"unexpected systems-hunt request"}'
    exit 1
    ;;
esac
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    fn write_systems_hunt_fixture(dir: &PathBuf) {
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(
            dir.join("src/parser.c"),
            "void parse(char *packet, uint16_t len) {\n  char buf[64];\n  memcpy(buf, packet, len);\n}\n",
        )
        .unwrap();
    }

    fn write_carlini_threat_model_fixture(dir: &PathBuf) {
        let state_dir = dir.join(".kuzushi");
        fs::create_dir_all(&state_dir).unwrap();
        fs::write(
            state_dir.join("threat-model.json"),
            r#"{"version":"2.0","dfd":{"nodes":[{"id":"actor-user","type":"external-entity","name":"Authenticated User","description":"External authenticated user","trustZone":"external"},{"id":"web","type":"process","name":"Web","description":"Web app","trustZone":"internal"}],"flows":[{"id":"flow-1","sourceId":"actor-user","targetId":"web","description":"profile request","trustBoundaryIds":["tb-1"],"protocol":"https"}],"trustBoundaries":[{"id":"tb-1","name":"edge","innerZone":"internal","outerZone":"external","crossingFlowIds":["flow-1"]}]},"threats":[{"id":"T-001","actorIds":["actor-user"],"flowIds":["flow-1"],"targetElementIds":["web"],"category":"tampering","title":"Profile HTML injection","description":"query reaches HTML","attackVector":"crafted profile query","impact":"high","likelihood":"medium","affectedFiles":[{"filePath":"src/app.ts","startLine":9}]}],"summary":{"total":1,"bySeverity":{"high":1},"byCategory":{"tampering":1}}}"#,
        )
        .unwrap();
    }

    #[cfg(unix)]
    fn fake_verify_bridge(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("verify-bridge.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"fingerprint":"fp-from-bridge","exploitable":true,"poc_payload":"curl -X POST /admin","poc_description":"POST reaches admin sink","attack_vector":"curl POST /admin","preconditions":["network access"],"confidence":0.84,"proof_level":3,"proof_verdict":"exploited"}}
JSON
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_patch_bridge(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("patch-bridge.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"diff":"--- a/src/db.ts\n+++ b/src/db.ts\n@@ -1 +1 @@\n-const query = req.query.q;\n+const query = String(req.query.q).replace(/[^a-z0-9]/gi, \"\");\n","explanation":"sanitize query input"}}
JSON
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn init_git_repo(dir: &PathBuf) {
        for args in [
            vec!["init"],
            vec!["config", "user.email", "kuzushi@example.test"],
            vec!["config", "user.name", "Kuzushi Test"],
            vec!["add", "."],
            vec!["commit", "-m", "fixture"],
        ] {
            let output = std::process::Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[cfg(unix)]
    fn fake_threat_model_bridge(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("threat-model-bridge.sh");
        fs::write(
            &binary,
            r#"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"document":{"version":"2.0","dfd":{"nodes":[{"id":"actor-user","type":"external-entity","name":"User","description":"External user","trustZone":"external"},{"id":"web","type":"process","name":"Web","description":"Web app","trustZone":"internal"}],"flows":[{"id":"flow-1","description":"request","sourceId":"actor-user","targetId":"web","trustBoundaryIds":["tb-1"]}],"trustBoundaries":[{"id":"tb-1","name":"edge","innerZone":"internal","outerZone":"external","crossingFlowIds":["flow-1"]}]},"threats":[{"id":"T-001","targetElementIds":["web"],"category":"spoofing","title":"Spoofed login","description":"stolen token","attackVector":"token theft","preconditions":[],"impact":"high","likelihood":"medium","existingMitigations":[],"missingMitigations":["bind sessions"],"relatedCwe":["CWE-287"],"affectedFiles":[{"filePath":"src/auth.ts","startLine":1}]}],"summary":{"total":1,"bySeverity":{"high":1},"byCategory":{"spoofing":1}}}}}
JSON
"#,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[cfg(unix)]
    fn fake_x_ray_bridge(dir: &PathBuf) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binary = dir.join("x-ray-bridge.sh");
        fs::write(
            &binary,
            r##"#!/bin/sh
cat >/dev/null
cat <<'JSON'
{"ok":true,"structured":{"xRayMarkdown":"# X-Ray\n\n## X-Ray Verdict\nWATCH\nReview invariants before launch.\n","entryPointsMarkdown":"# Entry Points\n\n> App | 1 entry point | 1 permissionless | 0 role-gated | 0 admin-only\n","invariantsMarkdown":"# Invariants\n\n### G-1 Balance conservation\n","architectureSvg":"<svg xmlns=\"http://www.w3.org/2000/svg\" />\n"}}
JSON
"##,
        )
        .unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        binary
    }

    #[test]
    fn help_command_routes_to_rust_shell_help_without_removed_cli_paths() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_command(parse_command("/help"));

        assert_eq!(app.shell_view, ShellView::Help);
        let help_log = app
            .log
            .iter()
            .filter(|line| line.prefix == "help")
            .map(|line| line.body.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(help_log.contains("/modules"));
        assert!(help_log.contains("/tools"));
        assert!(help_log.contains("/run <tool> [json]"));
        assert!(!help_log.contains("--load"));
        assert!(!help_log.contains("Ink"));
        assert!(!help_log.contains("TypeScript"));
    }

    #[test]
    fn completion_covers_commands_stateful_arguments_and_config_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-complete", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.rule",
            "src/app.ts",
            8,
            Some(8),
            Severity::High,
            "dangerous sink",
        );
        store.insert_finding("run-complete", &finding).unwrap();

        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.scan = Some(ScanPanelState {
            run_id: Some("run-active-123".to_string()),
            target: workspace.root().to_path_buf(),
            stage: "completed".to_string(),
            findings_count: 1,
            running: false,
            error: None,
        });
        app.kb_view.attachments = vec![AttachmentRecord {
            id: "A-123456789abc".to_string(),
            module_id: "context".to_string(),
            kind: kuzushi_core::AttachmentKind::Path,
            source: "README.md".to_string(),
            title: "README.md".to_string(),
            metadata_only: false,
            content_hash: Some("abc".to_string()),
            byte_count: Some(3),
            status: "indexed".to_string(),
            updated_at_unix: 1,
        }];

        for expected in ["/options", "/tasks", "/kb", "/context", "/auth"] {
            assert!(
                app.completion_candidates("/")
                    .iter()
                    .any(|candidate| candidate == expected),
                "missing slash completion {expected}"
            );
        }
        assert!(app.completion_candidates("m").contains(&"m".to_string()));
        assert!(app
            .completion_candidates("use sa")
            .contains(&"use sast".to_string()));
        assert!(app
            .completion_candidates("run sem")
            .contains(&"run semgrep:scan".to_string()));
        assert!(app
            .completion_candidates("set tri")
            .contains(&"set triage".to_string()));
        assert!(app
            .completion_candidates("task block co")
            .contains(&"task block codeql".to_string()));
        assert!(app
            .completion_candidates("open F-")
            .contains(&"open F-0001".to_string()));
        assert!(app
            .completion_candidates("replay run-")
            .contains(&"replay run-active-123".to_string()));
        assert!(app
            .completion_candidates("config runtime.")
            .contains(&"config runtime.kind".to_string()));
        assert!(app
            .completion_candidates("detach A-")
            .contains(&"detach A-123456789abc".to_string()));
    }

    #[test]
    fn command_reducer_updates_model_without_terminal() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_command(ShellCommand::Model(Some("openai:gpt-4.1".to_string())));

        assert_eq!(app.config.model.as_deref(), Some("openai:gpt-4.1"));
        assert!(app.log.iter().any(|line| line.prefix == "model"));
    }

    #[test]
    fn command_reducer_focuses_existing_module() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_command(ShellCommand::Use("semgrep".to_string()));

        assert_eq!(app.focused_module.as_deref(), Some("semgrep"));
    }

    #[test]
    fn findings_command_loads_store_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.rule",
            "src/app.ts",
            8,
            Some(8),
            Severity::High,
            "dangerous sink",
        );
        store.insert_finding("run-1", &finding).unwrap();

        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::Findings);

        assert_eq!(app.findings.len(), 1);
        assert_eq!(app.shell_view, ShellView::Findings);
    }

    #[test]
    fn open_command_accepts_deterministic_finding_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.rule",
            "src/app.ts",
            8,
            Some(8),
            Severity::High,
            "dangerous sink",
        );
        store.insert_finding("run-1", &finding).unwrap();

        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::Open("F-0001".to_string()));

        assert_eq!(app.shell_view, ShellView::Finding);
        assert_eq!(
            app.selected_finding
                .as_ref()
                .map(|finding| finding.fingerprint.as_str()),
            Some(finding.fingerprint.as_str())
        );
    }

    #[test]
    fn run_command_dispatches_focused_module_tool_through_registry() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::Use("dep-hygiene".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: None,
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "result"
                && line.body.contains("dep-hygiene: 1 risky specifier")));
    }

    #[test]
    fn run_command_dispatches_context_build_and_writes_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n",
        )
        .unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::Use("context".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(r#"{"sampleLimit":10}"#.to_string()),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app.log.iter().any(|line| {
            line.prefix == "result" && line.body.contains("context:build indexed 2 files")
        }));
        assert!(app.context_view.exists);
        assert!(workspace
            .root()
            .join(".kuzushi/context-snapshot.json")
            .exists());
    }

    #[test]
    fn run_dot_dispatches_focused_default_tool() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n",
        )
        .unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(parse_command("use context"));
        app.handle_command(parse_command(r#"run . {"sampleLimit":10}"#));

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app.context_view.exists);
        assert!(app.log.iter().any(|line| {
            line.prefix == "result" && line.body.contains("context:build indexed 2 files")
        }));
    }

    #[test]
    fn context_build_command_dispatches_context_build_and_writes_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n",
        )
        .unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        app.handle_command(ShellCommand::Context(ContextCommand::Build));

        assert_eq!(app.shell_view, ShellView::Context);
        assert_eq!(app.focused_module.as_deref(), Some("context"));
        assert!(app.context_view.exists);
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "result"
                && line.body.contains("context:build indexed 2 files")));
        assert!(workspace
            .root()
            .join(".kuzushi/context-snapshot.json")
            .exists());
    }

    #[test]
    fn context_status_displays_existing_snapshot_or_missing_state() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        app.handle_command(ShellCommand::Context(ContextCommand::Status));

        assert_eq!(app.shell_view, ShellView::Context);
        assert!(!app.context_view.exists);
        assert!(app.context_view.status.contains("missing"));

        app.handle_command(ShellCommand::Context(ContextCommand::Build));
        app.handle_command(ShellCommand::Context(ContextCommand::Show));

        assert!(app.context_view.exists);
        assert!(app.context_view.status.contains("snapshot present"));
    }

    #[test]
    fn context_regen_unknown_slice_is_actionable_and_does_not_mutate_state() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        app.handle_command(ShellCommand::Context(ContextCommand::Regen(
            "routes".to_string(),
        )));

        let error = app
            .log
            .iter()
            .rev()
            .find(|line| line.prefix == "error")
            .map(|line| line.body.as_str())
            .unwrap_or_default();
        assert!(error.contains("unknown context slice"));
        assert!(error.contains("Next: context regen repo"));
        assert!(!workspace
            .root()
            .join(".kuzushi/context-snapshot.json")
            .exists());
    }

    #[test]
    fn workspace_status_reports_no_active_workspace() {
        let mut app = ShellApp::new(V2Config::default(), None);

        app.handle_command(ShellCommand::Workspace(WorkspaceCommand::Status));

        assert_eq!(app.shell_view, ShellView::Workspace);
        assert_eq!(app.workspace_view.root, None);
        assert!(app.workspace_view.status.contains("no active workspace"));
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "workspace"
                && line.body.contains("start shell with --target")));
    }

    #[test]
    fn workspace_export_findings_to_temp_path() {
        let tmp = tempfile::tempdir().unwrap();
        let export_dir = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        store
            .insert_finding(
                "run-1",
                &Finding::new_tool(
                    "fixture",
                    "fixture/path",
                    "src/app.ts",
                    7,
                    None,
                    Severity::High,
                    "request data reaches sink",
                ),
            )
            .unwrap();
        let output = export_dir.path().join("findings.json");
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        app.handle_command(ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
            output: output.clone(),
        }));

        assert_eq!(app.shell_view, ShellView::Workspace);
        assert_eq!(app.workspace_view.findings_count, Some(1));
        assert_eq!(
            app.workspace_view.last_export.as_deref(),
            Some(output.as_path())
        );
        let exported: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(exported["count"], serde_json::json!(1));
        assert_eq!(
            exported["findings"][0]["message"],
            "request data reaches sink"
        );
    }

    #[test]
    fn workspace_export_rejects_unsupported_formats_actionably() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        app.handle_command(ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
            output: tmp.path().join("findings.sarif"),
        }));

        let error = app
            .log
            .iter()
            .rev()
            .find(|line| line.prefix == "error")
            .map(|line| line.body.as_str())
            .unwrap_or_default();
        assert!(error.contains("unsupported workspace findings export extension"));
        assert!(error.contains("Next: workspace export findings findings.json"));
        assert!(!tmp.path().join("findings.sarif").exists());
    }

    #[test]
    fn run_command_applies_session_options_to_focused_module_tool() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n",
        )
        .unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(tmp.path().join("src/lib.rs"), "pub fn demo() {}\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.option_store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("context:build".to_string()),
            "sampleLimit",
            serde_json::json!(1),
        );
        app.handle_command(ShellCommand::Use("context".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: None,
        });

        let snapshot =
            fs::read_to_string(workspace.root().join(".kuzushi/context-snapshot.json")).unwrap();
        let snapshot: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
        assert_eq!(
            snapshot["filesSample"].as_array().unwrap().len(),
            1,
            "stored sampleLimit should affect focused-module run"
        );
    }

    #[test]
    fn explicit_run_input_overrides_stored_tool_options() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n",
        )
        .unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(tmp.path().join("src/lib.rs"), "pub fn demo() {}\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.option_store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("context:build".to_string()),
            "sampleLimit",
            serde_json::json!(1),
        );
        app.handle_command(ShellCommand::Use("context".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(r#"{"sampleLimit":2}"#.to_string()),
        });

        let snapshot =
            fs::read_to_string(workspace.root().join(".kuzushi/context-snapshot.json")).unwrap();
        let snapshot: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
        assert_eq!(
            snapshot["filesSample"].as_array().unwrap().len(),
            2,
            "explicit run input should beat stored options"
        );
    }

    #[test]
    fn scan_path_reads_stored_sast_options() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.option_store.set_value(
            OptionScope::Session,
            OptionTarget::Tool("sast:scan".to_string()),
            "severity",
            serde_json::json!("critical,high"),
        );

        let options = app.scan_options_from_store().unwrap();

        assert_eq!(
            options.severity,
            Some(vec![Severity::Critical, Severity::High])
        );
    }

    #[test]
    fn task_commands_update_sast_scan_selection_options() {
        let mut app = ShellApp::new(V2Config::default(), None);

        app.handle_command(ShellCommand::Tasks);
        assert_eq!(app.shell_view, ShellView::SastTasks);
        assert_eq!(app.focused_module.as_deref(), Some("sast"));

        app.handle_command(ShellCommand::Task(SastTaskCommand::Block(
            "semgrep".to_string(),
        )));
        let prepared = app
            .registry
            .prepare_tool_input("sast:scan", serde_json::json!({}), Some(&app.option_store))
            .unwrap();
        assert_eq!(prepared["disabledTasks"], serde_json::json!("semgrep"));

        let scan_options = app.scan_options_from_store().unwrap();
        assert_eq!(
            scan_options.tasks,
            Some(vec![
                "dep-hygiene".to_string(),
                "secret-scan".to_string(),
                "iac-scan".to_string()
            ])
        );
    }

    #[test]
    fn task_mode_manual_seeds_and_allows_tasks_for_sast_scan() {
        let mut app = ShellApp::new(V2Config::default(), None);

        app.handle_command(ShellCommand::Task(SastTaskCommand::Mode(
            SastTaskModeCommand::Manual,
        )));
        app.handle_command(ShellCommand::Task(SastTaskCommand::Allow(
            "codeql".to_string(),
        )));

        let prepared = app
            .registry
            .prepare_tool_input("sast:scan", serde_json::json!({}), Some(&app.option_store))
            .unwrap();
        assert_eq!(prepared["taskMode"], serde_json::json!("manual"));
        assert!(prepared["tasks"]
            .as_str()
            .is_some_and(|tasks| tasks.split(',').any(|task| task == "codeql")));
    }

    #[test]
    fn unknown_task_id_lists_valid_ids_and_does_not_mutate_state() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_command(ShellCommand::Task(SastTaskCommand::Block(
            "semgrep".to_string(),
        )));
        let before = app.option_store.clone();

        app.handle_command(ShellCommand::Task(SastTaskCommand::Allow(
            "bogus-task".to_string(),
        )));

        assert_eq!(app.option_store, before);
        let error = app
            .log
            .iter()
            .rev()
            .find(|line| line.prefix == "error")
            .map(|line| line.body.as_str())
            .unwrap_or_default();
        assert!(error.contains("unknown SAST task"));
        assert!(error.contains("semgrep"));
        assert!(error.contains("codeql"));
        assert!(error.contains("Next: /tasks"));
    }

    #[test]
    fn kb_attach_detach_and_reparse_store_under_v2() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("notes.md"), "first\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::Use("threat-model".to_string()));

        app.handle_command(ShellCommand::Attach("notes.md".to_string()));

        assert_eq!(app.shell_view, ShellView::KnowledgeBase);
        assert_eq!(app.kb_view.module_id, "threat-model");
        assert!(workspace
            .root()
            .join(".kuzushi/v2/attachments.json")
            .exists());
        let record = app
            .kb_view
            .attachments
            .iter()
            .find(|record| record.module_id == "threat-model")
            .cloned()
            .unwrap();
        assert_eq!(record.source, "notes.md");
        let first_hash = record.content_hash.clone();

        fs::write(tmp.path().join("notes.md"), "second\n").unwrap();
        app.handle_command(ShellCommand::Reparse(record.id.clone()));
        let reparsed = app
            .kb_view
            .attachments
            .iter()
            .find(|candidate| candidate.id == record.id)
            .unwrap();
        assert_ne!(first_hash, reparsed.content_hash);

        app.handle_command(ShellCommand::Detach(record.id));
        assert!(app.kb_view.attachments.is_empty());
    }

    #[test]
    fn kb_records_url_metadata_without_fetching() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::KnowledgeBase(Some("x-ray".to_string())));
        app.handle_command(ShellCommand::Attach(
            "https://example.test/x-ray-notes".to_string(),
        ));

        let record = app
            .kb_view
            .attachments
            .iter()
            .find(|record| record.module_id == "x-ray")
            .unwrap();
        assert!(record.metadata_only);
        assert!(record.status.contains("not fetched"));
        assert_eq!(record.content_hash, None);
    }

    #[test]
    fn kb_rejects_unsafe_paths_and_unknown_modules() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        app.handle_command(ShellCommand::KnowledgeBase(Some("unknown".to_string())));
        let unknown_module = app
            .log
            .iter()
            .rev()
            .find(|line| line.prefix == "error")
            .map(|line| line.body.clone())
            .unwrap_or_default();
        assert!(unknown_module.contains("Supported KB modules"));

        app.handle_command(ShellCommand::Attach(outside.path().display().to_string()));
        let unsafe_path = app
            .log
            .iter()
            .rev()
            .find(|line| line.prefix == "error")
            .map(|line| line.body.clone())
            .unwrap_or_default();
        assert!(unsafe_path.contains("escapes workspace root"));
    }

    #[test]
    fn options_command_resolves_default_tool_and_set_updates_session_store() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("Cargo.toml"),
            "[package]\nname = \"fixture\"\n",
        )
        .unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(tmp.path().join("src/lib.rs"), "pub fn demo() {}\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));

        app.handle_command(ShellCommand::Use("context".to_string()));
        app.handle_command(ShellCommand::Options {
            tool: None,
            filter: OptionsFilter::Standard,
        });
        app.handle_command(ShellCommand::SetOption {
            global: false,
            name: "sampleLimit".to_string(),
            value: "1".to_string(),
        });
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: None,
        });

        let snapshot =
            fs::read_to_string(workspace.root().join(".kuzushi/context-snapshot.json")).unwrap();
        let snapshot: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
        assert_eq!(snapshot["filesSample"].as_array().unwrap().len(), 1);
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "set" && line.body.contains("context:build.sampleLimit")));
    }

    #[test]
    fn setg_and_unsetg_apply_global_shell_options() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_command(ShellCommand::Options {
            tool: Some("sast:scan".to_string()),
            filter: OptionsFilter::Standard,
        });
        app.handle_command(ShellCommand::SetOption {
            global: true,
            name: "triage".to_string(),
            value: "true".to_string(),
        });

        let prepared = app
            .registry
            .prepare_tool_input("sast:scan", serde_json::json!({}), Some(&app.option_store))
            .unwrap();
        assert_eq!(prepared["triage"], serde_json::json!(true));

        app.handle_command(ShellCommand::UnsetOption {
            global: true,
            name: "triage".to_string(),
        });
        let prepared = app
            .registry
            .prepare_tool_input("sast:scan", serde_json::json!({}), Some(&app.option_store))
            .unwrap();
        assert_eq!(prepared["triage"], serde_json::json!(false));
    }

    #[test]
    fn unknown_option_reports_closest_names_and_next_command() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_command(ShellCommand::Options {
            tool: Some("context:build".to_string()),
            filter: OptionsFilter::Standard,
        });
        app.handle_command(ShellCommand::SetOption {
            global: false,
            name: "sampleLmit".to_string(),
            value: "1".to_string(),
        });

        let error = app
            .log
            .iter()
            .rev()
            .find(|line| line.prefix == "error")
            .map(|line| line.body.as_str())
            .unwrap_or_default();
        assert!(error.contains("Closest: sampleLimit"));
        assert!(error.contains("Next: show options context:build"));
    }

    #[test]
    fn auth_provider_backend_model_and_cost_commands_are_explicit_and_secret_safe() {
        let mut config = V2Config::default();
        config.runtime.api_key_env = "KUZUSHI_BG011_TEST_SECRET".to_string();
        config.model = Some("openai:gpt-4.1".to_string());
        let mut app = ShellApp::new(config, None);

        app.handle_command(ShellCommand::Auth);
        let auth = app
            .log
            .iter()
            .rev()
            .find(|line| line.prefix == "auth")
            .map(|line| line.body.as_str())
            .unwrap_or_default();
        assert!(auth.contains("KUZUSHI_BG011_TEST_SECRET"));
        assert!(auth.contains("secret values hidden"));
        assert!(auth.contains("openai-codex oauth"));
        assert!(!auth.contains("sk-"));

        app.handle_command(ShellCommand::Provider(None));
        assert!(app
            .log
            .iter()
            .any(|line| { line.prefix == "provider" && line.body.contains("openai") }));

        app.handle_command(ShellCommand::Backend(Some("not-a-backend".to_string())));
        assert!(app.log.iter().any(|line| {
            line.prefix == "error" && line.body.contains("Supported: pi-agent-core")
        }));

        app.handle_command(ShellCommand::Model(Some("gpt-4.1".to_string())));
        assert_eq!(app.config.model.as_deref(), Some("openai:gpt-4.1"));
        assert!(app
            .log
            .iter()
            .any(|line| { line.prefix == "error" && line.body.contains("provider:model") }));

        app.handle_command(ShellCommand::Model(Some("openai:gpt-4.1-mini".to_string())));
        assert_eq!(app.config.model.as_deref(), Some("openai:gpt-4.1-mini"));
        assert!(app
            .log
            .iter()
            .any(|line| { line.prefix == "model" && line.body.contains("no fallback model") }));

        app.handle_command(ShellCommand::Model(Some("1 xtrahigh".to_string())));
        assert_eq!(app.config.model.as_deref(), Some("openai:gpt-5.5"));
        assert_eq!(app.session_thinking_level.as_deref(), Some("xhigh"));

        app.handle_command(ShellCommand::Use("randori".to_string()));
        app.handle_command(ShellCommand::Model(Some("5 high".to_string())));
        let stored = app.option_store.effective_stored_values("randori:pasta");
        assert_eq!(
            stored.get("model").and_then(serde_json::Value::as_str),
            Some("anthropic:claude-sonnet-4-6")
        );
        assert_eq!(
            stored.get("effort").and_then(serde_json::Value::as_str),
            Some("high")
        );

        app.last_tool_cost_usd = Some(0.0123);
        app.session_cost_usd = 0.0456;
        app.handle_command(ShellCommand::Cost);
        assert!(app.log.iter().any(|line| {
            line.prefix == "cost" && line.body.contains("session estimate $0.0456")
        }));
    }

    #[test]
    fn config_view_onboards_with_keyboard_model_selection() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Config;
        app.selected_model_index = 0;

        app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::empty()));
        assert_eq!(app.selected_model_index, 1);

        app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::empty()));
        assert_eq!(app.selected_model_index, 0);

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
        assert_eq!(app.config.model.as_deref(), Some("openai:gpt-5.5"));
        assert_eq!(app.session_thinking_level.as_deref(), Some("xhigh"));
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "model" && line.body.contains("selected via onboarding")));
    }

    #[test]
    fn ask_requires_explicit_model_and_unknown_prose_stays_deterministic() {
        let mut app = ShellApp::new(V2Config::default(), None);

        app.handle_command(parse_command("summarize this repo"));

        assert_eq!(app.shell_view, ShellView::Catalog);
        assert!(app.agent_chat.is_none());
        assert!(app.log.iter().any(|line| {
            line.prefix == "error" && line.body.contains("Free-form chat is explicit only")
        }));

        app.handle_command(parse_command("/ask What should I run first?"));

        assert_eq!(app.shell_view, ShellView::AgentChat);
        let agent = app.agent_chat.as_ref().unwrap();
        assert_eq!(agent.question, "What should I run first?");
        assert!(!agent.running);
        assert!(agent
            .error
            .as_deref()
            .is_some_and(|error| error.contains("explicit model")));
    }

    #[test]
    fn session_history_clear_load_resume_pause_and_story_are_explicit() {
        let mut app = ShellApp::new(V2Config::default(), None);

        app.submit_line("modules");
        app.submit_line("/history");

        assert_eq!(app.shell_view, ShellView::History);
        assert_eq!(
            app.command_history,
            vec!["modules".to_string(), "/history".to_string()]
        );
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "history" && line.body.contains("2 command")));

        app.submit_line("/clear");

        assert_eq!(
            app.command_history,
            vec![
                "modules".to_string(),
                "/history".to_string(),
                "/clear".to_string()
            ]
        );
        assert_eq!(app.log.len(), 1);
        assert!(app.log[0].body.contains("Conversation cleared"));

        app.handle_command(parse_command("/load builtin:sast"));
        assert!(app
            .log
            .iter()
            .any(|line| { line.prefix == "load" && line.body.contains("already available") }));

        app.handle_command(parse_command("/load file:///tmp/module.js"));
        assert!(app.log.iter().any(|line| {
            line.prefix == "error"
                && line
                    .body
                    .contains("dynamic module loading is not supported")
        }));

        app.handle_command(parse_command("/pause"));
        assert!(app.log.iter().any(|line| {
            line.prefix == "pause" && line.body.contains("no live pause/resume control")
        }));

        app.handle_command(parse_command("/resume run-123"));
        assert_eq!(app.shell_view, ShellView::Replay("run-123".to_string()));
        assert!(app
            .log
            .iter()
            .any(|line| { line.prefix == "resume" && line.body.contains("replay run-123") }));

        app.handle_command(parse_command("/story"));
        assert_eq!(app.shell_view, ShellView::Story);
    }

    #[cfg(unix)]
    #[test]
    fn ask_dispatches_agent_question_through_explicit_runtime() {
        let tmp = tempfile::tempdir().unwrap();
        let bridge = fake_ask_bridge(&tmp.path().to_path_buf());
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        config.runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "KUZUSHI_TEST_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![bridge.display().to_string()]),
            anthropic_oauth: None,
        };
        let mut app = ShellApp::new(config, None);

        app.handle_command(parse_command("?What should I run first?"));

        assert_eq!(app.shell_view, ShellView::AgentChat);
        assert!(app.agent_chat.as_ref().is_some_and(|agent| agent.running));
        for _ in 0..50 {
            app.drain_background_events();
            if app.agent_chat.as_ref().is_some_and(|agent| !agent.running) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let agent = app.agent_chat.as_ref().unwrap();
        assert!(!agent.running);
        assert_eq!(
            agent.answer.as_deref(),
            Some("Run context build, then scan .")
        );
        assert!(app
            .log
            .iter()
            .any(|line| { line.prefix == "answer" && line.body.contains("Run context build") }));
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_recon_nmap_through_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let binary = fake_nmap_binary(&tmp.path().to_path_buf());
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::Use("recon".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: Some("nmap".to_string()),
            input: Some(format!(
                r#"{{"target":"192.0.2.10","ports":"80,443","binary":"{}"}}"#,
                binary.display()
            )),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app.log.iter().any(|line| {
            line.prefix == "result"
                && line
                    .body
                    .contains("recon:nmap discovered 1 host and 2 open services")
        }));
        let mut store = kuzushi_core::ReconWorkspaceStore::open(&workspace).unwrap();
        let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
        let hosts = store.list_hosts(&workspace_id).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(store.list_services_for_host(&hosts[0].id).unwrap().len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_recon_http_fingerprint_through_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let binary = fake_curl_binary(&tmp.path().to_path_buf());
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::Use("recon".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: Some("http-fingerprint".to_string()),
            input: Some(format!(
                r#"{{"target":"https://www.example.com","binary":"{}"}}"#,
                binary.display()
            )),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app.log.iter().any(|line| {
            line.prefix == "result"
                && line
                    .body
                    .contains("recon:http-fingerprint registered https://www.example.com")
        }));
        let mut store = kuzushi_core::ReconWorkspaceStore::open(&workspace).unwrap();
        let workspace_id = store.ensure_default_workspace(workspace.root()).unwrap();
        let hosts = store.list_hosts(&workspace_id).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(store.list_services_for_host(&hosts[0].id).unwrap().len(), 1);
    }

    #[test]
    fn run_command_dispatches_secret_scan_through_registry() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("config.env"),
            [
                "OPENAI_API_KEY=",
                "sk",
                "-proj-",
                "abcdefghijklmnopqrstuvwxyzABCDEFGH",
            ]
            .concat(),
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::Use("secret-scan".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: None,
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app.log.iter().any(|line| {
            line.prefix == "result" && line.body.contains("secret-scan: 1 finding")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_semgrep_through_registry_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("server.js"), "res.send(req.query.x)\n").unwrap();
        let binary = fake_semgrep_binary(&tmp.path().to_path_buf());
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::Use("semgrep".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(format!(
                r#"{{"binary":"{}","config":"p/security-audit"}}"#,
                binary.display()
            )),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "result" && line.body.contains("semgrep: 1 finding")));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_codeql_through_registry_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("package.json"), "{}\n").unwrap();
        fs::write(tmp.path().join("server.js"), "db.query(req.query.q)\n").unwrap();
        let binary = fake_codeql_binary(&tmp.path().to_path_buf());
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::Use("codeql".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(format!(
                r#"{{"binary":"{}","language":"javascript"}}"#,
                binary.display()
            )),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "result" && line.body.contains("codeql: 1 finding")));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        assert_eq!(store.list_findings(10).unwrap().len(), 1);
    }

    #[test]
    fn run_command_dispatches_iac_scan_through_registry_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("main.tf"),
            "cidr_blocks = [\"0.0.0.0/0\"]\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::Use("iac-scan".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(r#"{"kind":"terraform"}"#.to_string()),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "result" && line.body.contains("iac-scan: 1 finding")));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "iac-scan");
    }

    #[test]
    fn run_command_dispatches_sast_scan_through_registry_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();
        fs::write(
            tmp.path().join("config.env"),
            [
                "OPENAI_API_KEY=",
                "sk",
                "-proj-",
                "abcdefghijklmnopqrstuvwxyzABCDEFGH",
            ]
            .concat(),
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::Use("sast".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(
                r#"{"taskMode":"manual","tasks":["dep-hygiene","secret-scan"]}"#.to_string(),
            ),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "result" && line.body.contains("sast:scan")));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        assert_eq!(store.list_findings(10).unwrap().len(), 2);
    }

    #[test]
    fn run_dot_from_catalog_dispatches_sast_scan() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();
        fs::write(
            tmp.path().join("config.env"),
            [
                "OPENAI_API_KEY=",
                "sk",
                "-proj-",
                "abcdefghijklmnopqrstuvwxyzABCDEFGH",
            ]
            .concat(),
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(parse_command(
            r#"run . {"taskMode":"manual","tasks":["dep-hygiene","secret-scan"]}"#,
        ));

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app.focused_module.is_none());
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "tool" && line.body.contains("running sast:scan")));
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "result" && line.body.contains("sast:scan")));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        assert_eq!(store.list_findings(10).unwrap().len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_agentic_sast_through_pi_agent_core_bridge_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let bridge = fake_agentic_bridge(&tmp.path().to_path_buf());
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        config.runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![bridge.display().to_string()]),
            anthropic_oauth: None,
        };

        let mut app = ShellApp::new(config, Some(&workspace));
        app.handle_command(ShellCommand::Use("agentic-sast".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(r#"{"maxFindings":5}"#.to_string()),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app.log.iter().any(|line| {
            line.prefix == "result" && line.body.contains("agentic-sast: 1 finding")
        }));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "agentic");
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_variant_hunt_through_pi_agent_core_bridge_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/app.ts"), "exec(req.body.cmd)\n").unwrap();
        fs::write(tmp.path().join("src/other.ts"), "exec(req.body.other)\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let fingerprint = seed_true_positive_finding(&workspace);
        let bridge = fake_variant_bridge(&tmp.path().to_path_buf());
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        config.runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![bridge.display().to_string()]),
            anthropic_oauth: None,
        };

        let mut app = ShellApp::new(config, Some(&workspace));
        app.handle_command(ShellCommand::Use("variant".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(format!(
                r#"{{"fingerprint":"{fingerprint}","maxFindings":5}}"#
            )),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app.log.iter().any(|line| {
            line.prefix == "result" && line.body.contains("variant:hunt complete")
        }));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(10).unwrap();
        assert!(findings
            .iter()
            .any(|finding| finding.tool == "variant-analysis"));
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_ndiff_hunt_through_pi_agent_core_bridge_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/parser.c"), "memcpy(dst, src, len)\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let bridge = fake_ndiff_bridge(&tmp.path().to_path_buf());
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        config.runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![bridge.display().to_string()]),
            anthropic_oauth: None,
        };

        let mut app = ShellApp::new(config, Some(&workspace));
        app.handle_command(ShellCommand::Use("ndiff".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: Some("hunt-variants".to_string()),
            input: Some(
                r#"{"advisoryId":"CVE-2024-1234","pattern":{"fixShape":"adds a bounds check before memcpy","vulnerableShape":"memcpy uses attacker-controlled length without a bounds check","cwe":["CWE-787"],"languages":["c"],"keywords":["memcpy","len"],"detectionQuery":"rg 'memcpy\\('","description":"Search copies guarded by no length cap.","confidence":"HIGH"}}"#
                    .to_string(),
            ),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app.log.iter().any(|line| {
            line.prefix == "result" && line.body.contains("ndiff:hunt-variants complete")
        }));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(10).unwrap();
        assert!(findings
            .iter()
            .any(|finding| finding.tool == "n-day-diff-hunter"));
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_taint_iris_through_pi_agent_core_bridge_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/db.ts"), "db.query(req.query.q)\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let bridge = fake_taint_iris_bridge(&tmp.path().to_path_buf());
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        config.runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![bridge.display().to_string()]),
            anthropic_oauth: None,
        };

        let mut app = ShellApp::new(config, Some(&workspace));
        app.handle_command(ShellCommand::Use("taint-iris".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(r#"{"maxFindings":5}"#.to_string()),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app.log.iter().any(|line| {
            line.prefix == "result" && line.body.contains("taint-iris: 1 finding")
        }));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "taint-iris");
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_taint_iris_next_through_pi_agent_core_bridge_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"express":"latest","prisma":"latest"}}"#,
        )
        .unwrap();
        fs::write(
            tmp.path().join("src/routes.ts"),
            "const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;\ndb.query(sql);\n",
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let bridge = fake_taint_iris_next_bridge(&tmp.path().to_path_buf());
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        config.runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![bridge.display().to_string()]),
            anthropic_oauth: None,
        };

        let mut app = ShellApp::new(config, Some(&workspace));
        app.handle_command(ShellCommand::Use("taint-iris-next".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(
                r#"{"mode":"hunt","maxCatalogEntries":3,"maxAgentFindings":5,"minEvidenceLevel":"candidate"}"#
                    .to_string(),
            ),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app
            .log
            .iter()
            .any(|line| { line.prefix == "result" && line.body.contains("Taint IRIS Next") }));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "taint-iris-next");
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_carlini_threat_hunt_through_pi_agent_core_bridge_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(
            tmp.path().join("src/app.ts"),
            "res.send(`<p>${req.query.name}</p>`)\n",
        )
        .unwrap();
        write_carlini_threat_model_fixture(&tmp.path().to_path_buf());
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let bridge = fake_carlini_bridge(&tmp.path().to_path_buf());
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        config.runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![bridge.display().to_string()]),
            anthropic_oauth: None,
        };

        let mut app = ShellApp::new(config, Some(&workspace));
        app.handle_command(ShellCommand::Use("carlini-threat-hunt".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(r#"{"maxActors":1,"runsPerActor":1}"#.to_string()),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app.log.iter().any(|line| {
            line.prefix == "result" && line.body.contains("carlini-threat-hunt: 1 finding")
        }));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "carlini-threat-hunt");
        assert_eq!(
            findings[0].actor_fingerprint.as_deref(),
            Some("carlini-threat-hunt:Authenticated_User:0")
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_systems_hunt_through_pi_agent_core_bridge_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        write_systems_hunt_fixture(&tmp.path().to_path_buf());
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let bridge = fake_systems_hunt_bridge(&tmp.path().to_path_buf());
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        config.runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![bridge.display().to_string()]),
            anthropic_oauth: None,
        };

        let mut app = ShellApp::new(config, Some(&workspace));
        app.handle_command(ShellCommand::RunTool {
            tool: Some("systems-hunt:systems-hunt".to_string()),
            input: Some(r#"{"maxFindings":5}"#.to_string()),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app.log.iter().any(|line| {
            line.prefix == "result" && line.body.contains("systems-hunt: 1 finding")
        }));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let findings = store.list_findings(10).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "systems-hunt");
    }

    #[test]
    fn run_command_dispatches_findings_filters_through_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            12,
            Some(12),
            Severity::High,
            "SQL injection in search",
        );
        let finding_id = store.insert_finding("run-1", &finding).unwrap();
        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "confirmed".to_string(),
                },
            )
            .unwrap();

        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::RunTool {
            tool: Some("findings:list".to_string()),
            input: Some(r#"{"severity":["high"],"verdict":["tp"],"name":"sql"}"#.to_string()),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app.log.iter().any(|line| {
            line.prefix == "result"
                && line.body.contains("SQL injection in search")
                && line.body.contains("1 matching")
        }));
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_triage_through_pi_agent_core_bridge_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            12,
            Some(12),
            Severity::High,
            "SQL injection in search",
        );
        store.insert_finding("run-1", &finding).unwrap();
        let bridge = fake_triage_bridge(&tmp.path().to_path_buf());
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        config.runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![bridge.display().to_string()]),
            anthropic_oauth: None,
        };

        let mut app = ShellApp::new(config, Some(&workspace));
        app.handle_command(ShellCommand::Use("triage".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(format!(r#"{{"fingerprint":"{}"}}"#, finding.fingerprint)),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "result" && line.body.contains("Triaged 1 of 1")));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let stored = store
            .get_finding_by_fingerprint(&finding.fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.triage.as_ref().map(|triage| triage.verdict),
            Some(TriageVerdict::TruePositive)
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_verify_through_pi_agent_core_bridge() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            12,
            Some(12),
            Severity::High,
            "SQL injection in search",
        );
        let finding_id = store.insert_finding("run-1", &finding).unwrap();
        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "confirmed".to_string(),
                },
            )
            .unwrap();
        let bridge = fake_verify_bridge(&tmp.path().to_path_buf());
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        config.runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![bridge.display().to_string()]),
            anthropic_oauth: None,
        };

        let mut app = ShellApp::new(config, Some(&workspace));
        app.handle_command(ShellCommand::Use("verify".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(format!(r#"{{"fingerprint":"{}"}}"#, finding.fingerprint)),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "result" && line.body.contains("VULNERABLE")));
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "result" && line.body.contains("curl POST /admin")));
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_patch_through_pi_agent_core_bridge_and_persists() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/db.ts"), "const query = req.query.q;\n").unwrap();
        init_git_repo(&tmp.path().to_path_buf());

        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.sql",
            "src/db.ts",
            1,
            Some(1),
            Severity::High,
            "SQL injection in search",
        );
        let finding_id = store.insert_finding("run-1", &finding).unwrap();
        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "confirmed".to_string(),
                },
            )
            .unwrap();
        let bridge = fake_patch_bridge(&tmp.path().to_path_buf());
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        config.runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![bridge.display().to_string()]),
            anthropic_oauth: None,
        };

        let mut app = ShellApp::new(config, Some(&workspace));
        app.handle_command(ShellCommand::Use("patch".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(format!(
                r#"{{"fingerprint":"{}","maxIterations":1,"buildCmd":"true","testCmd":"true"}}"#,
                finding.fingerprint
            )),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "result" && line.body.contains("patch:finding SOUND")));

        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        let patch_results = store
            .get_patch_results_for_finding(&finding.fingerprint)
            .unwrap();
        assert_eq!(patch_results.len(), 1);
        assert_eq!(patch_results[0].status.as_str(), "SOUND");
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_threat_model_build_through_pi_agent_core_bridge() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"express":"4"}}"#,
        )
        .unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let bridge = fake_threat_model_bridge(&tmp.path().to_path_buf());
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        config.runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![bridge.display().to_string()]),
            anthropic_oauth: None,
        };

        let mut app = ShellApp::new(config, Some(&workspace));
        app.handle_command(ShellCommand::Use("threat-model".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: None,
            input: Some(r#"{"outputDir":".kuzushi/tm"}"#.to_string()),
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app.log.iter().any(|line| {
            line.prefix == "result" && line.body.contains("threat-model:build complete")
        }));
        assert!(tmp.path().join(".kuzushi/threat-model.json").exists());
        assert!(tmp
            .path()
            .join(".kuzushi/tm/normalized-threat-model.json")
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn run_command_dispatches_x_ray_run_through_pi_agent_core_bridge() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("README.md"), "# app\n").unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let bridge = fake_x_ray_bridge(&tmp.path().to_path_buf());
        let mut config = V2Config::default();
        config.model = Some("openai:gpt-4.1".to_string());
        config.runtime = RuntimeConfig {
            kind: RuntimeKind::PiAgentCore,
            api_key_env: "OPENAI_API_KEY".to_string(),
            base_url: None,
            agent_bridge_command: Some(vec![bridge.display().to_string()]),
            anthropic_oauth: None,
        };

        let mut app = ShellApp::new(config, Some(&workspace));
        app.handle_command(ShellCommand::Use("x-ray".to_string()));
        app.handle_command(ShellCommand::RunTool {
            tool: Some("x-ray:run".to_string()),
            input: None,
        });

        assert_eq!(app.shell_view, ShellView::ModuleRun);
        assert!(app
            .log
            .iter()
            .any(|line| { line.prefix == "result" && line.body.contains("x-ray:run complete") }));
        assert!(workspace.root().join("x-ray/x-ray.md").exists());
        assert!(workspace.root().join("x-ray/architecture.svg").exists());
    }

    #[test]
    fn open_command_selects_finding_by_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.rule",
            "src/app.ts",
            8,
            Some(8),
            Severity::High,
            "dangerous sink",
        );
        store.insert_finding("run-1", &finding).unwrap();

        let mut app = ShellApp::new(V2Config::default(), Some(&workspace));
        app.handle_command(ShellCommand::Open(finding.fingerprint[..8].to_string()));

        assert_eq!(
            app.selected_finding
                .as_ref()
                .map(|finding| &finding.fingerprint),
            Some(&finding.fingerprint)
        );
    }

    #[test]
    fn ctrl_c_cancels_active_scan_before_exit() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.scan = Some(ScanPanelState {
            run_id: Some("run-1".to_string()),
            target: PathBuf::from("."),
            stage: "running semgrep".to_string(),
            findings_count: 0,
            running: true,
            error: None,
        });

        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));

        assert!(!app.should_quit);
        assert_eq!(
            app.scan.as_ref().map(|scan| scan.stage.as_str()),
            Some("cancelling")
        );
    }

    #[test]
    fn threat_digit_hotkeys_switch_views_without_entering_input() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Threat(ThreatView::Summary);

        app.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::empty()));

        assert_eq!(app.shell_view, ShellView::Threat(ThreatView::Stride));
        assert!(app.input.is_empty());
    }

    #[test]
    fn first_ctrl_c_at_idle_arms_without_quitting() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(!app.should_quit);
        assert!(app.ctrl_c_armed());
    }

    #[test]
    fn second_ctrl_c_within_window_quits() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.should_quit);
    }

    #[test]
    fn ctrl_d_also_arms_and_quits() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL));
        assert!(app.ctrl_c_armed());
        assert!(!app.should_quit);
        app.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL));
        assert!(app.should_quit);
    }

    #[test]
    fn any_other_key_disarms() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(app.ctrl_c_armed());
        app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::empty()));
        assert!(!app.ctrl_c_armed());
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(!app.should_quit);
    }

    #[test]
    fn arm_window_expires_via_tick() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.ctrl_c_armed_at = Some(Instant::now() - (CTRL_C_ARM_WINDOW + Duration::from_secs(1)));
        assert!(!app.ctrl_c_armed());
        app.tick();
        assert!(app.ctrl_c_armed_at.is_none());
    }

    #[test]
    fn throttle_advisory_set_and_clear() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_throttle("openai", "429: backing off 2s");
        assert!(app.advisory.throttle.is_some());
        app.clear_throttle();
        assert!(app.advisory.throttle.is_none());
    }

    #[test]
    fn throttle_advisory_expires_via_tick() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_throttle("openai", "stale");
        app.advisory.throttle.as_mut().unwrap().since =
            Instant::now() - (THROTTLE_STALE_AFTER + Duration::from_secs(1));
        app.tick();
        assert!(app.advisory.throttle.is_none());
    }

    #[test]
    fn budget_halt_triggers_when_cost_exceeds_cap() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.session_budget_usd = Some(0.10);
        app.record_cost(0.12);
        assert!(app.is_budget_halted());
        let halt = app.advisory.budget_halt.as_ref().unwrap();
        assert!(halt.spent_usd >= 0.12);
        assert_eq!(halt.limit_usd, 0.10);
    }

    fn make_finding(severity: Severity, fp: &str, title: &str) -> Finding {
        Finding {
            id: None,
            scan_id: None,
            fingerprint: fp.to_string(),
            rule_id: "test/rule".to_string(),
            title: title.to_string(),
            severity,
            file_path: "src/x.rs".to_string(),
            start_line: 1,
            end_line: None,
            message: String::new(),
            tool: "test".to_string(),
            actor_fingerprint: None,
            triage: None,
            created_at: String::new(),
            vuln_source: None,
            dedup_key: None,
        }
    }

    #[test]
    fn chain_alias_format_is_two_digit_zero_padded() {
        assert_eq!(format_chain_alias(0), "C-01");
        assert_eq!(format_chain_alias(8), "C-09");
        assert_eq!(format_chain_alias(9), "C-10");
    }

    #[test]
    fn parse_chain_alias_round_trips() {
        for case in ["C-01", "c-01", "C-99", "C-1"] {
            let parsed = parse_chain_alias(case).expect("valid");
            assert!(format_chain_alias(parsed).len() == 4);
        }
        assert!(parse_chain_alias("F-0001").is_none());
        assert!(parse_chain_alias("garbage").is_none());
    }

    #[test]
    fn sorted_chain_aliases_severity_then_id() {
        let chains = vec![
            ExploitChain {
                id: "z".to_string(),
                severity: ChainSeverity::Medium,
                title: "third".to_string(),
            },
            ExploitChain {
                id: "b".to_string(),
                severity: ChainSeverity::Critical,
                title: "first".to_string(),
            },
            ExploitChain {
                id: "a".to_string(),
                severity: ChainSeverity::Critical,
                title: "tied-but-earlier-id".to_string(),
            },
        ];
        let aliases = sorted_chain_aliases(&chains);
        assert_eq!(aliases[0].0, "C-01");
        assert_eq!(aliases[0].1.id, "a");
        assert_eq!(aliases[1].1.id, "b");
        assert_eq!(aliases[2].1.id, "z");
    }

    #[test]
    fn alias_table_emits_both_chain_and_finding_rows() {
        let findings = vec![
            make_finding(Severity::High, "ffff1111", "ssrf"),
            make_finding(Severity::Critical, "aaaa2222", "sqli"),
        ];
        let chains = vec![ExploitChain {
            id: "chain-1".to_string(),
            severity: ChainSeverity::High,
            title: "auth bypass".to_string(),
        }];
        let table = format_alias_table(&findings, &chains, None);
        assert!(table.contains("C-01"));
        assert!(table.contains("F-0001"));
        assert!(table.contains("F-0002"));
        // critical sorts ahead of high
        let f1_pos = table.find("F-0001").unwrap();
        let f2_pos = table.find("F-0002").unwrap();
        assert!(f1_pos < f2_pos);
    }

    #[test]
    fn alias_table_filters_by_prefix() {
        let findings = vec![make_finding(Severity::Medium, "abc12345", "x")];
        let chains = vec![ExploitChain {
            id: "c".to_string(),
            severity: ChainSeverity::Medium,
            title: "y".to_string(),
        }];
        let only_chains = format_alias_table(&findings, &chains, Some("C-"));
        assert!(only_chains.contains("C-01"));
        assert!(!only_chains.contains("F-0001"));
    }

    #[test]
    fn alias_table_handles_empty() {
        let table = format_alias_table(&[], &[], None);
        assert!(table.contains("No aliases"));
    }

    #[test]
    fn tune_set_writes_house_rules_and_reset_removes_them() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.target = Some(temp.path().to_path_buf());
        app.focused_module = Some("sast".to_string());
        app.shell_view = ShellView::Tune;
        app.submit_line("set \"focus on auth bypass\"");
        let path = temp.path().join(".kuzushi/house-rules/sast.md");
        assert!(path.exists());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "focus on auth bypass"
        );
        assert_eq!(
            app.read_house_rules().as_deref(),
            Some("focus on auth bypass")
        );
        app.submit_line("reset");
        assert!(!path.exists());
    }

    #[test]
    fn quickstart_emits_guided_help_lines() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_command(ShellCommand::Quickstart);
        assert_eq!(app.shell_view, ShellView::Help);
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "quickstart" && line.body.contains("/scan ./repo")));
    }

    #[test]
    fn target_command_switches_target_directory() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        let path_str = temp.path().to_string_lossy().to_string();
        app.handle_command(ShellCommand::Target(Some(path_str.clone())));
        let canonical = std::fs::canonicalize(temp.path()).unwrap();
        assert_eq!(app.target.as_deref(), Some(canonical.as_path()));
        // When called with no path, should report the current target.
        app.handle_command(ShellCommand::Target(None));
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "target" && line.body.contains("current target")));
    }

    #[test]
    fn paste_guard_swallows_enter_immediately_after_char() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.handle_key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::empty()));
        app.handle_key(KeyEvent::new(KeyCode::Char('i'), KeyModifiers::empty()));
        // Enter arrives within the paste-guard window; should NOT submit.
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
        assert_eq!(app.input, "hi", "input should not be drained");
        // After advancing past the guard window, Enter submits.
        app.last_char_at = Some(Instant::now() - (PASTE_GUARD_WINDOW + Duration::from_millis(20)));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()));
        assert!(app.input.is_empty());
    }

    #[test]
    fn vi_cursor_navigates_findings_list() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Findings;
        app.findings = vec![
            make_finding(Severity::High, "f1", "a"),
            make_finding(Severity::High, "f2", "b"),
            make_finding(Severity::High, "f3", "c"),
        ];

        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
        assert_eq!(app.findings_cursor, 1);
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
        assert_eq!(app.findings_cursor, 2);
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::empty()));
        assert_eq!(app.findings_cursor, 2, "j should clamp at last row");
        app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::empty()));
        assert_eq!(app.findings_cursor, 1);
        app.handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::empty()));
        assert_eq!(app.findings_cursor, 0);
        app.handle_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::empty()));
        assert_eq!(app.findings_cursor, 2);
    }

    #[test]
    fn pgdown_pgup_paginate_findings_cursor() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Findings;
        app.findings = (0..25)
            .map(|i| make_finding(Severity::High, &format!("fp-{i}"), "x"))
            .collect();
        app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()));
        assert_eq!(app.findings_cursor, 10);
        app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()));
        assert_eq!(app.findings_cursor, 20);
        app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::empty()));
        assert_eq!(app.findings_cursor, 24);
        app.handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::empty()));
        assert_eq!(app.findings_cursor, 14);
    }

    #[test]
    fn prompt_set_writes_override_file_and_reset_removes_it() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.target = Some(temp.path().to_path_buf());
        app.focused_module = Some("sast".to_string());
        app.shell_view = ShellView::PromptsEditor;

        app.submit_line("set triage \"focus on auth bypass\"");
        let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
        assert!(path.exists());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "focus on auth bypass"
        );

        app.submit_line("reset triage");
        assert!(!path.exists());
    }

    #[test]
    fn bare_verbs_only_intercepted_in_prompts_editor_view() {
        let temp = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.target = Some(temp.path().to_path_buf());
        app.focused_module = Some("sast".to_string());
        // NOT in prompts editor — should fall through to normal parser, which treats
        // unknown bare verbs as Unknown (not a prompt write).
        app.shell_view = ShellView::Catalog;
        app.submit_line("set triage \"abc\"");
        let path = temp.path().join(".kuzushi/prompts/sast/triage.md");
        assert!(!path.exists());
    }

    #[test]
    fn ctrl_o_toggles_story_overlay_back_to_origin() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.shell_view = ShellView::Findings;
        app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
        assert_eq!(app.shell_view, ShellView::Story);
        assert_eq!(app.story_return_view, Some(ShellView::Findings));
        app.handle_key(KeyEvent::new(KeyCode::Char('o'), KeyModifiers::CONTROL));
        assert_eq!(app.shell_view, ShellView::Findings);
        assert!(app.story_return_view.is_none());
    }

    #[test]
    fn scan_cancellation_pause_and_resume_round_trip() {
        let cancel = ScanCancellation::default();
        assert!(!cancel.is_paused());
        cancel.pause();
        assert!(cancel.is_paused());
        cancel.resume();
        assert!(!cancel.is_paused());
    }

    #[test]
    fn cancel_clears_pause_so_workers_observe_cancellation() {
        let cancel = ScanCancellation::default();
        cancel.pause();
        cancel.cancel();
        assert!(cancel.is_cancelled());
        assert!(!cancel.is_paused());
    }

    #[test]
    fn pause_command_during_active_scan_pauses_cancellation() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let cancel = ScanCancellation::default();
        app.scan_cancel = Some(cancel.clone());
        app.scan = Some(ScanPanelState {
            run_id: Some("run-1".to_string()),
            target: PathBuf::from("."),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            error: None,
        });
        app.handle_command(ShellCommand::Pause);
        assert!(cancel.is_paused());
        assert!(app.is_scan_paused());
        assert_eq!(
            app.scan.as_ref().map(|scan| scan.stage.as_str()),
            Some("paused")
        );
    }

    #[test]
    fn resume_command_resumes_paused_scan() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let cancel = ScanCancellation::default();
        cancel.pause();
        app.scan_cancel = Some(cancel.clone());
        app.scan = Some(ScanPanelState {
            run_id: Some("run-1".to_string()),
            target: PathBuf::from("."),
            stage: "paused".to_string(),
            findings_count: 0,
            running: true,
            error: None,
        });
        app.handle_command(ShellCommand::Resume(None));
        assert!(!cancel.is_paused());
        assert_eq!(
            app.scan.as_ref().map(|scan| scan.stage.as_str()),
            Some("running")
        );
    }

    #[test]
    fn module_run_p_and_r_keys_pause_resume() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let cancel = ScanCancellation::default();
        app.scan_cancel = Some(cancel.clone());
        app.scan = Some(ScanPanelState {
            run_id: Some("run-1".to_string()),
            target: PathBuf::from("."),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            error: None,
        });
        app.shell_view = ShellView::ModuleRun;
        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::empty()));
        assert!(cancel.is_paused());
        app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::empty()));
        assert!(!cancel.is_paused());
    }

    #[test]
    fn parse_threat_patch_extracts_summary_and_patch() {
        let body = r#"{"summary":"add admin trust zone","patch":{"trustZones":{"admin":"isolated"}},"unsupported":[]}"#;
        let patch = parse_threat_patch_json("regen", body).unwrap();
        assert_eq!(patch.summary, "add admin trust zone");
        assert_eq!(
            patch
                .patch
                .pointer("/trustZones/admin")
                .and_then(|v| v.as_str()),
            Some("isolated")
        );
    }

    #[test]
    fn merge_json_deep_merges_objects_and_handles_null_deletion() {
        let mut target = serde_json::json!({"trustZones":{"admin":"trusted","public":"untrusted"}});
        let patch =
            serde_json::json!({"trustZones":{"admin":"isolated","db":"private","public":null}});
        merge_json(&mut target, &patch);
        assert_eq!(
            target,
            serde_json::json!({"trustZones":{"admin":"isolated","db":"private"}})
        );
    }

    #[test]
    fn apply_pending_threat_patch_writes_to_disk() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().to_path_buf();
        let mut app = ShellApp::new(V2Config::default(), None);
        app.target = Some(target.clone());
        // Seed an existing model.
        save_persistent_threat_model(
            &target,
            &serde_json::json!({"trustZones":{"admin":"trusted"}}),
            true,
        )
        .unwrap();
        app.set_pending_threat_patch(ThreatPatch {
            goal: "g".to_string(),
            summary: "s".to_string(),
            patch: serde_json::json!({"trustZones":{"admin":"isolated"}}),
            unsupported: vec![],
        });
        app.apply_pending_threat_patch();
        let written = load_persistent_threat_model(&target).unwrap();
        assert_eq!(
            written
                .pointer("/trustZones/admin")
                .and_then(|v| v.as_str()),
            Some("isolated")
        );
        assert!(app.pending_threat_patch.is_none());
    }

    #[test]
    fn discard_threat_patch_clears_state() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_pending_threat_patch(ThreatPatch {
            goal: "g".to_string(),
            summary: "s".to_string(),
            patch: serde_json::json!({}),
            unsupported: vec![],
        });
        app.discard_pending_threat_patch();
        assert!(app.pending_threat_patch.is_none());
    }

    #[test]
    fn parse_plan_json_handles_well_formed_proposal() {
        let body = r#"{
            "summary": "lower SAST noise",
            "changes": [
                {"kind": "set_option", "tool": "sast:scan", "global": false, "name": "triage", "value": true},
                {"kind": "ask", "question": "any auth bypass risks?"},
                {"kind": "note", "text": "remember to re-baseline"}
            ],
            "unsupported": ["cannot toggle compiler hardening"]
        }"#;
        let plan = parse_plan_json("reduce noise", body).unwrap();
        assert_eq!(plan.goal, "reduce noise");
        assert_eq!(plan.summary, "lower SAST noise");
        assert_eq!(plan.changes.len(), 3);
        assert_eq!(plan.unsupported, vec!["cannot toggle compiler hardening"]);
    }

    #[test]
    fn parse_plan_json_skips_unknown_change_kinds() {
        let body = r#"{"summary":"x","changes":[{"kind":"explode","name":"x"}],"unsupported":[]}"#;
        let plan = parse_plan_json("x", body).unwrap();
        assert!(plan.changes.is_empty());
    }

    #[test]
    fn parse_plan_json_strips_surrounding_prose() {
        let body =
            "Here is the plan:\n```\n{\"summary\":\"x\",\"changes\":[],\"unsupported\":[]}\n```\n";
        let plan = parse_plan_json("x", body).unwrap();
        assert_eq!(plan.summary, "x");
    }

    #[test]
    fn pending_plan_y_key_applies() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_pending_plan(PlanProposal {
            goal: "g".to_string(),
            summary: "s".to_string(),
            changes: vec![PlanChange::Note {
                text: "noted".to_string(),
            }],
            unsupported: vec![],
        });
        app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::empty()));
        assert!(app.pending_plan.is_none());
        assert!(app.log.iter().any(|line| line.body.contains("noted")));
    }

    #[test]
    fn pending_plan_n_key_discards() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.set_pending_plan(PlanProposal {
            goal: "g".to_string(),
            summary: "s".to_string(),
            changes: vec![],
            unsupported: vec![],
        });
        app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::empty()));
        assert!(app.pending_plan.is_none());
        assert!(app
            .log
            .iter()
            .any(|line| line.prefix == "plan" && line.body.contains("discarded")));
    }

    #[test]
    fn budget_halt_c_continues_a_aborts() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.session_budget_usd = Some(0.05);
        app.record_cost(0.10);
        assert!(app.is_budget_halted());

        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::empty()));
        assert!(!app.is_budget_halted(), "c should clear the halt");

        app.session_cost_usd = 0.30;
        app.session_budget_usd = Some(0.20);
        app.record_cost(0.0);
        // Force re-trigger by lowering cap and recording zero (helper rechecks).
        app.advisory.budget_halt = Some(BudgetHalt {
            limit_usd: 0.20,
            spent_usd: 0.30,
        });
        app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::empty()));
        assert!(!app.is_budget_halted(), "a should clear the halt");
    }

    #[test]
    fn ctrl_c_during_active_scan_cancels_without_arming() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.scan = Some(ScanPanelState {
            run_id: Some("run-x".to_string()),
            target: PathBuf::from("."),
            stage: "running".to_string(),
            findings_count: 0,
            running: true,
            error: None,
        });
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(!app.should_quit);
        assert!(!app.ctrl_c_armed(), "scan-cancel path must not arm exit");
    }
}
