use std::path::PathBuf;

use crate::app::{OptionsFilter, ThreatView};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellCommand {
    Help,
    Back,
    Modules,
    Tools,
    Findings,
    Open(String),
    Scan(Option<PathBuf>),
    Model(Option<String>),
    Auth,
    AuthLogin(Option<String>),
    Provider(Option<String>),
    Backend(Option<String>),
    Cost,
    /// Show the per-role model routing in effect (from `models.toml`)
    /// plus the operator default and any session overrides.
    Models,
    /// Alias for `Models`.
    Route,
    Config,
    Use(String),
    Tune,
    Threat(ThreatView),
    ThreatEditor,
    ThreatRegen,
    ThreatAsk(String),
    ThreatApply,
    ThreatReject,
    Prompts,
    Prompt(String),
    Actor(usize),
    ShowRuns,
    ShowAliases(Option<String>),
    Since(String),
    Replay(String),
    Trace(String),
    Plan(String),
    PlanApply,
    PlanDiscard,
    Quickstart,
    Target(Option<String>),
    Ask(String),
    Options {
        tool: Option<String>,
        filter: OptionsFilter,
    },
    SetOption {
        global: bool,
        name: String,
        value: String,
    },
    UnsetOption {
        global: bool,
        name: String,
    },
    Tasks,
    Task(SastTaskCommand),
    Context(ContextCommand),
    Workspace(WorkspaceCommand),
    KnowledgeBase(Option<String>),
    Attach(String),
    Detach(String),
    Reparse(String),
    History,
    Clear,
    Load(Option<String>),
    Resume(Option<String>),
    Pause,
    Story,
    RunTool {
        tool: Option<String>,
        input: Option<String>,
    },
    Quit,
    Empty,
    Unknown(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellCommandCategory {
    Navigation,
    RunScan,
    OptionsTasks,
    ContextKb,
    FindingsEvidence,
    AuthConfigModel,
    Session,
}

impl ShellCommandCategory {
    pub const ORDER: [ShellCommandCategory; 7] = [
        ShellCommandCategory::Navigation,
        ShellCommandCategory::RunScan,
        ShellCommandCategory::OptionsTasks,
        ShellCommandCategory::ContextKb,
        ShellCommandCategory::FindingsEvidence,
        ShellCommandCategory::AuthConfigModel,
        ShellCommandCategory::Session,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ShellCommandCategory::Navigation => "NAVIGATION",
            ShellCommandCategory::RunScan => "RUN / SCAN",
            ShellCommandCategory::OptionsTasks => "OPTIONS / TASKS",
            ShellCommandCategory::ContextKb => "CONTEXT / KB",
            ShellCommandCategory::FindingsEvidence => "FINDINGS / EVIDENCE",
            ShellCommandCategory::AuthConfigModel => "AUTH / CONFIG / MODEL",
            ShellCommandCategory::Session => "SESSION",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellCommandSpec {
    pub command: &'static str,
    pub aliases: &'static [&'static str],
    pub category: ShellCommandCategory,
    pub description: &'static str,
}

const SHELL_COMMAND_SPECS: &[ShellCommandSpec] = &[
    ShellCommandSpec {
        command: "help",
        aliases: &["/help", "/h", "h", "?"],
        category: ShellCommandCategory::Navigation,
        description: "show grouped shell help",
    },
    ShellCommandSpec {
        command: "modules",
        aliases: &["/modules", "/m", "m", "show modules"],
        category: ShellCommandCategory::Navigation,
        description: "browse native Rust modules",
    },
    ShellCommandSpec {
        command: "tools",
        aliases: &["/tools", "show tools"],
        category: ShellCommandCategory::Navigation,
        description: "list routed Rust tools",
    },
    ShellCommandSpec {
        command: "use <module>",
        aliases: &["use semgrep", "/use <module>"],
        category: ShellCommandCategory::Navigation,
        description: "focus a module",
    },
    ShellCommandSpec {
        command: "back",
        aliases: &["/back", "/b", "b"],
        category: ShellCommandCategory::Navigation,
        description: "return to the previous view",
    },
    ShellCommandSpec {
        command: "scan [target]",
        aliases: &["scan .", "/scan [target]"],
        category: ShellCommandCategory::RunScan,
        description: "run configured scanners",
    },
    ShellCommandSpec {
        command: "run <tool> [json]",
        aliases: &["run .", "/run <tool> [json]", "run . [json]"],
        category: ShellCommandCategory::RunScan,
        description: "dispatch a tool; run . uses focused module or sast:scan",
    },
    ShellCommandSpec {
        command: "ask <question>",
        aliases: &["/ask <question>", "?text"],
        category: ShellCommandCategory::RunScan,
        description: "explicit agent question",
    },
    ShellCommandSpec {
        command: "options [tool]",
        aliases: &["/options [tool]"],
        category: ShellCommandCategory::OptionsTasks,
        description: "show tool options",
    },
    ShellCommandSpec {
        command: "show options [tool]",
        aliases: &["/show options [tool]"],
        category: ShellCommandCategory::OptionsTasks,
        description: "show tool options",
    },
    ShellCommandSpec {
        command: "show advanced",
        aliases: &["/show advanced"],
        category: ShellCommandCategory::OptionsTasks,
        description: "advanced and evasion options",
    },
    ShellCommandSpec {
        command: "show missing",
        aliases: &["/show missing"],
        category: ShellCommandCategory::OptionsTasks,
        description: "required options without values",
    },
    ShellCommandSpec {
        command: "set <key> <value>",
        aliases: &["/set <key> <value>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "set a session option",
    },
    ShellCommandSpec {
        command: "setg <key> <value>",
        aliases: &["/setg <key> <value>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "set a global option",
    },
    ShellCommandSpec {
        command: "unset <key>",
        aliases: &["/unset <key>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "clear a session option",
    },
    ShellCommandSpec {
        command: "unsetg <key>",
        aliases: &["/unsetg <key>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "clear a global option",
    },
    ShellCommandSpec {
        command: "tasks",
        aliases: &["/tasks"],
        category: ShellCommandCategory::OptionsTasks,
        description: "choose SAST scanner tasks",
    },
    ShellCommandSpec {
        command: "task block <id>",
        aliases: &["task deny <id>", "/task block <id>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "block a SAST task",
    },
    ShellCommandSpec {
        command: "task allow <id>",
        aliases: &["/task allow <id>", "task unblock <id>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "allow a SAST task",
    },
    ShellCommandSpec {
        command: "task toggle [id]",
        aliases: &["/task toggle [id]"],
        category: ShellCommandCategory::OptionsTasks,
        description: "toggle a SAST task",
    },
    ShellCommandSpec {
        command: "task mode auto|manual|toggle",
        aliases: &["/task mode auto|manual|toggle"],
        category: ShellCommandCategory::OptionsTasks,
        description: "switch SAST task selection",
    },
    ShellCommandSpec {
        command: "task reset",
        aliases: &["/task reset"],
        category: ShellCommandCategory::OptionsTasks,
        description: "reset SAST task state",
    },
    ShellCommandSpec {
        command: "context",
        aliases: &["/context"],
        category: ShellCommandCategory::ContextKb,
        description: "show current context snapshot",
    },
    ShellCommandSpec {
        command: "context build",
        aliases: &["/context build"],
        category: ShellCommandCategory::ContextKb,
        description: "build repository context",
    },
    ShellCommandSpec {
        command: "context status",
        aliases: &["/context status"],
        category: ShellCommandCategory::ContextKb,
        description: "show context status",
    },
    ShellCommandSpec {
        command: "context regen <slice>",
        aliases: &["/context regen <slice>"],
        category: ShellCommandCategory::ContextKb,
        description: "rebuild all, repo, or app-model",
    },
    ShellCommandSpec {
        command: "kb [module]",
        aliases: &["attachments", "/kb [module]"],
        category: ShellCommandCategory::ContextKb,
        description: "show local KB attachments",
    },
    ShellCommandSpec {
        command: "attach <path-or-url>",
        aliases: &["/attach <path-or-url>"],
        category: ShellCommandCategory::ContextKb,
        description: "record local file or URL metadata",
    },
    ShellCommandSpec {
        command: "detach <id>",
        aliases: &["/detach <id>"],
        category: ShellCommandCategory::ContextKb,
        description: "remove a KB attachment",
    },
    ShellCommandSpec {
        command: "reparse <id>",
        aliases: &["/reparse <id>"],
        category: ShellCommandCategory::ContextKb,
        description: "refresh local attachment metadata",
    },
    ShellCommandSpec {
        command: "workspace",
        aliases: &["/workspace", "workspace status"],
        category: ShellCommandCategory::ContextKb,
        description: "show target and state status",
    },
    ShellCommandSpec {
        command: "workspace export findings <path>",
        aliases: &[
            "/workspace export findings <path>",
            "findings export <path>",
        ],
        category: ShellCommandCategory::ContextKb,
        description: "export findings JSON or JSONL",
    },
    ShellCommandSpec {
        command: "findings",
        aliases: &["findings", "/f", "f", "/findings"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "open persisted findings",
    },
    ShellCommandSpec {
        command: "open <id>",
        aliases: &["open F-0001", "/open <id>"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "open a finding alias or fingerprint",
    },
    ShellCommandSpec {
        command: "show aliases [prefix]",
        aliases: &["/show aliases [prefix]"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "list finding aliases",
    },
    ShellCommandSpec {
        command: "show runs",
        aliases: &["/show runs", "runs", "/runs"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "recent run artifacts",
    },
    ShellCommandSpec {
        command: "replay <run>",
        aliases: &["/replay <run>"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "render a run summary",
    },
    ShellCommandSpec {
        command: "trace <run>",
        aliases: &["/trace <run>"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "stream run events",
    },
    ShellCommandSpec {
        command: "since <ref>",
        aliases: &["/since <ref>"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "scope findings to a git ref",
    },
    ShellCommandSpec {
        command: "threats [1-5]",
        aliases: &[
            "/threats [1-5]",
            "threats summary",
            "threats dfd",
            "threats stride",
            "threats stories",
            "threats scope",
        ],
        category: ShellCommandCategory::FindingsEvidence,
        description: "threat model views",
    },
    ShellCommandSpec {
        command: "threats edit",
        aliases: &["/threats edit"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "open the editable threat model view",
    },
    ShellCommandSpec {
        command: "auth",
        aliases: &["/auth", "auth status"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "show env/OAuth status without secrets",
    },
    ShellCommandSpec {
        command: "auth login <provider>",
        aliases: &["auth codex", "auth anthropic", "/auth login <provider>"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "start supported OAuth login",
    },
    ShellCommandSpec {
        command: "provider",
        aliases: &["/provider"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "show pi-agent-core provider choices",
    },
    ShellCommandSpec {
        command: "backend",
        aliases: &["/backend"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "show Rust runtime backend",
    },
    ShellCommandSpec {
        command: "model [choice]",
        aliases: &["model 1", "/model [choice]"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "select explicit provider:model",
    },
    ShellCommandSpec {
        command: "cost",
        aliases: &["/cost"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "show known session cost estimate",
    },
    ShellCommandSpec {
        command: "models",
        aliases: &["/models", "route", "/route"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "show models.toml routing per role + operator default",
    },
    ShellCommandSpec {
        command: "config",
        aliases: &["/config"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "show runtime config status",
    },
    ShellCommandSpec {
        command: "history",
        aliases: &["/history"],
        category: ShellCommandCategory::Session,
        description: "show command history",
    },
    ShellCommandSpec {
        command: "clear",
        aliases: &["/clear"],
        category: ShellCommandCategory::Session,
        description: "clear conversation log",
    },
    ShellCommandSpec {
        command: "load <specifier>",
        aliases: &["/load <specifier>"],
        category: ShellCommandCategory::Session,
        description: "static registry status or load error",
    },
    ShellCommandSpec {
        command: "pause",
        aliases: &["/pause"],
        category: ShellCommandCategory::Session,
        description: "document live-control absence",
    },
    ShellCommandSpec {
        command: "resume [runId]",
        aliases: &["/resume [runId]"],
        category: ShellCommandCategory::Session,
        description: "document checkpoint-resume absence",
    },
    ShellCommandSpec {
        command: "story",
        aliases: &["/story"],
        category: ShellCommandCategory::Session,
        description: "show session story replacements",
    },
    ShellCommandSpec {
        command: "prompts",
        aliases: &["/prompts", "show prompts"],
        category: ShellCommandCategory::Session,
        description: "prompt override view",
    },
    ShellCommandSpec {
        command: "prompt <verb>",
        aliases: &["/prompt <verb>"],
        category: ShellCommandCategory::Session,
        description: "prompt editor action",
    },
    ShellCommandSpec {
        command: "tune",
        aliases: &["/tune", "/t", "t"],
        category: ShellCommandCategory::Session,
        description: "module controls",
    },
    ShellCommandSpec {
        command: "actor <n>",
        aliases: &["/actor <n>"],
        category: ShellCommandCategory::Session,
        description: "actor transcript detail",
    },
    ShellCommandSpec {
        command: "plan <english>",
        aliases: &["/plan <english>"],
        category: ShellCommandCategory::Session,
        description: "Haiku natural-language planner; review then /yes or /no",
    },
    ShellCommandSpec {
        command: "threats regen",
        aliases: &["/threats regen"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "Haiku-driven threat-model patch; review then /threats apply",
    },
    ShellCommandSpec {
        command: "threats ask <question>",
        aliases: &["/threats ask <question>"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "ask the agent about the current threat model",
    },
    ShellCommandSpec {
        command: "threats apply",
        aliases: &["/threats apply"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "apply the pending threat-model patch",
    },
    ShellCommandSpec {
        command: "threats reject",
        aliases: &["/threats reject"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "discard the pending threat-model patch",
    },
    ShellCommandSpec {
        command: "yes",
        aliases: &["/yes", "y"],
        category: ShellCommandCategory::Session,
        description: "apply pending plan",
    },
    ShellCommandSpec {
        command: "no",
        aliases: &["/no", "n"],
        category: ShellCommandCategory::Session,
        description: "discard pending plan",
    },
    ShellCommandSpec {
        command: "quickstart",
        aliases: &["/quickstart"],
        category: ShellCommandCategory::Navigation,
        description: "first-run guided setup",
    },
    ShellCommandSpec {
        command: "target [path]",
        aliases: &["/target [path]"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "switch scan target without restart",
    },
    ShellCommandSpec {
        command: "quit",
        aliases: &["q", "/q", "exit", "/quit", "/exit", "exitj", "/exitj"],
        category: ShellCommandCategory::Session,
        description: "exit the shell",
    },
];

const FEATURED_HELP_EXAMPLES: &[&str] = &[
    "scan .",
    "use semgrep",
    "run .",
    "findings",
    "open F-0001",
    "model 1",
];

pub fn shell_command_specs() -> &'static [ShellCommandSpec] {
    SHELL_COMMAND_SPECS
}

pub fn shell_help_examples() -> Vec<&'static str> {
    FEATURED_HELP_EXAMPLES
        .iter()
        .copied()
        .filter(|example| {
            SHELL_COMMAND_SPECS
                .iter()
                .any(|spec| spec.aliases.contains(example))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SastTaskCommand {
    Block(String),
    Allow(String),
    Toggle(Option<String>),
    Mode(SastTaskModeCommand),
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextCommand {
    Show,
    Build,
    Status,
    Regen(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceCommand {
    Status,
    ExportFindings { output: PathBuf },
    Unsupported(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SastTaskModeCommand {
    Auto,
    Manual,
    Toggle,
}

pub fn parse_command(input: &str) -> ShellCommand {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return ShellCommand::Empty;
    }

    if trimmed == "?" {
        return ShellCommand::Help;
    }
    if let Some(question) = trimmed.strip_prefix('?') {
        let question = question.trim();
        if !question.is_empty() {
            return ShellCommand::Ask(question.to_string());
        }
    }

    let normalized = trimmed.strip_prefix('/').unwrap_or(trimmed);
    let mut parts = normalized.split_whitespace();
    let verb = parts.next().unwrap_or_default();

    match verb {
        "help" | "h" => ShellCommand::Help,
        "back" | "b" => ShellCommand::Back,
        "modules" | "m" => ShellCommand::Modules,
        "tools" => ShellCommand::Tools,
        "options" => ShellCommand::Options {
            tool: parts.next().map(ToString::to_string),
            filter: OptionsFilter::Standard,
        },
        "findings" | "f" => match parts.next() {
            Some("export") => parts
                .next()
                .map(|path| {
                    ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
                        output: PathBuf::from(path),
                    })
                })
                .unwrap_or_else(|| ShellCommand::Unknown("findings export".to_string())),
            Some(other) => ShellCommand::Unknown(format!("findings {other}")),
            None => ShellCommand::Findings,
        },
        "open" => parts
            .next()
            .map(|id| ShellCommand::Open(id.to_string()))
            .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string())),
        "scan" => ShellCommand::Scan(parts.next().map(PathBuf::from)),
        "model" => {
            let rest = parts.collect::<Vec<_>>().join(" ");
            ShellCommand::Model((!rest.trim().is_empty()).then_some(rest))
        }
        "auth" => match parts.next() {
            None | Some("status") => ShellCommand::Auth,
            Some("login") => ShellCommand::AuthLogin(parts.next().map(ToString::to_string)),
            Some("openai-codex") | Some("codex") => {
                ShellCommand::AuthLogin(Some("openai-codex".to_string()))
            }
            Some("anthropic") | Some("claude") => {
                ShellCommand::AuthLogin(Some("anthropic".to_string()))
            }
            Some(other) => ShellCommand::Unknown(format!("auth {other}")),
        },
        "provider" => ShellCommand::Provider(parts.next().map(ToString::to_string)),
        "backend" => ShellCommand::Backend(parts.next().map(ToString::to_string)),
        "cost" => ShellCommand::Cost,
        "models" => ShellCommand::Models,
        "route" => ShellCommand::Route,
        "config" => ShellCommand::Config,
        "use" => parts
            .next()
            .map(|id| ShellCommand::Use(id.to_string()))
            .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string())),
        "tune" | "t" => ShellCommand::Tune,
        "threats" => match parts.next() {
            None | Some("summary") | Some("5") => ShellCommand::Threat(ThreatView::Summary),
            Some("dfd") | Some("1") => ShellCommand::Threat(ThreatView::Dfd),
            Some("stride") | Some("2") => ShellCommand::Threat(ThreatView::Stride),
            Some("stories") | Some("3") => ShellCommand::Threat(ThreatView::Stories),
            Some("scope") | Some("4") => ShellCommand::Threat(ThreatView::Scope),
            Some("edit") => ShellCommand::ThreatEditor,
            Some("regen") => ShellCommand::ThreatRegen,
            Some("apply") => ShellCommand::ThreatApply,
            Some("reject") | Some("discard") => ShellCommand::ThreatReject,
            Some("ask") => {
                let rest = parts.collect::<Vec<_>>().join(" ");
                if rest.trim().is_empty() {
                    ShellCommand::Unknown("/threats ask".to_string())
                } else {
                    ShellCommand::ThreatAsk(rest)
                }
            }
            Some(other) => ShellCommand::Unknown(format!("/threats {other}")),
        },
        "prompts" => ShellCommand::Prompts,
        "prompt" => {
            let rest = parts.collect::<Vec<_>>().join(" ");
            if rest.is_empty() {
                ShellCommand::Prompts
            } else {
                ShellCommand::Prompt(rest)
            }
        }
        "actor" => parts
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .map(ShellCommand::Actor)
            .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string())),
        "show" => match parts.next() {
            Some("modules") => ShellCommand::Modules,
            Some("tools") => ShellCommand::Tools,
            Some("runs") => ShellCommand::ShowRuns,
            Some("aliases") => ShellCommand::ShowAliases(parts.next().map(ToString::to_string)),
            Some("prompts") => ShellCommand::Prompts,
            Some("options") => ShellCommand::Options {
                tool: parts.next().map(ToString::to_string),
                filter: OptionsFilter::Standard,
            },
            Some("advanced") => ShellCommand::Options {
                tool: parts.next().map(ToString::to_string),
                filter: OptionsFilter::Advanced,
            },
            Some("missing") => ShellCommand::Options {
                tool: parts.next().map(ToString::to_string),
                filter: OptionsFilter::Missing,
            },
            Some(other) => ShellCommand::Unknown(format!("/show {other}")),
            None => ShellCommand::Unknown(trimmed.to_string()),
        },
        "since" => parts
            .next()
            .map(|reference| ShellCommand::Since(reference.to_string()))
            .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string())),
        "replay" => parts
            .next()
            .map(|run_id| ShellCommand::Replay(run_id.to_string()))
            .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string())),
        "trace" => parts
            .next()
            .map(|run_id| ShellCommand::Trace(run_id.to_string()))
            .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string())),
        "plan" => {
            let rest = parts.collect::<Vec<_>>().join(" ");
            if rest.is_empty() {
                ShellCommand::Unknown(trimmed.to_string())
            } else {
                ShellCommand::Plan(rest)
            }
        }
        "yes" | "y" => ShellCommand::PlanApply,
        "no" | "n" => ShellCommand::PlanDiscard,
        "quickstart" => ShellCommand::Quickstart,
        "target" => ShellCommand::Target(parts.next().map(ToString::to_string)),
        "ask" => {
            let rest = parts.collect::<Vec<_>>().join(" ");
            if rest.is_empty() {
                ShellCommand::Unknown(trimmed.to_string())
            } else {
                ShellCommand::Ask(rest)
            }
        }
        "run" => parse_run_command(parts.collect::<Vec<_>>()),
        "set" => parse_set_command(false, parts.collect::<Vec<_>>()),
        "setg" => parse_set_command(true, parts.collect::<Vec<_>>()),
        "unset" => parse_unset_command(false, parts.collect::<Vec<_>>()),
        "unsetg" => parse_unset_command(true, parts.collect::<Vec<_>>()),
        "tasks" => ShellCommand::Tasks,
        "task" => parse_task_command(parts.collect::<Vec<_>>()),
        "context" => parse_context_command(parts.collect::<Vec<_>>()),
        "workspace" => parse_workspace_command(parts.collect::<Vec<_>>()),
        "kb" | "attachments" => ShellCommand::KnowledgeBase(parts.next().map(ToString::to_string)),
        "attach" => {
            let rest = parts.collect::<Vec<_>>().join(" ");
            if rest.is_empty() {
                ShellCommand::Unknown(trimmed.to_string())
            } else {
                ShellCommand::Attach(rest)
            }
        }
        "detach" => parts
            .next()
            .map(|id| ShellCommand::Detach(id.to_string()))
            .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string())),
        "reparse" => parts
            .next()
            .map(|id| ShellCommand::Reparse(id.to_string()))
            .unwrap_or_else(|| ShellCommand::Unknown(trimmed.to_string())),
        "runs" => ShellCommand::ShowRuns,
        "history" => ShellCommand::History,
        "clear" => ShellCommand::Clear,
        "load" => {
            let specifier = parts.collect::<Vec<_>>().join(" ");
            if specifier.trim().is_empty() {
                ShellCommand::Load(None)
            } else {
                ShellCommand::Load(Some(specifier))
            }
        }
        "resume" => ShellCommand::Resume(parts.next().map(ToString::to_string)),
        "pause" => ShellCommand::Pause,
        "story" => ShellCommand::Story,
        "quit" | "exit" | "q" | "exitj" => ShellCommand::Quit,
        _ => ShellCommand::Unknown(trimmed.to_string()),
    }
}

fn parse_context_command(parts: Vec<&str>) -> ShellCommand {
    match parts.first().copied() {
        None => ShellCommand::Context(ContextCommand::Show),
        Some("build") => ShellCommand::Context(ContextCommand::Build),
        Some("status") => ShellCommand::Context(ContextCommand::Status),
        Some("regen") => parts
            .get(1)
            .map(|slice| ShellCommand::Context(ContextCommand::Regen((*slice).to_string())))
            .unwrap_or_else(|| ShellCommand::Unknown("context regen".to_string())),
        Some(other) => ShellCommand::Unknown(format!("context {other}")),
    }
}

fn parse_workspace_command(parts: Vec<&str>) -> ShellCommand {
    match parts.first().copied() {
        None | Some("status") => ShellCommand::Workspace(WorkspaceCommand::Status),
        Some("export") => match parts.get(1).copied() {
            Some("findings") => parts
                .get(2)
                .map(|path| {
                    ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
                        output: PathBuf::from(path),
                    })
                })
                .unwrap_or_else(|| ShellCommand::Unknown("workspace export findings".to_string())),
            Some(other) => ShellCommand::Workspace(WorkspaceCommand::Unsupported(format!(
                "workspace export {other}"
            ))),
            None => ShellCommand::Unknown("workspace export".to_string()),
        },
        Some("import") => ShellCommand::Workspace(WorkspaceCommand::Unsupported(
            "workspace import".to_string(),
        )),
        Some(other) => {
            ShellCommand::Workspace(WorkspaceCommand::Unsupported(format!("workspace {other}")))
        }
    }
}

fn parse_task_command(parts: Vec<&str>) -> ShellCommand {
    let Some(subcommand) = parts.first().copied() else {
        return ShellCommand::Unknown("task".to_string());
    };

    match subcommand {
        "block" | "deny" => parts
            .get(1)
            .map(|id| ShellCommand::Task(SastTaskCommand::Block((*id).to_string())))
            .unwrap_or_else(|| ShellCommand::Unknown("task block".to_string())),
        "allow" | "unblock" => parts
            .get(1)
            .map(|id| ShellCommand::Task(SastTaskCommand::Allow((*id).to_string())))
            .unwrap_or_else(|| ShellCommand::Unknown("task allow".to_string())),
        "toggle" => ShellCommand::Task(SastTaskCommand::Toggle(
            parts.get(1).map(|id| (*id).to_string()),
        )),
        "mode" => match parts.get(1).map(|mode| mode.to_ascii_lowercase()) {
            Some(mode) if mode == "auto" => {
                ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Auto))
            }
            Some(mode) if mode == "manual" => {
                ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Manual))
            }
            Some(mode) if mode == "toggle" => {
                ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Toggle))
            }
            _ => ShellCommand::Unknown("task mode".to_string()),
        },
        "reset" => ShellCommand::Task(SastTaskCommand::Reset),
        other => ShellCommand::Unknown(format!("task {other}")),
    }
}

fn parse_set_command(global: bool, parts: Vec<&str>) -> ShellCommand {
    if parts.is_empty() {
        return ShellCommand::Unknown(if global {
            "setg".to_string()
        } else {
            "set".to_string()
        });
    }

    let mut name = parts[0].to_string();
    let value = if let Some((lhs, rhs)) = parts[0].split_once('=') {
        name = lhs.to_string();
        let suffix = parts.get(1..).unwrap_or_default().join(" ");
        if suffix.is_empty() {
            rhs.to_string()
        } else {
            format!("{rhs} {suffix}")
        }
    } else if parts.len() >= 2 {
        parts[1..].join(" ")
    } else {
        String::new()
    };

    if name.trim().is_empty() || value.trim().is_empty() {
        return ShellCommand::Unknown(if global {
            "setg".to_string()
        } else {
            "set".to_string()
        });
    }

    ShellCommand::SetOption {
        global,
        name,
        value,
    }
}

fn parse_unset_command(global: bool, parts: Vec<&str>) -> ShellCommand {
    let Some(name) = parts.first().filter(|value| !value.trim().is_empty()) else {
        return ShellCommand::Unknown(if global {
            "unsetg".to_string()
        } else {
            "unset".to_string()
        });
    };

    ShellCommand::UnsetOption {
        global,
        name: (*name).to_string(),
    }
}

fn parse_run_command(parts: Vec<&str>) -> ShellCommand {
    if parts.is_empty() {
        return ShellCommand::RunTool {
            tool: None,
            input: None,
        };
    }

    let first = parts[0];
    if first == "." {
        return ShellCommand::RunTool {
            tool: None,
            input: if parts.len() > 1 {
                Some(parts[1..].join(" "))
            } else {
                None
            },
        };
    }

    if first.starts_with('{') || first.starts_with('[') {
        return ShellCommand::RunTool {
            tool: None,
            input: Some(parts.join(" ")),
        };
    }

    ShellCommand::RunTool {
        tool: Some(first.to_string()),
        input: if parts.len() > 1 {
            Some(parts[1..].join(" "))
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kept_commands() {
        assert_eq!(parse_command("/help"), ShellCommand::Help);
        assert_eq!(parse_command("/h"), ShellCommand::Help);
        assert_eq!(parse_command("?"), ShellCommand::Help);
        assert_eq!(parse_command("/modules"), ShellCommand::Modules);
        assert_eq!(parse_command("/show modules"), ShellCommand::Modules);
        assert_eq!(parse_command("/tools"), ShellCommand::Tools);
        assert_eq!(parse_command("/show tools"), ShellCommand::Tools);
        assert_eq!(parse_command("/findings"), ShellCommand::Findings);
        assert_eq!(parse_command("/f"), ShellCommand::Findings);
        assert_eq!(
            parse_command("findings export /tmp/findings.json"),
            ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
                output: PathBuf::from("/tmp/findings.json")
            })
        );
        assert_eq!(parse_command("/back"), ShellCommand::Back);
        assert_eq!(
            parse_command("/threats stride"),
            ShellCommand::Threat(ThreatView::Stride)
        );
        assert_eq!(
            parse_command("/threats 5"),
            ShellCommand::Threat(ThreatView::Summary)
        );
        assert_eq!(parse_command("/threats regen"), ShellCommand::ThreatRegen);
        assert_eq!(
            parse_command("/threats ask what changed?"),
            ShellCommand::ThreatAsk("what changed?".to_string())
        );
        assert_eq!(parse_command("/threats apply"), ShellCommand::ThreatApply);
        assert_eq!(parse_command("/threats reject"), ShellCommand::ThreatReject);
        assert_eq!(parse_command("/prompts"), ShellCommand::Prompts);
        assert_eq!(
            parse_command("/prompt show run"),
            ShellCommand::Prompt("show run".to_string())
        );
        assert_eq!(
            parse_command("/open abc123"),
            ShellCommand::Open("abc123".to_string())
        );
        assert_eq!(
            parse_command("/scan ./repo"),
            ShellCommand::Scan(Some(PathBuf::from("./repo")))
        );
        assert_eq!(
            parse_command("/model openai:gpt-5.5 xtrahigh"),
            ShellCommand::Model(Some("openai:gpt-5.5 xtrahigh".to_string()))
        );
        assert_eq!(parse_command("/auth"), ShellCommand::Auth);
        assert_eq!(
            parse_command("/auth login anthropic"),
            ShellCommand::AuthLogin(Some("anthropic".to_string()))
        );
        assert_eq!(
            parse_command("auth codex"),
            ShellCommand::AuthLogin(Some("openai-codex".to_string()))
        );
        assert_eq!(
            parse_command("/provider openai"),
            ShellCommand::Provider(Some("openai".to_string()))
        );
        assert_eq!(
            parse_command("/backend pi-agent-core"),
            ShellCommand::Backend(Some("pi-agent-core".to_string()))
        );
        assert_eq!(parse_command("/cost"), ShellCommand::Cost);
        assert_eq!(parse_command("/models"), ShellCommand::Models);
        assert_eq!(parse_command("models"), ShellCommand::Models);
        assert_eq!(parse_command("/route"), ShellCommand::Route);
        assert_eq!(parse_command("route"), ShellCommand::Route);
        assert_eq!(parse_command("/config"), ShellCommand::Config);
        assert_eq!(
            parse_command("/use semgrep"),
            ShellCommand::Use("semgrep".to_string())
        );
        assert_eq!(parse_command("/tune"), ShellCommand::Tune);
        assert_eq!(parse_command("/t"), ShellCommand::Tune);
        assert_eq!(parse_command("/actor 1"), ShellCommand::Actor(1));
        assert_eq!(parse_command("/show runs"), ShellCommand::ShowRuns);
        assert_eq!(
            parse_command("/show aliases F-00"),
            ShellCommand::ShowAliases(Some("F-00".to_string()))
        );
        assert_eq!(parse_command("/show prompts"), ShellCommand::Prompts);
        assert_eq!(
            parse_command("/options semgrep:scan"),
            ShellCommand::Options {
                tool: Some("semgrep:scan".to_string()),
                filter: OptionsFilter::Standard
            }
        );
        assert_eq!(
            parse_command("show options sast:scan"),
            ShellCommand::Options {
                tool: Some("sast:scan".to_string()),
                filter: OptionsFilter::Standard
            }
        );
        assert_eq!(
            parse_command("show advanced"),
            ShellCommand::Options {
                tool: None,
                filter: OptionsFilter::Advanced
            }
        );
        assert_eq!(
            parse_command("show missing"),
            ShellCommand::Options {
                tool: None,
                filter: OptionsFilter::Missing
            }
        );
        assert_eq!(
            parse_command("/set sampleLimit 2"),
            ShellCommand::SetOption {
                global: false,
                name: "sampleLimit".to_string(),
                value: "2".to_string()
            }
        );
        assert_eq!(
            parse_command("setg triage=false"),
            ShellCommand::SetOption {
                global: true,
                name: "triage".to_string(),
                value: "false".to_string()
            }
        );
        assert_eq!(
            parse_command("/unset sampleLimit"),
            ShellCommand::UnsetOption {
                global: false,
                name: "sampleLimit".to_string()
            }
        );
        assert_eq!(
            parse_command("unsetg triage"),
            ShellCommand::UnsetOption {
                global: true,
                name: "triage".to_string()
            }
        );
        assert_eq!(parse_command("/tasks"), ShellCommand::Tasks);
        assert_eq!(
            parse_command("/kb threat-model"),
            ShellCommand::KnowledgeBase(Some("threat-model".to_string()))
        );
        assert_eq!(
            parse_command("attachments"),
            ShellCommand::KnowledgeBase(None)
        );
        assert_eq!(
            parse_command("attach docs/design.md"),
            ShellCommand::Attach("docs/design.md".to_string())
        );
        assert_eq!(
            parse_command("detach A-123"),
            ShellCommand::Detach("A-123".to_string())
        );
        assert_eq!(
            parse_command("reparse A-123"),
            ShellCommand::Reparse("A-123".to_string())
        );
        assert_eq!(parse_command("/history"), ShellCommand::History);
        assert_eq!(parse_command("/clear"), ShellCommand::Clear);
        assert_eq!(
            parse_command("/load builtin:sast"),
            ShellCommand::Load(Some("builtin:sast".to_string()))
        );
        assert_eq!(parse_command("/load"), ShellCommand::Load(None));
        assert_eq!(parse_command("/pause"), ShellCommand::Pause);
        assert_eq!(parse_command("/resume"), ShellCommand::Resume(None));
        assert_eq!(
            parse_command("/resume run-123"),
            ShellCommand::Resume(Some("run-123".to_string()))
        );
        assert_eq!(parse_command("/story"), ShellCommand::Story);
        assert_eq!(
            parse_command("task block semgrep"),
            ShellCommand::Task(SastTaskCommand::Block("semgrep".to_string()))
        );
        assert_eq!(
            parse_command("/task allow codeql"),
            ShellCommand::Task(SastTaskCommand::Allow("codeql".to_string()))
        );
        assert_eq!(
            parse_command("/task toggle"),
            ShellCommand::Task(SastTaskCommand::Toggle(None))
        );
        assert_eq!(
            parse_command("/task toggle secret-scan"),
            ShellCommand::Task(SastTaskCommand::Toggle(Some("secret-scan".to_string())))
        );
        assert_eq!(
            parse_command("/task mode auto"),
            ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Auto))
        );
        assert_eq!(
            parse_command("/task mode manual"),
            ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Manual))
        );
        assert_eq!(
            parse_command("/task mode toggle"),
            ShellCommand::Task(SastTaskCommand::Mode(SastTaskModeCommand::Toggle))
        );
        assert_eq!(
            parse_command("/task reset"),
            ShellCommand::Task(SastTaskCommand::Reset)
        );
        assert_eq!(
            parse_command("/context"),
            ShellCommand::Context(ContextCommand::Show)
        );
        assert_eq!(
            parse_command("context build"),
            ShellCommand::Context(ContextCommand::Build)
        );
        assert_eq!(
            parse_command("/context status"),
            ShellCommand::Context(ContextCommand::Status)
        );
        assert_eq!(
            parse_command("/context regen repo"),
            ShellCommand::Context(ContextCommand::Regen("repo".to_string()))
        );
        assert_eq!(
            parse_command("/workspace"),
            ShellCommand::Workspace(WorkspaceCommand::Status)
        );
        assert_eq!(
            parse_command("workspace status"),
            ShellCommand::Workspace(WorkspaceCommand::Status)
        );
        assert_eq!(
            parse_command("workspace export findings out.json"),
            ShellCommand::Workspace(WorkspaceCommand::ExportFindings {
                output: PathBuf::from("out.json")
            })
        );
        assert_eq!(
            parse_command("workspace import burp report.xml"),
            ShellCommand::Workspace(WorkspaceCommand::Unsupported(
                "workspace import".to_string()
            ))
        );
        assert_eq!(
            parse_command("/since main"),
            ShellCommand::Since("main".to_string())
        );
        assert_eq!(
            parse_command("/replay run-123"),
            ShellCommand::Replay("run-123".to_string())
        );
        assert_eq!(
            parse_command("/trace run-123"),
            ShellCommand::Trace("run-123".to_string())
        );
        assert_eq!(
            parse_command("/plan only admin routes"),
            ShellCommand::Plan("only admin routes".to_string())
        );
        assert_eq!(
            parse_command("/ask what changed?"),
            ShellCommand::Ask("what changed?".to_string())
        );
        assert_eq!(
            parse_command("ask what changed?"),
            ShellCommand::Ask("what changed?".to_string())
        );
        assert_eq!(
            parse_command("?what changed?"),
            ShellCommand::Ask("what changed?".to_string())
        );
        assert_eq!(parse_command("?"), ShellCommand::Help);
        assert_eq!(
            parse_command("/run dep-hygiene:check {\"target\":\".\"}"),
            ShellCommand::RunTool {
                tool: Some("dep-hygiene:check".to_string()),
                input: Some("{\"target\":\".\"}".to_string())
            }
        );
        assert_eq!(
            parse_command("/run ."),
            ShellCommand::RunTool {
                tool: None,
                input: None
            }
        );
        assert_eq!(
            parse_command("run . {\"sampleLimit\":10}"),
            ShellCommand::RunTool {
                tool: None,
                input: Some("{\"sampleLimit\":10}".to_string())
            }
        );
        assert_eq!(parse_command("/exit"), ShellCommand::Quit);
        assert_eq!(parse_command("/quit"), ShellCommand::Quit);
    }

    #[test]
    fn accepts_commands_without_slash_for_log_prompt() {
        assert_eq!(parse_command("help"), ShellCommand::Help);
        assert_eq!(parse_command("modules"), ShellCommand::Modules);
        assert_eq!(parse_command("m"), ShellCommand::Modules);
        assert_eq!(parse_command("tools"), ShellCommand::Tools);
        assert_eq!(parse_command("findings"), ShellCommand::Findings);
        assert_eq!(parse_command("back"), ShellCommand::Back);
        assert_eq!(parse_command("b"), ShellCommand::Back);
        assert_eq!(parse_command("runs"), ShellCommand::ShowRuns);
        assert_eq!(
            parse_command("context status"),
            ShellCommand::Context(ContextCommand::Status)
        );
        assert_eq!(
            parse_command("scan ./repo"),
            ShellCommand::Scan(Some(PathBuf::from("./repo")))
        );
        assert_eq!(parse_command("q"), ShellCommand::Quit);
        assert_eq!(parse_command("exitj"), ShellCommand::Quit);
        assert_eq!(parse_command("/exitj"), ShellCommand::Quit);
    }

    #[test]
    fn unknown_prose_does_not_route_to_agent_chat() {
        assert_eq!(
            parse_command("summarize this repo"),
            ShellCommand::Unknown("summarize this repo".to_string())
        );
        assert_eq!(
            parse_command("ask"),
            ShellCommand::Unknown("ask".to_string())
        );
        assert_eq!(
            parse_command("/ask"),
            ShellCommand::Unknown("/ask".to_string())
        );
    }

    #[test]
    fn command_catalog_advertises_only_routed_commands() {
        for spec in shell_command_specs() {
            let mut forms = vec![spec.command];
            forms.extend(spec.aliases.iter().copied());
            for form in forms {
                let sample = sample_help_form(form);
                let parsed = parse_command(&sample);
                assert!(
                    !matches!(parsed, ShellCommand::Unknown(_)),
                    "catalog form {form:?} materialized as {sample:?} did not route"
                );
            }
        }
    }

    #[test]
    fn command_catalog_covers_every_public_route_kind() {
        let mut routed = std::collections::BTreeSet::new();
        for spec in shell_command_specs() {
            let mut forms = vec![spec.command];
            forms.extend(spec.aliases.iter().copied());
            for form in forms {
                routed.insert(route_kind(&parse_command(&sample_help_form(form))));
            }
        }

        let expected = std::collections::BTreeSet::from([
            "actor",
            "attach",
            "ask",
            "auth",
            "auth-login",
            "back",
            "backend",
            "clear",
            "config",
            "context",
            "cost",
            "detach",
            "findings",
            "help",
            "history",
            "kb",
            "load",
            "model",
            "models",
            "modules",
            "open",
            "options",
            "pause",
            "plan",
            "plan-apply",
            "plan-discard",
            "prompts",
            "prompt",
            "provider",
            "quickstart",
            "quit",
            "reparse",
            "replay",
            "resume",
            "route",
            "run-tool",
            "scan",
            "set-option",
            "show-aliases",
            "show-runs",
            "since",
            "story",
            "target",
            "task",
            "tasks",
            "threat",
            "threat-ask",
            "threat-apply",
            "threat-editor",
            "threat-regen",
            "threat-reject",
            "tools",
            "trace",
            "tune",
            "unset-option",
            "use",
            "workspace",
        ]);

        assert_eq!(routed, expected);
    }

    #[test]
    fn featured_help_examples_are_alias_backed_and_routed() {
        let examples = shell_help_examples();
        assert_eq!(
            examples,
            vec![
                "scan .",
                "use semgrep",
                "run .",
                "findings",
                "open F-0001",
                "model 1"
            ]
        );

        for example in examples {
            assert!(
                shell_command_specs()
                    .iter()
                    .any(|spec| spec.aliases.contains(&example)),
                "featured help example {example:?} is not backed by ShellCommandSpec.aliases"
            );
            assert!(
                !matches!(parse_command(example), ShellCommand::Unknown(_)),
                "featured help example {example:?} did not route"
            );
        }
    }

    fn route_kind(command: &ShellCommand) -> &'static str {
        match command {
            ShellCommand::Help => "help",
            ShellCommand::Back => "back",
            ShellCommand::Modules => "modules",
            ShellCommand::Tools => "tools",
            ShellCommand::Findings => "findings",
            ShellCommand::Open(_) => "open",
            ShellCommand::Scan(_) => "scan",
            ShellCommand::Model(_) => "model",
            ShellCommand::Auth => "auth",
            ShellCommand::AuthLogin(_) => "auth-login",
            ShellCommand::Provider(_) => "provider",
            ShellCommand::Backend(_) => "backend",
            ShellCommand::Cost => "cost",
            ShellCommand::Models => "models",
            ShellCommand::Route => "route",
            ShellCommand::Config => "config",
            ShellCommand::Use(_) => "use",
            ShellCommand::Tune => "tune",
            ShellCommand::Threat(_) => "threat",
            ShellCommand::ThreatEditor => "threat-editor",
            ShellCommand::ThreatRegen => "threat-regen",
            ShellCommand::ThreatAsk(_) => "threat-ask",
            ShellCommand::ThreatApply => "threat-apply",
            ShellCommand::ThreatReject => "threat-reject",
            ShellCommand::Prompts => "prompts",
            ShellCommand::Prompt(_) => "prompt",
            ShellCommand::Actor(_) => "actor",
            ShellCommand::ShowRuns => "show-runs",
            ShellCommand::ShowAliases(_) => "show-aliases",
            ShellCommand::Since(_) => "since",
            ShellCommand::Replay(_) => "replay",
            ShellCommand::Trace(_) => "trace",
            ShellCommand::Plan(_) => "plan",
            ShellCommand::PlanApply => "plan-apply",
            ShellCommand::PlanDiscard => "plan-discard",
            ShellCommand::Quickstart => "quickstart",
            ShellCommand::Target(_) => "target",
            ShellCommand::Ask(_) => "ask",
            ShellCommand::Options { .. } => "options",
            ShellCommand::SetOption { .. } => "set-option",
            ShellCommand::UnsetOption { .. } => "unset-option",
            ShellCommand::Tasks => "tasks",
            ShellCommand::Task(_) => "task",
            ShellCommand::Context(_) => "context",
            ShellCommand::Workspace(_) => "workspace",
            ShellCommand::KnowledgeBase(_) => "kb",
            ShellCommand::Attach(_) => "attach",
            ShellCommand::Detach(_) => "detach",
            ShellCommand::Reparse(_) => "reparse",
            ShellCommand::History => "history",
            ShellCommand::Clear => "clear",
            ShellCommand::Load(_) => "load",
            ShellCommand::Resume(_) => "resume",
            ShellCommand::Pause => "pause",
            ShellCommand::Story => "story",
            ShellCommand::RunTool { .. } => "run-tool",
            ShellCommand::Quit => "quit",
            ShellCommand::Empty => "empty",
            ShellCommand::Unknown(_) => "unknown",
        }
    }

    fn sample_help_form(form: &str) -> String {
        form.split_whitespace()
            .map(|part| match part {
                "<module>" => "sast".to_string(),
                "<tool>" => "sast:scan".to_string(),
                "<key>" => "severity".to_string(),
                "<value>" => "high".to_string(),
                "<id>" => "semgrep".to_string(),
                "<slice>" => "repo".to_string(),
                "<path>" => "findings.json".to_string(),
                "<path-or-url>" => "README.md".to_string(),
                "<run>" | "<runId>" => "run-123".to_string(),
                "<ref>" => "main".to_string(),
                "<provider>" => "openai-codex".to_string(),
                "<choice>" => "1".to_string(),
                "<question>" => "what now".to_string(),
                "<specifier>" => "builtin:sast".to_string(),
                "<verb>" => "show run".to_string(),
                "<n>" => "1".to_string(),
                "[json]" => String::new(),
                "[tool]" => "sast:scan".to_string(),
                "[target]" => "./repo".to_string(),
                "[module]" => "context".to_string(),
                "[prefix]" => "F-00".to_string(),
                "[id]" => "semgrep".to_string(),
                "[1-5]" => "5".to_string(),
                "[choice]" => "1".to_string(),
                "[runId]" => "run-123".to_string(),
                "auto|manual|toggle" => "auto".to_string(),
                other => other.to_string(),
            })
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    }
}
