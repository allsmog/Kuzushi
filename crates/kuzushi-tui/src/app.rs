use std::io::{self, Stdout};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::cursor::MoveTo;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType};
use kuzushi_core::modules::ToolExecutionContext;
use kuzushi_core::{
    default_scan_engines, AgentRuntime, Finding, FindingStore, ModuleRegistry, ScanCancellation,
    Severity, V2Config, WorkspaceTarget,
};
use kuzushi_openai::PiAgentCoreRuntime;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use uuid::Uuid;

use crate::commands::{parse_command, ShellCommand};
use crate::renderer::render_app;

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
    pub findings: Vec<Finding>,
    pub selected_finding: Option<Finding>,
    pub scan: Option<ScanPanelState>,
    pub should_quit: bool,
    scan_rx: Option<Receiver<ScanEvent>>,
    scan_cancel: Option<ScanCancellation>,
}

impl ShellApp {
    pub fn new(config: V2Config, target: Option<&WorkspaceTarget>) -> Self {
        let mut app = Self {
            input: String::new(),
            log: Vec::new(),
            target: target.map(|target| target.root().to_path_buf()),
            focused_module: None,
            shell_view: ShellView::Catalog,
            catalog_expanded: false,
            config,
            registry: ModuleRegistry::with_v2_builtins(),
            findings: Vec::new(),
            selected_finding: None,
            scan: None,
            should_quit: false,
            scan_rx: None,
            scan_cancel: None,
        };
        app.log("system", "kuzushi shell");
        app.log(
            "help",
            "/scan, /run <tool>, /findings, /open <id>, /modules, /tools, /threats, /quit",
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
                self.log(
                    "help",
                    "/modules /tools /findings /open <fingerprint> /scan [target] /run <tool> [json] /model [id] /config /use <module> /threats /prompts /quit",
                );
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
            ShellCommand::Model(model) => {
                if let Some(model) = model {
                    self.config.model = Some(model);
                }
                let model = self
                    .config
                    .model
                    .clone()
                    .unwrap_or_else(|| "unconfigured".to_string());
                self.log("model", model);
            }
            ShellCommand::Config => {
                self.shell_view = ShellView::Config;
                self.log(
                    "config",
                    format!(
                        "runtime={:?} model={}",
                        self.config.runtime.kind,
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
                self.log("prompt", raw);
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
                self.shell_view = ShellView::Findings;
                self.log(
                    "aliases",
                    prefix
                        .map(|prefix| format!("filter {prefix}"))
                        .unwrap_or_else(|| "finding aliases".to_string()),
                );
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
            ShellCommand::Plan(goal) => {
                self.shell_view = ShellView::Help;
                self.log("plan", goal);
            }
            ShellCommand::RunTool { tool, input } => self.run_tool(tool, input),
            ShellCommand::Quit => {
                self.request_exit();
            }
            ShellCommand::Empty => {}
            ShellCommand::Unknown(raw) => self.log("error", format!("unknown command {raw:?}")),
        }
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

        thread::spawn(move || scan_worker(target_root, db_path, tx, cancel));
    }

    fn run_tool(&mut self, tool: Option<String>, input: Option<String>) {
        let tool_name = match tool {
            Some(tool) => tool,
            None => match self.default_tool_for_focused_module() {
                Some(tool) => tool,
                None => {
                    self.log("error", "run requires a tool name or focused module");
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
                Ok(runtime) => Some(runtime),
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
        let store = match self.open_store() {
            Ok(store) => store,
            Err(error) => {
                self.log("error", error.to_string());
                return;
            }
        };

        match store.get_finding_by_reference(reference) {
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

    fn handle_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if !self.cancel_active_scan() {
                    self.should_quit = true;
                }
            }
            KeyCode::Char(ch)
                if self.input.is_empty()
                    && key.modifiers.is_empty()
                    && self.handle_view_hotkey(ch) => {}
            KeyCode::Char(ch) => self.input.push(ch),
            KeyCode::Backspace => {
                self.input.pop();
            }
            KeyCode::Enter => {
                let raw = std::mem::take(&mut self.input);
                self.log(">", raw.clone());
                let command = parse_command(&raw);
                self.handle_command(command);
            }
            KeyCode::Esc => {
                self.input.clear();
            }
            _ => {}
        }
    }

    fn handle_view_hotkey(&mut self, ch: char) -> bool {
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
            | ShellView::Threat(_)
            | ShellView::ThreatEditor => ShellView::Catalog,
            ShellView::Tune | ShellView::PromptsEditor => {
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
}

pub fn run_shell(config: V2Config, target: Option<&WorkspaceTarget>) -> Result<()> {
    let mut terminal = setup_terminal()?;
    let mut app = ShellApp::new(config, target);

    loop {
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

fn scan_worker(target: PathBuf, db_path: PathBuf, tx: Sender<ScanEvent>, cancel: ScanCancellation) {
    if let Err(error) = run_scan_worker(target, db_path, &tx, &cancel) {
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

    let scanners = default_scan_engines();
    let mut findings = Vec::new();
    for scanner in scanners {
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

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{RuntimeConfig, RuntimeKind, TriageOutcome, TriageVerdict};
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
        assert!(!help_log.contains("quickstart"));
        assert!(!help_log.contains("--load"));
        assert!(!help_log.contains("Ink"));
        assert!(!help_log.contains("TypeScript"));
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
        assert!(workspace
            .root()
            .join(".kuzushi/context-snapshot.json")
            .exists());
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
            "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGH",
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
            "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGH",
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
}
