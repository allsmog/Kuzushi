use std::path::PathBuf;
use std::time::Instant;

use kuzushi_core::{AttachmentRecord, KnownArtifact, ReconHost, ReconNote, ReconService};

use super::PendingConfirm;

#[derive(Debug, Clone, Default)]
pub struct AdvisoryState {
    pub throttle: Option<ThrottleAdvisory>,
    pub budget_halt: Option<BudgetHalt>,
    /// Pending operator approval for a tool dispatch that triggered a
    /// confirm gate (network egress, fs:write outside `.kuzushi/`,
    /// destructive verb).  See `design/mockups/confirm-dialog.jsx`.
    pub pending_confirm: Option<PendingConfirm>,
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
    pub(super) fn rank(self) -> u8 {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuneAction {
    ShowHouseRules,
    EditHouseRules,
    ResetHouseRules,
}

impl TuneAction {
    pub const ORDER: &'static [TuneAction] = &[
        TuneAction::ShowHouseRules,
        TuneAction::EditHouseRules,
        TuneAction::ResetHouseRules,
    ];

    pub fn label(self) -> &'static str {
        match self {
            TuneAction::ShowHouseRules => "show house rules",
            TuneAction::EditHouseRules => "edit house rules (set \"...\")",
            TuneAction::ResetHouseRules => "reset house rules",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            TuneAction::ShowHouseRules => "log the current house-rules text into the transcript",
            TuneAction::EditHouseRules => {
                "prefill the prompt with `set \"\"` so you can type a value"
            }
            TuneAction::ResetHouseRules => "delete the house-rules file and revert to defaults",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActorDetailFilter {
    #[default]
    All,
    Findings,
    Errors,
    Tools,
}

impl ActorDetailFilter {
    pub fn label(self) -> &'static str {
        match self {
            ActorDetailFilter::All => "all",
            ActorDetailFilter::Findings => "findings",
            ActorDetailFilter::Errors => "errors",
            ActorDetailFilter::Tools => "tools",
        }
    }

    pub fn keeps(self, prefix: &str) -> bool {
        match self {
            ActorDetailFilter::All => true,
            ActorDetailFilter::Findings => prefix == "finding" || prefix == "title",
            ActorDetailFilter::Errors => prefix == "error",
            ActorDetailFilter::Tools => matches!(
                prefix,
                "scan" | "tool" | "agent" | "answer" | "plan" | "tune" | "prompt"
            ),
        }
    }

    pub fn next(self) -> Self {
        match self {
            ActorDetailFilter::All => ActorDetailFilter::Findings,
            ActorDetailFilter::Findings => ActorDetailFilter::Errors,
            ActorDetailFilter::Errors => ActorDetailFilter::Tools,
            ActorDetailFilter::Tools => ActorDetailFilter::All,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptsAction {
    Show,
    Edit,
    Diff,
    Reset,
    Set,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ThreatPatch {
    pub goal: String,
    pub summary: String,
    pub patch: serde_json::Value,
    pub unsupported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScanPanelState {
    pub run_id: Option<String>,
    pub target: PathBuf,
    pub stage: String,
    pub findings_count: usize,
    pub running: bool,
    pub abort_requested: bool,
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

/// Cached structured snapshot of the most recent recon tool result. The TUI
/// renderer prefers reading from this snapshot (when populated) rather than
/// grepping the freeform log lines, so transcript truncation does not erase
/// recon evidence.
#[derive(Debug, Clone, Default)]
pub struct ReconSnapshot {
    pub hosts: Vec<ReconHost>,
    pub services: Vec<ReconService>,
    pub notes: Vec<ReconNote>,
    pub last_tool: Option<String>,
    pub last_target: Option<String>,
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
    Quickstart,
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
    /// `/auth` providers + model + spend surface.  See
    /// `design/mockups/auth.jsx`.
    Auth,
    /// `/cost` budget bars + by-tool spend.  See `design/mockups/cost.jsx`.
    Cost,
    /// `/patch <alias>` view — RATIONALE / DIFF / TESTS / GUARDRAIL
    /// per `design/mockups/patch.jsx`.  String is the finding alias
    /// the patch addresses.
    Patch(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatView {
    Dfd,
    Stride,
    Stories,
    Scope,
    Summary,
}

#[derive(Debug, Clone)]
pub struct CompletionCycle {
    pub prefix: String,
    pub candidates: Vec<String>,
    pub index: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_severity_rank_and_label_are_stable() {
        assert_eq!(ChainSeverity::Critical.rank(), 0);
        assert_eq!(ChainSeverity::High.rank(), 1);
        assert_eq!(ChainSeverity::Medium.rank(), 2);

        assert_eq!(ChainSeverity::Critical.label(), "CRIT");
        assert_eq!(ChainSeverity::High.label(), "HIGH");
        assert_eq!(ChainSeverity::Medium.label(), "MED");
    }
}
