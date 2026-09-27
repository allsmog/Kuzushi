use super::*;

#[derive(Debug, Clone, Default)]
pub struct AdvisoryState {
    pub throttle: Option<ThrottleAdvisory>,
    pub budget_halt: Option<BudgetHalt>,
    /// Transient error/warning banner surfaced above the prompt so failures
    /// and dropped input are visible, not buried in the transcript log.
    pub notice: Option<Notice>,
    /// Pending operator approval for a tool dispatch that triggered a
    /// confirm gate (network egress, fs:write outside `.kuzushi/`,
    /// destructive verb).  See `design/mockups/confirm-dialog.jsx`.
    pub pending_confirm: Option<PendingConfirm>,
    /// One-shot launch payload parked behind `pending_confirm`. This is kept
    /// separate from the rendered confirmation copy so non-run confirmations
    /// do not grow extra UI-facing fields.
    pub(crate) pending_confirm_launch: Option<crate::app::RunToolLaunch>,
    /// The OAuth credential choice parked behind a `ModelSwitch` confirmation;
    /// it runs only after the operator explicitly approves the switch.
    pub(crate) pending_confirm_model_switch: Option<crate::app::PendingModelSwitchConsent>,
    /// End-of-engagement retry gate: offered after 掛 KAKE when planning tasks
    /// failed. Yes re-runs them (with auto-adjustments); no skips them.
    pub pending_retry: Option<crate::app::PendingRetry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThrottleAdvisory {
    pub source: String,
    pub message: String,
    pub since: Instant,
}

/// A transient, auto-clearing banner. `Error` (red) for failures, `Warn`
/// (amber) for non-fatal notices like a staged multi-line paste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub source: String,
    pub message: String,
    pub severity: NoticeSeverity,
    pub since: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeSeverity {
    Error,
    Warn,
    /// Informational terminal state such as a deliberately skipped tool.
    Info,
    /// Background work finished while the operator was elsewhere — green
    /// banner with the result and the verb that opens it.
    Success,
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

/// Full exploit chain (id/title/severity + ordered steps), cached from
/// `exploit-chain:scan` output for the attack-tree visualization. Parallel to
/// the minimal `ExploitChain` (which feeds alias/list views).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExploitChainDetail {
    pub id: String,
    pub title: String,
    pub severity: ChainSeverity,
    pub narrative: Option<String>,
    pub impact_description: Option<String>,
    pub preconditions: Vec<String>,
    pub steps: Vec<ExploitChainStep>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExploitChainStep {
    pub role: String,
    pub description: String,
    pub file: String,
    pub line: u32,
}

/// A source→sink taint flow, cached from `taint-iris:hunt` structured output
/// for the attack-path visualization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintFlowSnapshot {
    pub finding_fingerprint: Option<String>,
    pub finding_identity_id: Option<String>,
    pub cwe: String,
    pub severity: String,
    pub stages: Vec<TaintStage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintStage {
    pub message: String,
    pub file: String,
    pub line: u32,
    pub snippet: Option<String>,
}

/// One finding's operator-requested trace expansion. Steps hydrate from the
/// durable static-evidence store (or the `trace:expand` result on
/// completion); the last canonical result supplies questions, evidence notes
/// and its completion receipt, including a zero-step outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceExpansionSnapshot {
    pub last_outcome: Option<String>,
    pub finding_fingerprint: String,
    pub steps: Vec<TraceExpansionStep>,
    pub open_questions: Vec<String>,
    pub evidence_deltas: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceExpansionStep {
    pub symbol: String,
    pub file: String,
    pub line: u32,
    pub annotation: String,
}

impl ChainSeverity {
    pub(crate) fn rank(self) -> u8 {
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
    RunTool {
        phase: WorkflowPhase,
        tool: String,
        input: Option<String>,
    },
    SetOption {
        /// Present only for prose submitted through a selected phase. The
        /// application reducer uses it as a hard capability boundary.
        phase: Option<WorkflowPhase>,
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
            PlanChange::RunTool { phase, tool, input } => format!(
                "{} run {}{}",
                phase.label(),
                tool,
                input
                    .as_deref()
                    .map(|value| format!(" {value}"))
                    .unwrap_or_default()
            ),
            PlanChange::SetOption {
                phase,
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
                let phase_part = phase
                    .map(|phase| format!("{} ", phase.label()))
                    .unwrap_or_default();
                format!("{phase_part}{scope} {tool_part}{name}={value}")
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
