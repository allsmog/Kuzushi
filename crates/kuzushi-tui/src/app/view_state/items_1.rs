use super::prelude::*;
use super::*;

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
