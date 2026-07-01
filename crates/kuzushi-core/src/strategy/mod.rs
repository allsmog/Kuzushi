use crate::fs_atomic::write_atomic;
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const STRATEGY_QUEUE_FILE: &str = "strategy-queue.jsonl";

mod correction;
pub use correction::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StrategyProposal {
    pub id: String,
    pub phase: StrategyPhase,
    pub base_strategy: String,
    pub recommended_strategy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corrected_strategy: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied_corrections: Vec<AppliedStrategyCorrection>,
    pub rationale: String,
    pub expected_cost_usd: Option<f64>,
    pub expected_runtime: Option<String>,
    pub preflight: StrategyPreflight,
    pub resource_risk: StrategyResourceRisk,
    pub status: StrategyProposalStatus,
    pub source_run_id: Option<String>,
    pub tool: Option<String>,
    pub next_input: Option<Value>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StrategyPhase {
    Context,
    ProjectModel,
    Review,
    Classification,
    Confirmation,
    ReportFollowUp,
}

impl StrategyPhase {
    pub fn label(self) -> &'static str {
        match self {
            Self::Context => "context",
            Self::ProjectModel => "project-model",
            Self::Review => "review",
            Self::Classification => "classification",
            Self::Confirmation => "confirmation",
            Self::ReportFollowUp => "report",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StrategyPreflight {
    pub status: StrategyPreflightStatus,
    pub notes: Vec<String>,
}

impl StrategyPreflight {
    pub fn ready() -> Self {
        Self {
            status: StrategyPreflightStatus::Ready,
            notes: Vec::new(),
        }
    }

    pub fn blocked(notes: Vec<String>) -> Self {
        Self {
            status: StrategyPreflightStatus::Blocked,
            notes,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StrategyPreflightStatus {
    Ready,
    Warning,
    Blocked,
    Unknown,
}

impl StrategyPreflightStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Warning => "warning",
            Self::Blocked => "blocked",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StrategyResourceRisk {
    Low,
    Medium,
    High,
    Blocked,
    Unknown,
}

impl StrategyResourceRisk {
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Blocked => "blocked",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StrategyProposalStatus {
    Proposed,
    Approved,
    Rejected,
}

impl StrategyProposalStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }
}

impl StrategyProposal {
    pub fn new(
        phase: StrategyPhase,
        recommended_strategy: impl Into<String>,
        rationale: impl Into<String>,
    ) -> Self {
        let now = now_ms();
        let recommended_strategy = recommended_strategy.into();
        Self {
            id: strategy_proposal_id(phase, &recommended_strategy, now),
            phase,
            base_strategy: "current phase defaults".to_string(),
            recommended_strategy,
            corrected_strategy: None,
            applied_corrections: Vec::new(),
            rationale: rationale.into(),
            expected_cost_usd: None,
            expected_runtime: None,
            preflight: StrategyPreflight {
                status: StrategyPreflightStatus::Unknown,
                notes: Vec::new(),
            },
            resource_risk: StrategyResourceRisk::Unknown,
            status: StrategyProposalStatus::Proposed,
            source_run_id: None,
            tool: None,
            next_input: None,
            created_at_ms: now,
            updated_at_ms: now,
        }
    }

    pub fn with_tool(mut self, tool: impl Into<String>, next_input: Option<Value>) -> Self {
        self.tool = Some(tool.into());
        self.next_input = next_input;
        self
    }

    pub fn with_source_run(mut self, run_id: Option<String>) -> Self {
        self.source_run_id = run_id;
        self
    }

    pub fn with_estimates(
        mut self,
        expected_cost_usd: Option<f64>,
        expected_runtime: Option<String>,
        resource_risk: StrategyResourceRisk,
    ) -> Self {
        self.expected_cost_usd = expected_cost_usd;
        self.expected_runtime = expected_runtime;
        self.resource_risk = resource_risk;
        self
    }

    pub fn with_preflight(mut self, preflight: StrategyPreflight) -> Self {
        self.preflight = preflight;
        self
    }
}

pub fn strategy_queue_path(workspace: &WorkspaceTarget) -> PathBuf {
    workspace.state_dir().join(STRATEGY_QUEUE_FILE)
}

pub fn load_strategy_queue(workspace: &WorkspaceTarget) -> Result<Vec<StrategyProposal>> {
    let path = strategy_queue_path(workspace);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("Could not read {}", path.display()))
        }
    };
    parse_strategy_queue_jsonl(&text)
        .with_context(|| format!("Could not parse {}", path.display()))
}

pub fn save_strategy_queue(
    workspace: &WorkspaceTarget,
    proposals: &[StrategyProposal],
) -> Result<()> {
    write_atomic(
        &strategy_queue_path(workspace),
        &serialize_strategy_queue_jsonl(proposals)?,
    )
}

pub fn append_strategy_proposal(
    workspace: &WorkspaceTarget,
    proposal: &StrategyProposal,
) -> Result<()> {
    let mut proposals = load_strategy_queue(workspace)?;
    proposals.push(proposal.clone());
    save_strategy_queue(workspace, &proposals)
}

pub fn set_strategy_proposal_status(
    workspace: &WorkspaceTarget,
    id: &str,
    status: StrategyProposalStatus,
) -> Result<bool> {
    let mut proposals = load_strategy_queue(workspace)?;
    let Some(proposal) = proposals.iter_mut().find(|proposal| proposal.id == id) else {
        return Ok(false);
    };
    proposal.status = status;
    proposal.updated_at_ms = now_ms();
    save_strategy_queue(workspace, &proposals)?;
    Ok(true)
}

fn parse_strategy_queue_jsonl(text: &str) -> Result<Vec<StrategyProposal>> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str::<StrategyProposal>(line)
                .with_context(|| format!("line {}", index + 1))
        })
        .collect()
}

fn serialize_strategy_queue_jsonl(proposals: &[StrategyProposal]) -> Result<String> {
    let mut lines = Vec::with_capacity(proposals.len());
    for proposal in proposals {
        lines.push(serde_json::to_string(proposal).context("Could not serialize proposal")?);
    }
    Ok(if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    })
}

fn strategy_proposal_id(phase: StrategyPhase, recommended_strategy: &str, now: u64) -> String {
    let slug = recommended_strategy
        .chars()
        .map(|value| {
            if value.is_ascii_alphanumeric() {
                value.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .take(4)
        .collect::<Vec<_>>()
        .join("-");
    let suffix = if slug.is_empty() { "strategy" } else { &slug };
    format!("{}-{now}-{suffix}", phase.label())
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
