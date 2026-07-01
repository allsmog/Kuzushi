use super::{now_ms, save_strategy_queue, StrategyPhase, StrategyProposal};
use crate::fs_atomic::write_atomic;
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

pub const STRATEGY_CORRECTIONS_FILE: &str = "strategy-corrections.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StrategyCorrection {
    pub id: String,
    pub target_phase: StrategyPhase,
    pub proposal_id: Option<String>,
    pub from_strategy: String,
    pub to_strategy: String,
    pub scope: StrategyCorrectionScope,
    pub run_id: Option<String>,
    pub reason: String,
    pub author: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StrategyCorrectionScope {
    Run,
    Workspace,
}

impl StrategyCorrectionScope {
    pub fn label(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Workspace => "workspace",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppliedStrategyCorrection {
    pub id: String,
    pub scope: StrategyCorrectionScope,
    pub author: String,
    pub reason: String,
    pub from_strategy: String,
    pub to_strategy: String,
}

impl StrategyCorrection {
    pub fn new(
        target_phase: StrategyPhase,
        proposal_id: Option<String>,
        from_strategy: impl Into<String>,
        to_strategy: impl Into<String>,
        scope: StrategyCorrectionScope,
        run_id: Option<String>,
        reason: impl Into<String>,
        author: impl Into<String>,
    ) -> Self {
        let now = now_ms();
        let to_strategy = to_strategy.into();
        Self {
            id: strategy_correction_id(target_phase, &to_strategy, now),
            target_phase,
            proposal_id,
            from_strategy: from_strategy.into(),
            to_strategy,
            scope,
            run_id,
            reason: reason.into(),
            author: author.into(),
            created_at_ms: now,
        }
    }
}

pub fn strategy_corrections_path(workspace: &WorkspaceTarget) -> PathBuf {
    workspace.state_dir().join(STRATEGY_CORRECTIONS_FILE)
}

pub fn load_strategy_corrections(workspace: &WorkspaceTarget) -> Result<Vec<StrategyCorrection>> {
    let path = strategy_corrections_path(workspace);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("Could not read {}", path.display()))
        }
    };
    parse_strategy_corrections_jsonl(&text)
        .with_context(|| format!("Could not parse {}", path.display()))
}

pub fn save_strategy_corrections(
    workspace: &WorkspaceTarget,
    corrections: &[StrategyCorrection],
) -> Result<()> {
    write_atomic(
        &strategy_corrections_path(workspace),
        &serialize_strategy_corrections_jsonl(corrections)?,
    )
}

pub fn append_strategy_correction(
    workspace: &WorkspaceTarget,
    correction: &StrategyCorrection,
) -> Result<()> {
    let mut corrections = load_strategy_corrections(workspace)?;
    corrections.push(correction.clone());
    save_strategy_corrections(workspace, &corrections)
}

pub fn record_strategy_correction(
    workspace: &WorkspaceTarget,
    correction: &StrategyCorrection,
) -> Result<()> {
    append_strategy_correction(workspace, correction)?;
    let mut proposals = super::load_strategy_queue(workspace)?;
    apply_strategy_correction_to_proposals(&mut proposals, correction);
    save_strategy_queue(workspace, &proposals)
}

pub fn apply_strategy_corrections(
    workspace: &WorkspaceTarget,
    run_id: Option<&str>,
    proposals: &mut [StrategyProposal],
) -> Result<()> {
    for correction in load_strategy_corrections(workspace)? {
        if correction_applies_to_run(&correction, run_id) {
            apply_strategy_correction_to_proposals(proposals, &correction);
        }
    }
    Ok(())
}

fn apply_strategy_correction_to_proposals(
    proposals: &mut [StrategyProposal],
    correction: &StrategyCorrection,
) {
    for proposal in proposals {
        if correction_applies_to_proposal(correction, proposal) {
            proposal.apply_correction(correction);
        }
    }
}

fn correction_applies_to_run(correction: &StrategyCorrection, run_id: Option<&str>) -> bool {
    match correction.scope {
        StrategyCorrectionScope::Workspace => true,
        StrategyCorrectionScope::Run => match (correction.run_id.as_deref(), run_id) {
            (Some(expected), Some(actual)) => expected == actual,
            (None, None) => true,
            _ => false,
        },
    }
}

fn correction_applies_to_proposal(
    correction: &StrategyCorrection,
    proposal: &StrategyProposal,
) -> bool {
    correction.target_phase == proposal.phase
        && correction
            .proposal_id
            .as_ref()
            .map_or(true, |id| id == &proposal.id)
        && correction.from_strategy == proposal.effective_strategy()
}

impl StrategyProposal {
    pub fn effective_strategy(&self) -> &str {
        self.corrected_strategy
            .as_deref()
            .unwrap_or(&self.recommended_strategy)
    }

    pub fn apply_correction(&mut self, correction: &StrategyCorrection) {
        self.corrected_strategy = Some(correction.to_strategy.clone());
        self.updated_at_ms = now_ms();
        if !self
            .applied_corrections
            .iter()
            .any(|applied| applied.id == correction.id)
        {
            self.applied_corrections.push(AppliedStrategyCorrection {
                id: correction.id.clone(),
                scope: correction.scope,
                author: correction.author.clone(),
                reason: correction.reason.clone(),
                from_strategy: correction.from_strategy.clone(),
                to_strategy: correction.to_strategy.clone(),
            });
        }
    }
}

fn parse_strategy_corrections_jsonl(text: &str) -> Result<Vec<StrategyCorrection>> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str::<StrategyCorrection>(line)
                .with_context(|| format!("line {}", index + 1))
        })
        .collect()
}

fn serialize_strategy_corrections_jsonl(corrections: &[StrategyCorrection]) -> Result<String> {
    let mut lines = Vec::with_capacity(corrections.len());
    for correction in corrections {
        lines.push(serde_json::to_string(correction).context("Could not serialize correction")?);
    }
    Ok(if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    })
}

fn strategy_correction_id(phase: StrategyPhase, to_strategy: &str, now: u64) -> String {
    let slug = to_strategy
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
    format!("correction-{}-{now}-{suffix}", phase.label())
}
