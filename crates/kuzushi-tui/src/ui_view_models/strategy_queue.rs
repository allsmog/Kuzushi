use crate::app::StrategyQueueState;
use crate::ShellApp;
use kuzushi_core::{
    strategy_queue_path, StrategyPhase, StrategyPreflightStatus, StrategyProposal,
    StrategyProposalStatus, StrategyResourceRisk, WorkspaceTarget,
};
use std::path::Path;

const STRATEGY_QUEUE_HEADERS: [&str; 12] = [
    "status",
    "phase",
    "id",
    "strategy",
    "yield",
    "rounds",
    "est",
    "actual",
    "outcome",
    "preflight",
    "runtime",
    "risk",
];
const STRATEGY_QUEUE_COMMANDS: [&str; 6] = [
    "strategy approve <id>",
    "strategy reject <id>",
    "strategy correct <id> <strategy>",
    "recommend",
    "prompts",
    "back",
];
const STRATEGY_QUEUE_EMPTY_COMMANDS: [&str; 3] = ["recommend", "runs", "back"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StrategyQueueModel {
    pub(crate) title: &'static str,
    pub(crate) detail_rows: Vec<StrategyQueueDetailRow>,
    pub(crate) summary: String,
    pub(crate) headers: [&'static str; 12],
    pub(crate) commands: [&'static str; 6],
    pub(crate) empty_state: StrategyQueueEmptyState,
    pub(crate) rows: Vec<StrategyQueueRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StrategyQueueDetailRow {
    pub(crate) cells: [String; 2],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StrategyQueueEmptyState {
    pub(crate) title: &'static str,
    pub(crate) explanations: [&'static str; 2],
    pub(crate) actions: [(&'static str, &'static str); 2],
    pub(crate) commands: [&'static str; 3],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StrategyQueueRow {
    pub(crate) id: String,
    pub(crate) cells: [String; 12],
    pub(crate) rationale: String,
    pub(crate) lineage: String,
    pub(crate) source_run: String,
}

pub(crate) fn strategy_queue_model(app: &ShellApp) -> StrategyQueueModel {
    let source = StrategyQueueSource::from_app(app);
    let snapshot = strategy_queue_snapshot(app, &source);
    let detail_rows = strategy_queue_detail_rows(&source);
    StrategyQueueModel {
        title: "STRATEGY QUEUE",
        detail_rows,
        summary: snapshot.summary,
        headers: STRATEGY_QUEUE_HEADERS,
        commands: STRATEGY_QUEUE_COMMANDS,
        empty_state: strategy_queue_empty_state(source.workspace.is_some()),
        rows: snapshot.rows,
    }
}

struct StrategyQueueSnapshot {
    rows: Vec<StrategyQueueRow>,
    summary: String,
}

fn strategy_queue_snapshot(app: &ShellApp, source: &StrategyQueueSource) -> StrategyQueueSnapshot {
    if source.workspace.is_none() {
        return StrategyQueueSnapshot {
            rows: Vec::new(),
            summary: "no target selected; strategy queue is target-scoped".to_string(),
        };
    };
    match app
        .workbench_cache
        .borrow_mut()
        .strategy_queue(source.workspace.as_ref())
    {
        Some(StrategyQueueState::Ready(proposals)) => {
            let summary = strategy_queue_summary(&proposals);
            StrategyQueueSnapshot {
                rows: strategy_rows_from_proposals(proposals),
                summary,
            }
        }
        Some(StrategyQueueState::Unreadable(error)) => StrategyQueueSnapshot {
            rows: vec![strategy_queue_error_row(error.clone())],
            summary: format!("could not read strategy queue: {error}"),
        },
        None => StrategyQueueSnapshot {
            rows: Vec::new(),
            summary: "no target selected; strategy queue is target-scoped".to_string(),
        },
    }
}

fn strategy_queue_error_row(error: String) -> StrategyQueueRow {
    StrategyQueueRow {
        id: "queue-read-error".to_string(),
        cells: [
            "blocked".to_string(),
            "review".to_string(),
            "queue-read-error".to_string(),
            "repair queue artifact".to_string(),
            "-".to_string(),
            "-".to_string(),
            "blocked".to_string(),
            "unknown".to_string(),
            "failed".to_string(),
            "blocked".to_string(),
            "unknown".to_string(),
            "blocked".to_string(),
        ],
        rationale: error,
        lineage: "base -> recommended".to_string(),
        source_run: "-".to_string(),
    }
}

fn strategy_rows_from_proposals(mut proposals: Vec<StrategyProposal>) -> Vec<StrategyQueueRow> {
    proposals.sort_by_key(strategy_proposal_sort_key);
    proposals
        .into_iter()
        .map(strategy_row_from_proposal)
        .collect()
}

fn strategy_proposal_sort_key(proposal: &StrategyProposal) -> (u8, &'static str, String, String) {
    (
        strategy_status_order(proposal.status),
        proposal.phase.label(),
        proposal.effective_strategy().to_string(),
        proposal.id.clone(),
    )
}

fn strategy_status_order(status: StrategyProposalStatus) -> u8 {
    match status {
        StrategyProposalStatus::Proposed => 0,
        StrategyProposalStatus::Approved => 1,
        StrategyProposalStatus::Running => 2,
        StrategyProposalStatus::Failed => 3,
        StrategyProposalStatus::Done => 4,
        StrategyProposalStatus::Rejected => 5,
    }
}

fn strategy_row_from_proposal(proposal: StrategyProposal) -> StrategyQueueRow {
    let strategy = proposal.effective_strategy().to_string();
    let lineage = strategy_lineage(&proposal);
    StrategyQueueRow {
        id: proposal.id.clone(),
        cells: [
            status_label(proposal.status).to_string(),
            phase_label(proposal.phase).to_string(),
            proposal.id.clone(),
            strategy,
            yield_label(proposal.yield_score),
            rounds_label(proposal.estimated_rounds),
            cost_label(proposal.expected_cost_usd),
            cost_label(proposal.actual_cost_usd),
            outcome_label(&proposal),
            preflight_label(proposal.preflight.status).to_string(),
            proposal
                .expected_runtime
                .unwrap_or_else(|| "unknown".to_string()),
            risk_label(proposal.resource_risk).to_string(),
        ],
        rationale: strategy_rationale(
            proposal.rationale,
            proposal.preflight.notes,
            &proposal.applied_corrections,
        ),
        lineage,
        source_run: proposal.source_run_id.unwrap_or_else(|| "-".to_string()),
    }
}

fn strategy_rationale(
    rationale: String,
    notes: Vec<String>,
    corrections: &[kuzushi_core::AppliedStrategyCorrection],
) -> String {
    let notes = notes
        .into_iter()
        .filter(|note| !note.trim().is_empty())
        .take(3)
        .collect::<Vec<_>>();
    let mut segments = vec![rationale];
    if !notes.is_empty() {
        segments.push(format!("preflight: {}", notes.join("; ")));
    }
    segments.extend(corrections.iter().map(|correction| {
        format!(
            "correction:{} by {}: {}",
            correction.scope.label(),
            correction.author,
            correction.reason
        )
    }));
    segments.join(" | ")
}

fn strategy_lineage(proposal: &StrategyProposal) -> String {
    match proposal.corrected_strategy.as_deref() {
        Some(corrected) => format!(
            "{} -> {} -> {}",
            proposal.base_strategy, proposal.recommended_strategy, corrected
        ),
        None => format!(
            "{} -> {}",
            proposal.base_strategy, proposal.recommended_strategy
        ),
    }
}

fn cost_label(cost: Option<f64>) -> String {
    cost.map(|value| format!("${value:.4}"))
        .unwrap_or_else(|| "unknown".to_string())
}

fn yield_label(score: Option<f64>) -> String {
    score
        .map(|value| format!("{:.2}", value.clamp(0.0, 1.0)))
        .unwrap_or_else(|| "-".to_string())
}

fn rounds_label(rounds: Option<u32>) -> String {
    rounds
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn outcome_label(proposal: &StrategyProposal) -> String {
    if let Some(failure) = proposal.failure.as_ref().filter(|value| !value.is_empty()) {
        return format!("failed:{failure}");
    }
    match (proposal.findings_count, proposal.confirmed_count) {
        (Some(findings), Some(confirmed)) => format!("{confirmed}/{findings} confirmed"),
        (Some(findings), None) => format!("{findings} findings"),
        _ => proposal
            .result_run_id
            .as_ref()
            .map(|run| format!("run:{run}"))
            .unwrap_or_else(|| "-".to_string()),
    }
}

fn status_label(status: StrategyProposalStatus) -> &'static str {
    match status {
        StrategyProposalStatus::Proposed => "proposed",
        StrategyProposalStatus::Approved => "approved",
        StrategyProposalStatus::Rejected => "rejected",
        StrategyProposalStatus::Running => "running",
        StrategyProposalStatus::Done => "done",
        StrategyProposalStatus::Failed => "failed",
    }
}

fn phase_label(phase: StrategyPhase) -> &'static str {
    phase.label()
}

fn preflight_label(status: StrategyPreflightStatus) -> &'static str {
    status.label()
}

fn risk_label(risk: StrategyResourceRisk) -> &'static str {
    risk.label()
}

fn strategy_queue_summary(proposals: &[StrategyProposal]) -> String {
    if proposals.is_empty() {
        return "no queued strategy proposals".to_string();
    }
    let counts = strategy_queue_counts(proposals);
    format!(
        "{} proposals: {} proposed, {} approved, {} running, {} done, {} failed, {} rejected, {} corrected",
        proposals.len(),
        counts.proposed,
        counts.approved,
        counts.running,
        counts.done,
        counts.failed,
        counts.rejected,
        counts.corrected
    )
}

struct StrategyQueueCounts {
    proposed: usize,
    approved: usize,
    rejected: usize,
    running: usize,
    done: usize,
    failed: usize,
    corrected: usize,
}

fn strategy_queue_counts(proposals: &[StrategyProposal]) -> StrategyQueueCounts {
    let status_count = |status| {
        proposals
            .iter()
            .filter(|proposal| proposal.status == status)
            .count()
    };
    StrategyQueueCounts {
        proposed: status_count(StrategyProposalStatus::Proposed),
        approved: status_count(StrategyProposalStatus::Approved),
        rejected: status_count(StrategyProposalStatus::Rejected),
        running: status_count(StrategyProposalStatus::Running),
        done: status_count(StrategyProposalStatus::Done),
        failed: status_count(StrategyProposalStatus::Failed),
        corrected: proposals
            .iter()
            .filter(|proposal| proposal.corrected_strategy.is_some())
            .count(),
    }
}

fn strategy_queue_detail_rows(source: &StrategyQueueSource) -> Vec<StrategyQueueDetailRow> {
    vec![
        strategy_queue_detail_row("scope", source.scope_label.clone()),
        strategy_queue_detail_row("queue", source.queue_label.clone()),
    ]
}

fn strategy_queue_detail_row(label: &str, value: String) -> StrategyQueueDetailRow {
    StrategyQueueDetailRow {
        cells: [label.to_string(), value],
    }
}

fn strategy_queue_empty_state(target_selected: bool) -> StrategyQueueEmptyState {
    if !target_selected {
        return StrategyQueueEmptyState {
            title: "no target selected",
            explanations: [
                "strategy proposals are stored under the selected target.",
                "choose a target before asking the recommender to propose review work.",
            ],
            actions: [("target <path>", "select a target"), ("back", "return")],
            commands: ["target <path>", "runs", "back"],
        };
    }
    StrategyQueueEmptyState {
        title: "no queued proposals",
        explanations: [
            "strategy queue reads .kuzushi/v2/strategy-queue.jsonl.",
            "run the recommender to materialize review proposals before execution.",
        ],
        actions: [
            ("recommend", "rank modules and write strategy proposals"),
            ("runs", "inspect persisted runs"),
        ],
        commands: STRATEGY_QUEUE_EMPTY_COMMANDS,
    }
}

struct StrategyQueueSource {
    workspace: Option<WorkspaceTarget>,
    scope_label: String,
    queue_label: String,
}

impl StrategyQueueSource {
    fn from_app(app: &ShellApp) -> Self {
        let Some(target) = app.target.as_deref() else {
            return Self {
                workspace: None,
                scope_label: "no target selected".to_string(),
                queue_label: "unavailable".to_string(),
            };
        };
        match WorkspaceTarget::new(target) {
            Ok(workspace) => {
                let queue = strategy_queue_path(&workspace);
                Self {
                    scope_label: scope_label(target),
                    queue_label: queue.display().to_string(),
                    workspace: Some(workspace),
                }
            }
            Err(error) => Self {
                workspace: None,
                scope_label: scope_label(target),
                queue_label: format!("unavailable: {error}"),
            },
        }
    }
}

fn scope_label(target: &Path) -> String {
    target.display().to_string()
}

#[cfg(test)]
mod tests;
