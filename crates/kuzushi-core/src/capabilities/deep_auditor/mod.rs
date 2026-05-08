/// Hard cap on tool-loop steps per finding. Mirrors RoboDuck's tool-loop
/// budget — large enough that the model can read several files but small
/// enough that a runaway loop is bounded.

/// Conservative initial deposit per audit. Real cost surfaces from the
/// bridge per-step and settles via SpendLimiter::refund.

/// What the model is asked to return as its final structured answer.

/// Run a tool-augmented deep audit on a single finding.
///
/// `runtime` should be a `RoutedRuntime` so the model is selected by the
/// `DeepAuditor` role. Per-call enforcement uses the supplied
/// [`SpendLimiter`]; pass `None` to skip budgeting (tests / dry-runs).

/// Salvage evidence from tool transcripts when the model didn't return
/// any in its structured answer. We pick out file/line ranges from
/// successful read_source calls and the matching arguments.

/// Persist evidence citations into the optional `findings_evidence`
/// table. Best-effort — failures log but don't propagate, since the
/// audit verdict itself is the primary artefact.
use crate::agent_router::{AgentRole, RoutedRuntime};
use crate::code_nav::{code_nav_tool_specs, code_nav_toolbox, CodeNavConfig};
use crate::findings::{Finding, TriageOutcome, TriageVerdict};
use crate::runtime::{
    run_tool_loop, AgentLoopOutcome, AgentRuntime, AgentToolLoopRequest, LoopHistoryEntry,
};
use crate::spend::{Operation, SpendLimiter};
use anyhow::{Context, Result};
pub(crate) use build_triage_outcome::*;
pub(crate) use deep_audit_contract::*;
pub(crate) use parse_vuln_analysis::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
mod build_triage_outcome;
mod deep_audit_contract;
mod parse_vuln_analysis;
mod run_deep_auditor;
#[cfg(test)]
mod tests;

pub use build_triage_outcome::save_evidence;
pub use deep_audit_contract::DeepAuditConfig;
pub use deep_audit_contract::DeepAuditOutcome;
pub use deep_audit_contract::EvidenceCitation;
pub use deep_audit_contract::VulnAnalysis;
pub use deep_audit_contract::DEFAULT_DEPOSIT_USD;
pub use deep_audit_contract::DEFAULT_MAX_STEPS;
pub use run_deep_auditor::run_deep_auditor;
