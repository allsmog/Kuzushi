use super::adapters::{
    cpg_taint_paths_tool, handle_cpg_taint_paths, open_cpg_taint_engine, CpgTaintReadiness,
};
use super::domain::{
    deep_auditor_system_prompt, DeepAuditConfig, DeepAuditOutcome, EvidenceCitation,
    EvidenceOrigin, VulnAnalysis,
};
use crate::agent_router::{AgentRole, RoutedRuntime};
use crate::code_nav::{code_nav_tool_specs, code_nav_toolbox, CodeNavConfig};
use crate::findings::{Finding, TriageOutcome, TriageVerdict};
use crate::run_artifacts::TraceHandle;
use crate::runtime::{
    run_tool_loop, AgentLoopOutcome, AgentQueryRequest, AgentRuntime, AgentTool,
    AgentToolLoopRequest, LoopHistoryEntry, ToolBox,
};
use crate::spend::{Operation, SpendLimiter};
use anyhow::{Context, Result};
use serde_json::Value;

mod build_triage_outcome;
mod parse_vuln_analysis;
mod run_deep_auditor;

pub(crate) use build_triage_outcome::*;
pub(crate) use parse_vuln_analysis::*;
pub use run_deep_auditor::run_deep_auditor;
pub use run_deep_auditor::run_deep_auditor_traced;
