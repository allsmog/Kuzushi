use crate::findings::Finding;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UafHuntPersistedRun {
    #[serde(rename = "runId")]
    pub run_id: String,
    #[serde(rename = "findingsDb")]
    pub findings_db: String,
    /// Newline-delimited JSON transcript of the agent's tool-call loop.
    /// Each line is one `LoopHistoryEntry` (assistant text, tool call,
    /// tool result). Operators inspect this when a run hits the step
    /// cap with no findings to see what the agent actually looked at.
    #[serde(rename = "transcriptPath", skip_serializing_if = "Option::is_none")]
    pub transcript_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UafHuntReport {
    pub target: String,
    pub count: usize,
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted: Option<UafHuntPersistedRun>,
    #[serde(rename = "compileCommandsPath")]
    pub compile_commands_path: String,
    /// Number of mcp-clang RPC calls the agent issued during the run.
    /// Helps diagnose "0 findings" — high count + 0 findings means the
    /// agent looked but didn't conclude, low count + 0 findings means
    /// the clang index wasn't useful.
    #[serde(rename = "clangToolCalls")]
    pub clang_tool_calls: u32,
    /// Anyhow chain of the first mcp-clang call that errored, if any.
    /// Surfaces clangd index / compile_commands issues that would
    /// otherwise be invisible behind a "0 findings, ok: true".
    #[serde(rename = "firstClangError", skip_serializing_if = "Option::is_none")]
    pub first_clang_error: Option<String>,
    #[serde(rename = "stepsUsed")]
    pub steps_used: u32,
    pub truncated: bool,
    #[serde(rename = "costUsd")]
    pub cost_usd: f64,
    #[serde(skip)]
    pub cost_usd_exact: bool,
}
