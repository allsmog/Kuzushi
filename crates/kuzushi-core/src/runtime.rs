use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::findings::{Finding, TriageOutcome};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageRequest {
    pub model: String,
    pub cwd: PathBuf,
    pub finding: Finding,
    pub prompt_template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentQueryRequest {
    pub model: String,
    pub cwd: PathBuf,
    pub system_prompt: String,
    pub prompt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentQueryResponse {
    pub text: String,
    pub structured: Option<Value>,
}

#[async_trait]
pub trait AgentRuntime: Send + Sync {
    fn query_blocking(&self, _request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        anyhow::bail!("agent runtime does not support generic pi-agent-core queries")
    }

    async fn query(&self, request: AgentQueryRequest) -> Result<AgentQueryResponse> {
        self.query_blocking(request)
    }

    fn triage_finding_blocking(&self, request: TriageRequest) -> Result<TriageOutcome>;

    async fn triage_finding(&self, request: TriageRequest) -> Result<TriageOutcome> {
        self.triage_finding_blocking(request)
    }
}
