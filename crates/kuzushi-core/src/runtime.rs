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
    #[serde(default)]
    pub tool_policy: AgentToolPolicy,
}

impl AgentQueryRequest {
    pub fn new(
        model: impl Into<String>,
        cwd: impl Into<PathBuf>,
        system_prompt: impl Into<String>,
        prompt: impl Into<String>,
    ) -> Self {
        Self {
            model: model.into(),
            cwd: cwd.into(),
            system_prompt: system_prompt.into(),
            prompt: prompt.into(),
            tool_policy: AgentToolPolicy::default(),
        }
    }

    pub fn with_tool_policy(mut self, tool_policy: AgentToolPolicy) -> Self {
        self.tool_policy = tool_policy;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentToolPolicy {
    pub profile: String,
    #[serde(default)]
    pub tools: Vec<String>,
}

impl AgentToolPolicy {
    pub fn new(
        profile: impl Into<String>,
        tools: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            profile: profile.into(),
            tools: tools.into_iter().map(Into::into).collect(),
        }
    }

    pub fn is_default(&self) -> bool {
        self.profile == "default" && self.tools.is_empty()
    }
}

impl Default for AgentToolPolicy {
    fn default() -> Self {
        Self {
            profile: "default".to_string(),
            tools: Vec::new(),
        }
    }
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
