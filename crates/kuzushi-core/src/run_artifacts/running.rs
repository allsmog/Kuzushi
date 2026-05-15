use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunArtifact {
    pub label: String,
    pub path: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunLlmCallAudit {
    pub n: usize,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verb: Option<String>,
    pub model: String,
    pub provider: String,
    pub prompt_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunSummary {
    pub run_id: String,
    pub kind: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub target: String,
    pub started_at_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub llm_calls: Vec<RunLlmCallAudit>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<RunArtifact>,
}

impl RunSummary {
    pub fn running(
        run_id: impl Into<String>,
        kind: impl Into<String>,
        tool: Option<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            kind: kind.into(),
            status: "running".to_string(),
            tool,
            target: target.into(),
            started_at_unix: now_unix(),
            completed_at_unix: None,
            findings: None,
            cost_usd: None,
            error: None,
            process_id: None,
            llm_calls: Vec::new(),
            artifacts: Vec::new(),
        }
    }

    pub fn complete(mut self) -> Self {
        self.status = "completed".to_string();
        self.completed_at_unix = Some(now_unix());
        self.process_id = None;
        self
    }

    pub fn failed(mut self, error: impl Into<String>) -> Self {
        self.status = "failed".to_string();
        self.completed_at_unix = Some(now_unix());
        self.error = Some(error.into());
        self.process_id = None;
        self
    }

    pub fn interrupted(mut self, error: impl Into<String>) -> Self {
        self.status = "interrupted".to_string();
        self.completed_at_unix = Some(now_unix());
        self.error = Some(error.into());
        self.process_id = None;
        self
    }

    pub fn with_process_id(mut self, process_id: u32) -> Self {
        self.process_id = Some(process_id);
        self
    }

    pub fn with_findings(mut self, findings: Option<u64>) -> Self {
        self.findings = findings;
        self
    }

    pub fn with_cost(mut self, cost_usd: Option<f64>) -> Self {
        self.cost_usd = cost_usd;
        self
    }

    pub fn with_artifact(mut self, artifact: RunArtifact) -> Self {
        self.artifacts.push(artifact);
        self
    }

    pub fn with_llm_calls(mut self, llm_calls: Vec<RunLlmCallAudit>) -> Self {
        self.llm_calls = llm_calls;
        self
    }
}

// schema v2: adds module/feed metadata and optional LLM audit fields. All new
// fields are optional so older trace.jsonl files round-trip without rewrites.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct RunTraceStep {
    pub n: usize,
    pub kind: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verb: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_step: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_hash: Option<String>,
}
