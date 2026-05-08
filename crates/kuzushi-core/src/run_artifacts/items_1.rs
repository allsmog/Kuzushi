use super::prelude::*;
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
            artifacts: Vec::new(),
        }
    }

    pub fn complete(mut self) -> Self {
        self.status = "complete".to_string();
        self.completed_at_unix = Some(now_unix());
        self
    }

    pub fn failed(mut self, error: impl Into<String>) -> Self {
        self.status = "failed".to_string();
        self.completed_at_unix = Some(now_unix());
        self.error = Some(error.into());
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
}

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
}
