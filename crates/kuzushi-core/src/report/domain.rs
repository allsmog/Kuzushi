use crate::run_artifacts::{RunArtifact, RunSummary};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalReportArtifact {
    pub file: String,
    pub label: String,
    pub path: String,
    pub present: bool,
    pub summary: String,
}

impl CanonicalReportArtifact {
    pub(crate) fn present(
        file: impl Into<String>,
        label: impl Into<String>,
        path: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            file: file.into(),
            label: label.into(),
            path: path.into(),
            present: true,
            summary: summary.into(),
        }
    }

    pub(crate) fn missing(
        file: impl Into<String>,
        label: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            file: file.into(),
            label: label.into(),
            path: path.into(),
            present: false,
            summary: "missing".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RunReportBuild {
    pub source_run_id: String,
    pub source_status: String,
    pub source_tool: Option<String>,
    pub report_path: String,
    pub report_markdown: String,
    pub summary: String,
    pub canonical_artifacts: Vec<CanonicalReportArtifact>,
    pub declared_artifacts: Vec<RunArtifact>,
    pub failure_handoffs: Vec<ReportFailureHandoff>,
}

impl RunReportBuild {
    pub(crate) fn new(
        source: RunSummary,
        report_path: impl Into<String>,
        report_markdown: impl Into<String>,
        canonical_artifacts: Vec<CanonicalReportArtifact>,
        declared_artifacts: Vec<RunArtifact>,
        failure_handoffs: Vec<ReportFailureHandoff>,
    ) -> Self {
        let summary = format!("Report built for run {}", source.run_id);
        Self {
            source_run_id: source.run_id,
            source_status: source.status,
            source_tool: source.tool,
            report_path: report_path.into(),
            report_markdown: report_markdown.into(),
            summary,
            canonical_artifacts,
            declared_artifacts,
            failure_handoffs,
        }
    }

    pub fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "status": "completed",
            "summary": self.summary,
            "reportMarkdown": self.report_markdown,
            "artifacts": [self.report_artifact()],
            "warnings": self.report_warnings(),
            "errors": [],
            "data": self,
        })
    }

    fn report_artifact(&self) -> Value {
        json!({
            "label": "report",
            "path": self.report_path,
            "kind": "markdown"
        })
    }

    fn report_warnings(&self) -> Vec<String> {
        self.canonical_artifacts
            .iter()
            .filter(|artifact| !artifact.present)
            .map(missing_artifact_warning)
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ReportFailureHandoff {
    pub failed_stage: String,
    pub cause: String,
    pub artifacts_available: Vec<RunArtifact>,
    pub allowed_proof_level: String,
    pub missing_artifacts: Vec<String>,
    pub next_files_or_artifacts_to_inspect: Vec<String>,
    pub recovery_options: Vec<String>,
    pub fallback_prompt: String,
    pub claims_forbidden: Vec<String>,
}

fn missing_artifact_warning(artifact: &CanonicalReportArtifact) -> String {
    format!("canonical artifact {} is missing", artifact.file)
}
