use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const TRACE_EXPANSION_CONTRACT_VERSION: u32 = 1;

/// Hard cap on steps per expansion: the agent task is bounded, and the store
/// stays legible. Extra steps are truncated, never silently reordered.
pub const MAX_TRACE_EXPANSION_STEPS: usize = 12;

/// What the operator asked for: the finding whose path should deepen, the
/// node ids of the currently rendered path (so the agent extends rather than
/// restates), and the free-form instruction from the Trace screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceExpansionRequest {
    #[serde(default = "default_contract_version")]
    pub version: u32,
    pub finding_fingerprint: String,
    #[serde(default)]
    pub current_path_node_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_instruction: Option<String>,
}

impl TraceExpansionRequest {
    pub fn new(finding_fingerprint: impl Into<String>) -> Self {
        Self {
            version: TRACE_EXPANSION_CONTRACT_VERSION,
            finding_fingerprint: finding_fingerprint.into(),
            current_path_node_ids: Vec::new(),
            operator_instruction: None,
        }
    }
}

/// One intermediary hop the agent recovered between the recorded anchors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceStep {
    pub symbol: String,
    pub file_path: String,
    pub line: u32,
    pub annotation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceExpansionResult {
    #[serde(default = "default_contract_version")]
    pub version: u32,
    pub finding_fingerprint: String,
    pub steps: Vec<TraceStep>,
    #[serde(default)]
    pub evidence_deltas: Vec<String>,
    #[serde(default)]
    pub open_questions: Vec<String>,
}

impl TraceExpansionResult {
    /// Enforce the step cap after parsing; the schema advertises it but the
    /// contract, not the provider, is the authority.
    pub fn clamped(mut self) -> Self {
        self.steps.truncate(MAX_TRACE_EXPANSION_STEPS);
        self
    }
}

fn default_contract_version() -> u32 {
    TRACE_EXPANSION_CONTRACT_VERSION
}

pub(crate) fn parse_trace_expansion_result(raw: Value) -> Result<TraceExpansionResult> {
    let result: TraceExpansionResult = serde_json::from_value(raw)?;
    anyhow::ensure!(
        result.version == TRACE_EXPANSION_CONTRACT_VERSION,
        "unsupported trace expansion contract version {}",
        result.version
    );
    Ok(result.clamped())
}

pub(crate) fn trace_expansion_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["version", "findingFingerprint", "steps"],
        "properties": {
            "version": {"type": "integer", "const": TRACE_EXPANSION_CONTRACT_VERSION},
            "findingFingerprint": {"type": "string"},
            "steps": {
                "type": "array",
                "maxItems": MAX_TRACE_EXPANSION_STEPS,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["symbol", "filePath", "line", "annotation"],
                    "properties": {
                        "symbol": {"type": "string"},
                        "filePath": {"type": "string"},
                        "line": {"type": "integer", "minimum": 0},
                        "annotation": {"type": "string"}
                    }
                }
            },
            "evidenceDeltas": {"type": "array", "items": {"type": "string"}},
            "openQuestions": {"type": "array", "items": {"type": "string"}}
        }
    })
}
