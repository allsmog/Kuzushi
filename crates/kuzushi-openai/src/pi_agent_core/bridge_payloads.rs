use kuzushi_core::{AgentStructuredOutput, AgentToolPolicy};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NextStepBridgeRequest {
    #[serde(rename = "type")]
    pub(crate) envelope_type: &'static str,
    pub(crate) model: String,
    pub(crate) cwd: String,
    pub(crate) system_prompt: String,
    pub(crate) messages: Vec<Value>,
    pub(crate) tools: Vec<BridgeTool>,
    pub(crate) max_tokens: u32,
    pub(crate) api_key_env: String,
    pub(crate) api_key: Option<String>,
    pub(crate) base_url: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BridgeTool {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) input_schema: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NextStepBridgeResponse {
    pub(crate) ok: bool,
    #[serde(default)]
    pub(crate) step: Option<String>,
    #[serde(default)]
    pub(crate) text: Option<String>,
    #[serde(default)]
    pub(crate) structured: Option<Value>,
    #[serde(default, alias = "cost_usd")]
    pub(crate) cost_usd: Option<f64>,
    #[serde(default)]
    pub(crate) call: Option<NextStepBridgeCall>,
    #[serde(default)]
    pub(crate) error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NextStepBridgeCall {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) input: Value,
    #[serde(rename = "callId")]
    pub(crate) call_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BridgeRequest {
    pub(crate) model: String,
    pub(crate) cwd: String,
    pub(crate) system_prompt: String,
    pub(crate) prompt: String,
    pub(crate) structured_output: Option<AgentStructuredOutput>,
    pub(crate) api_key_env: String,
    pub(crate) api_key: Option<String>,
    pub(crate) base_url: Option<String>,
    pub(crate) thinking_level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) max_output_tokens: Option<u32>,
    pub(crate) tool_policy: AgentToolPolicy,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BridgeResponse {
    pub(crate) ok: bool,
    pub(crate) text: Option<String>,
    pub(crate) structured: Option<Value>,
    pub(crate) error: Option<String>,
    #[serde(default)]
    pub(crate) truncated: bool,
    #[serde(default)]
    pub(crate) stop_reason: Option<String>,
    #[serde(default, alias = "cost_usd")]
    pub(crate) cost_usd: Option<f64>,
    #[serde(default, alias = "input_tokens")]
    pub(crate) input_tokens: Option<u64>,
    #[serde(default, alias = "output_tokens")]
    pub(crate) output_tokens: Option<u64>,
}
