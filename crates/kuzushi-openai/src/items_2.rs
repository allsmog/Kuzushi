use super::prelude::*;
use super::*;

pub(crate) fn build_messages_for_anthropic(
    initial_prompt: &str,
    history: &[LoopHistoryEntry],
) -> Vec<Value> {
    let mut messages = Vec::with_capacity(history.len() + 1);
    messages.push(serde_json::json!({
        "role": "user",
        "content": initial_prompt,
    }));
    for entry in history {
        match entry {
            LoopHistoryEntry::AssistantToolCall(call) => {
                messages.push(serde_json::json!({
                    "role": "assistant",
                    "content": [{
                        "type": "tool_use",
                        "id": call.call_id,
                        "name": call.name,
                        "input": call.input,
                    }],
                }));
            }
            LoopHistoryEntry::ToolResult(result) => {
                messages.push(serde_json::json!({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": result.call_id,
                        "content": stringify_tool_output(&result.output),
                        "is_error": result.is_error,
                    }],
                }));
            }
            LoopHistoryEntry::AssistantText(text) => {
                messages.push(serde_json::json!({
                    "role": "assistant",
                    "content": text,
                }));
            }
        }
    }
    messages
}

pub(crate) fn stringify_tool_output(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<non-serialisable>".to_string()),
    }
}

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
    #[serde(default)]
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
