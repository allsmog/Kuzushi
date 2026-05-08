use super::prelude::*;
use super::*;

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
    pub(crate) tool_policy: AgentToolPolicy,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BridgeResponse {
    pub(crate) ok: bool,
    pub(crate) text: Option<String>,
    pub(crate) structured: Option<Value>,
    pub(crate) error: Option<String>,
}
