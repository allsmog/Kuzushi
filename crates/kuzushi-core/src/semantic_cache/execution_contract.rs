use crate::identity::{executable::implementation_identity, hash_parts, Blake3Hash};
use crate::runtime::{AgentQueryRequest, AgentRuntime, AgentToolPolicy};
use serde_json::{json, Value};

/// Versioned, secret-free projection. The adapter separately attests defaults
/// and backend configuration that do not live in `AgentQueryRequest`.
pub(crate) fn execution_query_cache_key(
    runtime: &dyn AgentRuntime,
    request: &AgentQueryRequest,
    tool_name: &str,
    schema_name: &str,
    schema: &Value,
) -> Option<Blake3Hash> {
    if request.tool_policy != AgentToolPolicy::default() {
        return None;
    }
    if request.temperature.is_some_and(|value| !value.is_finite()) {
        return None;
    }
    let runtime_identity = runtime.semantic_cache_identity(request)?;
    let projection = request_projection(request, tool_name, schema_name, schema);
    Some(hash_parts(
        "semantic-cache:structured-query:v2",
        &[
            implementation_identity()?.as_bytes(),
            runtime_identity.as_str().as_bytes(),
            projection.to_string().as_bytes(),
        ],
    ))
}

fn request_projection(
    request: &AgentQueryRequest,
    tool_name: &str,
    schema_name: &str,
    schema: &Value,
) -> Value {
    let options = request.runtime_options.as_ref();
    json!({
        "model": request.model,
        "cwd": request.cwd,
        "systemPrompt": request.system_prompt,
        "prompt": request.prompt,
        "cacheablePromptPrefix": request.cacheable_prompt_prefix,
        "toolName": tool_name,
        "schemaName": schema_name,
        "schema": schema,
        "thinkingLevel": request.thinking_level,
        "maxOutputTokens": request.max_output_tokens,
        "temperature": request.temperature,
        "maxModelTurns": options.and_then(|value| value.max_model_turns),
        "observedSpendStopUsd": options.and_then(|value| value.observed_spend_stop_usd),
    })
}
