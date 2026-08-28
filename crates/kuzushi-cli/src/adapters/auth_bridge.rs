//! Presentation for `auth ping` bridge results.
//!
//! Building the ping envelope and spawning the bridge belong to the shared
//! runtime (`LangGraphRuntime::auth_ping_blocking`), which binds the
//! credential to the model's provider. This module only renders what came
//! back.

use kuzushi_openai::PingBridgeResponse;

pub(crate) fn bridge_ping_error(parsed: &PingBridgeResponse) -> Option<String> {
    if parsed.ok {
        return None;
    }
    Some(
        parsed
            .error
            .clone()
            .unwrap_or_else(|| "(no error message)".to_string()),
    )
}

pub(crate) fn bridge_ping_summary(parsed: &PingBridgeResponse) -> String {
    let auth_mode = parsed.auth_mode.as_deref().unwrap_or("?");
    let latency_ms = parsed.latency_ms.unwrap_or(0);
    let in_tok = parsed.input_tokens.unwrap_or(0);
    let out_tok = parsed.output_tokens.unwrap_or(0);
    let cost = parsed.cost_usd.unwrap_or(0.0);
    format!(
        "round-trip ok via {auth_mode} ({latency_ms}ms, {in_tok}/{out_tok} tokens, ~${cost:.5})"
    )
}
