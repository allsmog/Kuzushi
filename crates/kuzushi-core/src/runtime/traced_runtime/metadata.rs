use super::*;

pub(super) fn subagent_trace_verb(role: SubagentRole) -> &'static str {
    const VERBS: &[(SubagentRole, &str)] = &[
        (SubagentRole::Generic, "subagent"),
        (SubagentRole::UnsafeBlockReasoner, "subagent-unsafe"),
        (SubagentRole::LifetimeAliasingReasoner, "subagent-lifetime"),
        (SubagentRole::FfiBoundaryReasoner, "subagent-ffi"),
    ];
    VERBS
        .iter()
        .find_map(|(candidate, verb)| (*candidate == role).then_some(*verb))
        .unwrap_or("subagent")
}

pub(super) fn tool_call_label(call: &ToolCall, history_len: usize) -> String {
    let action = safe_tool_action_summary(call);
    format!("agent-action: {action} · turn {}", history_len + 1)
}

pub(super) fn final_label(history_len: usize) -> String {
    format!("model completed · turn {}", history_len + 1)
}

pub(super) fn safe_error_label(verb: &str, error: &anyhow::Error) -> String {
    format!("{verb} failed ({})", model_error_class(error))
}

pub(super) fn model_error_class(error: &anyhow::Error) -> &'static str {
    crate::runtime::runtime_failure_metadata(error)
        .map(|metadata| metadata.error_class.as_str())
        .unwrap_or_else(|| model_error_class_from_message(&error.to_string()))
}

pub fn model_error_class_from_message(message: &str) -> &'static str {
    let normalized = message.to_ascii_lowercase();
    if normalized.contains("cancel") || normalized.contains("interrupt") {
        "canceled"
    } else if normalized.contains("timeout") || normalized.contains("timed out") {
        "timeout"
    } else if normalized.contains("429")
        || normalized.contains("rate limit")
        || normalized.contains("rate_limited")
    {
        "rate_limited"
    } else if normalized.contains("401")
        || normalized.contains("403")
        || normalized.contains("auth")
        || normalized.contains("credential")
    {
        "authentication"
    } else if normalized.contains("sdk_client_validation")
        || normalized.contains("client-side before sending")
        || normalized.contains("invocation param")
    {
        "sdk_client_validation"
    } else if normalized.contains("parse")
        || normalized.contains("schema")
        || normalized.contains("invalid response")
        || normalized.contains("invalid_response")
    {
        "invalid_response"
    } else if normalized.contains("connect")
        || normalized.contains("network")
        || normalized.contains("transport")
    {
        "transport"
    } else {
        "runtime_error"
    }
}

/// Produces an operator-safe model failure summary without retaining provider
/// response content or adapter diagnostics.
pub fn safe_model_failure_message(message: &str) -> String {
    let safe = format!(
        "model request failed ({})",
        model_error_class_from_message(message)
    );
    let persistence_failure = format!("{safe}; additionally, terminal run persistence failed");
    if message == safe || message == persistence_failure {
        return message.to_string();
    }
    safe
}

pub fn model_provider(model: &str) -> &str {
    model
        .split_once(':')
        .map(|(provider, _)| provider)
        .unwrap_or("")
}

pub fn prompt_pair_hash(system_prompt: &str, prompt: &str) -> String {
    stable_prompt_hash(&[system_prompt, prompt])
}

pub(super) fn triage_prompt_hash(request: &TriageRequest) -> String {
    stable_prompt_hash(&[
        request.prompt_template.as_deref().unwrap_or(""),
        &request.finding.fingerprint,
        &request.finding.title,
        &request.finding.file_path,
    ])
}

fn stable_prompt_hash(parts: &[&str]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for part in parts {
        hash = fnv1a_update(hash, part.as_bytes());
        hash = fnv1a_update(hash, &[0xff]);
    }
    format!("fnv1a64:{hash:016x}")
}

fn fnv1a_update(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

pub(super) fn preview_str(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.chars().count() <= 80 {
        trimmed.to_string()
    } else {
        let mut out = trimmed.chars().take(77).collect::<String>();
        out.push_str("...");
        out
    }
}

fn safe_tool_action_summary(call: &ToolCall) -> String {
    let name = safe_trace_fragment(&call.name);
    let Value::Object(options) = &call.input else {
        return name;
    };
    let names = options
        .keys()
        .take(8)
        .map(|key| safe_trace_fragment(key))
        .collect::<Vec<_>>();
    if names.is_empty() {
        name
    } else {
        format!("{name} · options {}", names.join(", "))
    }
}

fn safe_trace_fragment(value: &str) -> String {
    let escaped = value
        .chars()
        .flat_map(|character| character.escape_default())
        .collect::<String>();
    preview_str(&escaped)
}

#[cfg(test)]
mod error_label_tests {
    use super::*;

    #[test]
    fn model_error_labels_never_echo_response_content() {
        let sentinel = "raw-model-response-sentinel";
        let error = anyhow::anyhow!("could not parse response: {sentinel}");

        let label = safe_error_label("query", &error);

        assert_eq!(label, "query failed (invalid_response)");
        assert!(!label.contains(sentinel));
    }

    #[test]
    fn safe_model_failure_messages_are_bounded_and_idempotent() {
        let sentinel = "RAW_MODEL_RESPONSE_SENTINEL";
        let message =
            safe_model_failure_message(&format!("provider returned invalid response: {sentinel}"));

        assert_eq!(message, "model request failed (invalid_response)");
        assert_eq!(safe_model_failure_message(&message), message);
        let persistence = format!("{message}; additionally, terminal run persistence failed");
        assert_eq!(safe_model_failure_message(&persistence), persistence);
        assert!(!message.contains(sentinel));
    }

    #[test]
    fn wrapped_typed_failures_keep_their_runtime_class() {
        let metadata = crate::runtime::RuntimeFailureMetadata::new(
            crate::runtime::RuntimeFailureClass::Authentication,
            None,
            None,
        );
        let error = anyhow::Error::new(crate::runtime::RuntimeFailure::new(metadata))
            .context("structured output failed");

        assert_eq!(safe_error_label("query", &error), "query failed (authentication)");
    }
}
