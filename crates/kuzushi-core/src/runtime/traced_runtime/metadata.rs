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
    let args_summary = preview_value(&call.input);
    if args_summary.is_empty() {
        format!("tool-call · {} (turn {})", call.name, history_len + 1)
    } else {
        format!(
            "tool-call · {}({}) (turn {})",
            call.name,
            args_summary,
            history_len + 1
        )
    }
}

pub(super) fn final_label(text: &str, history_len: usize) -> String {
    let preview = preview_text(text);
    if preview.is_empty() {
        format!("final · turn {}", history_len + 1)
    } else {
        format!("final · {preview}")
    }
}

pub fn model_provider(model: &str) -> &str {
    model.split_once(':').map(|(provider, _)| provider).unwrap_or("")
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

pub(super) fn preview_text(text: &str) -> String {
    let mut body = text.trim_start();
    let mut opening_fence = None;
    if let Some(rest) = strip_opening_fence(body, "```") {
        body = rest;
        opening_fence = Some("```");
    } else if let Some(rest) = strip_opening_fence(body, "~~~") {
        body = rest;
        opening_fence = Some("~~~");
    }
    if let Some(fence) = opening_fence {
        body = strip_closing_fence(body, fence);
    }
    let collapsed = body.replace(['\n', '\r'], " ");
    preview_str(&collapsed.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn strip_opening_fence<'a>(text: &'a str, fence: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(fence)?;
    let rest = rest.trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    Some(rest.trim_start_matches(['\n', '\r']))
}

fn strip_closing_fence<'a>(text: &'a str, fence: &str) -> &'a str {
    text.trim_end()
        .strip_suffix(fence)
        .map(str::trim_end)
        .unwrap_or(text)
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

fn preview_value(value: &Value) -> String {
    if value.is_null() {
        return String::new();
    }
    let value = value.to_string();
    if value.chars().count() <= 60 {
        value
    } else {
        let mut out = value.chars().take(57).collect::<String>();
        out.push_str("...");
        out
    }
}
