use super::*;

/// First confirmation gate a tool input trips, if any. Checked in priority
/// order: destructive verbs are unconditional (allowlist can't bypass), then the
/// allowlist-aware egress / candidate-attempt / fs-write gates.
pub fn confirm_gate_for_tool(
    tool: &str,
    input: &serde_json::Value,
    allowlist: &std::collections::BTreeSet<String>,
) -> Option<PendingConfirm> {
    destructive_verb_confirm(tool, input)
        .or_else(|| delegated_target_write_confirm(tool, input))
        .or_else(|| network_egress_confirm(tool, input, allowlist))
        .or_else(|| pwn_candidate_confirm(tool, input, allowlist))
        .or_else(|| fs_write_confirm(tool, input, allowlist))
}

fn delegated_target_write_confirm(tool: &str, input: &serde_json::Value) -> Option<PendingConfirm> {
    let auto_patch = tool == "sast:scan"
        && input
            .get("autoPatch")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
    auto_patch.then(|| PendingConfirm {
        kind: ConfirmKind::DescriptorEffect,
        tool: tool.to_string(),
        target: "patch:finding".to_string(),
        rationale: Some("autoPatch delegates an approved target write".to_string()),
        allowlist: None,
        actor: opt_str(input, "actor"),
        remembered: false,
    })
}

/// Descriptor-owned approval is the final shell gate. It deliberately does
/// not consult the session allowlist: a target write or external action must
/// mint a fresh dispatch proof through an affirmative confirmation.
pub fn descriptor_approval_confirm(
    descriptor: &kuzushi_core::ToolDescriptor,
    input: &serde_json::Value,
) -> Option<PendingConfirm> {
    if descriptor.approval != kuzushi_core::modules::ApprovalPolicy::Explicit {
        return None;
    }
    let target = ["target", "url", "path"]
        .into_iter()
        .find_map(|key| input.get(key).and_then(serde_json::Value::as_str))
        .unwrap_or(descriptor.name.as_str());
    Some(PendingConfirm {
        kind: ConfirmKind::DescriptorEffect,
        tool: descriptor.name.clone(),
        target: target.to_string(),
        rationale: Some(format!("declared {:?} effect", descriptor.effect)),
        allowlist: None,
        actor: opt_str(input, "actor"),
        remembered: false,
    })
}

fn opt_str(input: &serde_json::Value, key: &str) -> Option<String> {
    input
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string)
}

/// Destructive shell/system verbs are gated unconditionally — even an explicit
/// allowlist entry must not bypass them.
fn destructive_verb_confirm(tool: &str, input: &serde_json::Value) -> Option<PendingConfirm> {
    let cmd_target = input
        .get("cmd")
        .and_then(serde_json::Value::as_str)
        .or_else(|| input.get("verb").and_then(serde_json::Value::as_str))
        .or_else(|| input.get("command").and_then(serde_json::Value::as_str))
        .unwrap_or("");
    if cmd_target.is_empty() || !is_destructive_verb(cmd_target) {
        return None;
    }
    Some(PendingConfirm {
        kind: ConfirmKind::DestructiveVerb,
        tool: tool.to_string(),
        target: cmd_target.to_string(),
        rationale: opt_str(input, "rationale"),
        allowlist: None,
        actor: opt_str(input, "actor"),
        remembered: false,
    })
}

/// Network egress: `sandbox:run` (or a `:run-with-network` tool) with
/// `network: true` or an http(s) target. Allowlistable per (tool, target).
fn network_egress_confirm(
    tool: &str,
    input: &serde_json::Value,
    allowlist: &std::collections::BTreeSet<String>,
) -> Option<PendingConfirm> {
    if tool != "sandbox:run" && !tool.ends_with(":run-with-network") {
        return None;
    }
    let network = input
        .get("network")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let target = input
        .get("target")
        .and_then(serde_json::Value::as_str)
        .or_else(|| input.get("url").and_then(serde_json::Value::as_str))
        .unwrap_or("");
    let url_target = target.starts_with("http://") || target.starts_with("https://");
    if (!network && !url_target) || allowlist.contains(&confirm_allowlist_key(tool, target)) {
        return None;
    }
    Some(PendingConfirm {
        kind: ConfirmKind::NetworkEgress,
        tool: tool.to_string(),
        target: target.to_string(),
        rationale: opt_str(input, "rationale"),
        allowlist: opt_str(input, "allowlist_match"),
        actor: opt_str(input, "actor"),
        remembered: false,
    })
}

/// `pwn:run-candidates` launches exploit attempts — gate it (allowlistable per
/// target), surfacing the attempt budget in the rationale.
fn pwn_candidate_confirm(
    tool: &str,
    input: &serde_json::Value,
    allowlist: &std::collections::BTreeSet<String>,
) -> Option<PendingConfirm> {
    if tool != "pwn:run-candidates" {
        return None;
    }
    let target = input
        .get("target")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if allowlist.contains(&confirm_allowlist_key(tool, target)) {
        return None;
    }
    Some(PendingConfirm {
        kind: ConfirmKind::PwnCandidateAttempt,
        tool: tool.to_string(),
        target: target.to_string(),
        rationale: Some(pwn_attempt_rationale(input)),
        allowlist: None,
        actor: opt_str(input, "actor"),
        remembered: false,
    })
}

/// Human-readable summary of a pwn candidate run's attempt budget, for the
/// confirmation card.
fn pwn_attempt_rationale(input: &serde_json::Value) -> String {
    let i64_field = |keys: &[&str]| {
        keys.iter()
            .find_map(|k| input.get(*k).and_then(serde_json::Value::as_i64))
    };
    let max_attempts = i64_field(&["maxAttempts", "max_attempts"]).unwrap_or(10);
    let parallelism = i64_field(&["parallelism"]).unwrap_or(1);
    let state_id = input
        .get("stateId")
        .or_else(|| input.get("state_id"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    format!("state={state_id} · maxAttempts={max_attempts} · parallelism={parallelism}")
}

/// `fs:write` to a path outside `.kuzushi/`. A `..` component can escape the
/// directory while the string still starts with `.kuzushi/` (e.g.
/// `.kuzushi/../../etc/passwd`), so a traversal path is never treated as inside.
fn fs_write_confirm(
    tool: &str,
    input: &serde_json::Value,
    allowlist: &std::collections::BTreeSet<String>,
) -> Option<PendingConfirm> {
    if tool != "fs:write" {
        return None;
    }
    let path = input
        .get("path")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let inside_kuzushi =
        (path.starts_with(".kuzushi/") || path.contains("/.kuzushi/")) && !path.contains("..");
    if path.is_empty() || inside_kuzushi || allowlist.contains(&confirm_allowlist_key(tool, path)) {
        return None;
    }
    Some(PendingConfirm {
        kind: ConfirmKind::FsWriteOutsideKuzushi,
        tool: tool.to_string(),
        target: path.to_string(),
        rationale: opt_str(input, "rationale"),
        allowlist: None,
        actor: opt_str(input, "actor"),
        remembered: false,
    })
}

pub(crate) fn is_destructive_verb(cmd: &str) -> bool {
    let lower = cmd.to_lowercase();
    let stripped = lower.trim();
    [
        contains_destructive_shell_fragment(stripped),
        starts_with_destructive_system_verb(stripped),
        is_force_with_lease_push(stripped),
        is_split_rm_rf(stripped),
    ]
    .into_iter()
    .any(|matched| matched)
}
