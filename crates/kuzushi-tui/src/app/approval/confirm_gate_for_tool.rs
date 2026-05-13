use super::*;

pub fn confirm_gate_for_tool(
    tool: &str,
    input: &serde_json::Value,
    allowlist: &std::collections::BTreeSet<String>,
) -> Option<PendingConfirm> {
    // Destructive verb check first — destructive verbs are unconditional,
    // even an entry on the allowlist shouldn't bypass.
    let cmd_target = input
        .get("cmd")
        .and_then(serde_json::Value::as_str)
        .or_else(|| input.get("verb").and_then(serde_json::Value::as_str))
        .or_else(|| input.get("command").and_then(serde_json::Value::as_str))
        .unwrap_or("");
    if !cmd_target.is_empty() && is_destructive_verb(cmd_target) {
        return Some(PendingConfirm {
            kind: ConfirmKind::DestructiveVerb,
            tool: tool.to_string(),
            target: cmd_target.to_string(),
            rationale: input
                .get("rationale")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string),
            allowlist: None,
            actor: input
                .get("actor")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string),
            remembered: false,
        });
    }

    // Network egress: `sandbox:run` with `network: true` or a URL target.
    if tool == "sandbox:run" || tool.ends_with(":run-with-network") {
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
        if network || url_target {
            let key = confirm_allowlist_key(tool, target);
            if allowlist.contains(&key) {
                return None;
            }
            return Some(PendingConfirm {
                kind: ConfirmKind::NetworkEgress,
                tool: tool.to_string(),
                target: target.to_string(),
                rationale: input
                    .get("rationale")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string),
                allowlist: input
                    .get("allowlist_match")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string),
                actor: input
                    .get("actor")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string),
                remembered: false,
            });
        }
    }

    if tool == "pwn:run-candidates" {
        let target = input
            .get("target")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let max_attempts = input
            .get("maxAttempts")
            .or_else(|| input.get("max_attempts"))
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(10);
        let parallelism = input
            .get("parallelism")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(1);
        let state_id = input
            .get("stateId")
            .or_else(|| input.get("state_id"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let key = confirm_allowlist_key(tool, target);
        if allowlist.contains(&key) {
            return None;
        }
        return Some(PendingConfirm {
            kind: ConfirmKind::PwnCandidateAttempt,
            tool: tool.to_string(),
            target: target.to_string(),
            rationale: Some(format!(
                "state={state_id} · maxAttempts={max_attempts} · parallelism={parallelism}"
            )),
            allowlist: None,
            actor: input
                .get("actor")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string),
            remembered: false,
        });
    }

    // fs:write outside .kuzushi/.
    if tool == "fs:write" {
        let path = input
            .get("path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if !path.is_empty() && !path.starts_with(".kuzushi/") && !path.contains("/.kuzushi/") {
            let key = confirm_allowlist_key(tool, path);
            if allowlist.contains(&key) {
                return None;
            }
            return Some(PendingConfirm {
                kind: ConfirmKind::FsWriteOutsideKuzushi,
                tool: tool.to_string(),
                target: path.to_string(),
                rationale: input
                    .get("rationale")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string),
                allowlist: None,
                actor: input
                    .get("actor")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string),
                remembered: false,
            });
        }
    }

    None
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
