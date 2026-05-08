use super::*;

pub(crate) fn contains_destructive_shell_fragment(cmd: &str) -> bool {
    [
        "rm -rf",
        "rm -fr",
        "git push --force",
        "git push -f",
        "chmod -r 777",
        "dd of=/dev/",
        "> /dev/sda",
        "mkfs",
        "git reset --hard origin",
        "git filter-branch",
    ]
    .iter()
    .any(|needle| cmd.contains(needle))
}

pub(crate) fn starts_with_destructive_system_verb(cmd: &str) -> bool {
    ["shutdown", "reboot"]
        .iter()
        .any(|prefix| cmd.starts_with(prefix))
}

pub(crate) fn is_force_with_lease_push(cmd: &str) -> bool {
    cmd.starts_with("git push") && cmd.contains("--force-with-lease=")
}

pub(crate) fn is_split_rm_rf(cmd: &str) -> bool {
    cmd.starts_with("rm ") && cmd.contains(" -rf")
}

pub fn parse_pending_patch(data: &serde_json::Value) -> Option<PendingPatch> {
    let alias = data
        .get("alias")
        .and_then(serde_json::Value::as_str)?
        .to_string();
    let rationale = data
        .get("rationale")
        .and_then(serde_json::Value::as_str)?
        .to_string();
    let diff = data
        .get("diff")
        .and_then(serde_json::Value::as_str)?
        .to_string();
    let side_effect = data
        .get("side_effect")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let tests = data
        .get("tests")
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|t| {
                    let name = t
                        .get("name")
                        .and_then(serde_json::Value::as_str)?
                        .to_string();
                    let blurb = t
                        .get("blurb")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    Some((name, blurb))
                })
                .collect()
        })
        .unwrap_or_default();
    let guardrail = data
        .get("guardrail")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let staged_at = data
        .get("staged_at")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    Some(PendingPatch {
        alias,
        rationale,
        side_effect,
        diff,
        tests,
        guardrail,
        staged_at,
    })
}
