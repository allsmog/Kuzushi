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
    let result: kuzushi_core::PatchResult =
        serde_json::from_value(data.get("patchResult")?.clone()).ok()?;
    pending_patch_from_result(
        result,
        data.get("explanation").and_then(serde_json::Value::as_str),
    )
}

pub(crate) fn pending_patch_from_result(
    result: kuzushi_core::PatchResult,
    explanation: Option<&str>,
) -> Option<PendingPatch> {
    let tests = patch_validation_rows(&result);
    let diff = result.diff.filter(|diff| !diff.trim().is_empty())?;
    let rationale = explanation
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("reviewed patch candidate")
        .to_string();
    Some(PendingPatch {
        alias: result.fingerprint,
        patch_run_id: result.patch_run_id,
        status: result.status,
        rationale,
        side_effect: None,
        diff,
        tests,
        guardrail: patch_guardrail(result.status),
        staged_at: result.updated_at.or(result.created_at),
    })
}

fn patch_validation_rows(result: &kuzushi_core::PatchResult) -> Vec<(String, String)> {
    [
        ("build", result.build_command.as_deref()),
        ("test", result.test_command.as_deref()),
    ]
    .into_iter()
    .filter_map(|(name, command)| command.map(|command| (name.to_string(), command.to_string())))
    .collect()
}

fn patch_guardrail(status: kuzushi_core::PatchStatus) -> Option<String> {
    (status != kuzushi_core::PatchStatus::Sound).then(|| {
        format!(
            "Apply is blocked: persisted patch status is {} (SOUND required)",
            status.as_str()
        )
    })
}
