use super::ShellApp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmKind {
    NetworkEgress,
    FsWriteOutsideKuzushi,
    DestructiveVerb,
}

impl ConfirmKind {
    pub fn label(self) -> &'static str {
        match self {
            ConfirmKind::NetworkEgress => "CONFIRM · network egress",
            ConfirmKind::FsWriteOutsideKuzushi => "CONFIRM · fs:write outside .kuzushi/",
            ConfirmKind::DestructiveVerb => "REFUSED · destructive verb",
        }
    }

    pub fn allows_yes(self) -> bool {
        !matches!(self, ConfirmKind::DestructiveVerb)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPatch {
    pub alias: String,
    pub rationale: String,
    pub side_effect: Option<String>,
    pub diff: String,
    pub tests: Vec<(String, String)>,
    pub guardrail: Option<String>,
    pub staged_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingConfirm {
    pub kind: ConfirmKind,
    pub tool: String,
    pub target: String,
    pub rationale: Option<String>,
    pub allowlist: Option<String>,
    pub actor: Option<String>,
    pub remembered: bool,
}

impl ShellApp {
    pub fn request_confirm(&mut self, request: PendingConfirm) {
        self.advisory.pending_confirm = Some(request);
    }

    pub fn resolve_confirm(&mut self, outcome: bool, remember: bool) -> Option<PendingConfirm> {
        let mut request = self.advisory.pending_confirm.take()?;
        if !request.kind.allows_yes() && outcome {
            return Some(PendingConfirm {
                remembered: false,
                ..request
            });
        }
        request.remembered = outcome && remember;
        if remember {
            let key = confirm_allowlist_key(&request.tool, &request.target);
            if outcome {
                self.confirm_allowlist.insert(key);
            } else {
                self.confirm_denylist.insert(key);
            }
        }
        let glyph = if outcome { "✓" } else { "✗" };
        let verb = if outcome {
            if remember {
                "allowed (remembered for run)"
            } else {
                "allowed once"
            }
        } else if remember {
            "denied (added to denylist)"
        } else {
            "denied once"
        };
        self.log(
            "system",
            format!(
                "{glyph} {verb}: {tool} {target}",
                tool = request.tool,
                target = request.target
            ),
        );
        Some(request)
    }
}

/// Stable key for a `<tool> <target>` allowlist/denylist entry.
fn confirm_allowlist_key(tool: &str, target: &str) -> String {
    format!("{tool} {target}")
}

/// Returns a `PendingConfirm` when `<tool>` + `<input>` look like a
/// gated dispatch per `design/mockups/confirm-dialog.jsx`:
///
///   - `sandbox:run` (or any `*:run` tool) with a `target` URL or
///     `network: true` → CONFIRM · network egress
///   - `fs:write` with a `path` outside `.kuzushi/` →
///     CONFIRM · fs:write outside .kuzushi/
///   - any tool whose `cmd` / `verb` matches a destructive pattern
///     (`rm -rf`, `git push --force`, `:force`, `chmod -R 777`,
///     `> /dev/`, ...) → REFUSED · destructive verb (no override).
///
/// `allowlist` is consulted first — already-approved `<tool> <target>`
/// entries skip the gate entirely.  Returns None for tools that aren't
/// known-risky.
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

/// Pattern-match destructive shell verbs.  Conservative: only flags
/// patterns that are unambiguously destructive (no false-positives on
/// `git push origin foo` etc.).
fn is_destructive_verb(cmd: &str) -> bool {
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

fn contains_destructive_shell_fragment(cmd: &str) -> bool {
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

fn starts_with_destructive_system_verb(cmd: &str) -> bool {
    ["shutdown", "reboot"]
        .iter()
        .any(|prefix| cmd.starts_with(prefix))
}

fn is_force_with_lease_push(cmd: &str) -> bool {
    cmd.starts_with("git push") && cmd.contains("--force-with-lease=")
}

fn is_split_rm_rf(cmd: &str) -> bool {
    cmd.starts_with("rm ") && cmd.contains(" -rf")
}

/// Parse a `patch:run` / `patch:finding` result into a `PendingPatch`.
/// Tools should produce `data` shaped like:
///   `{ alias, rationale, side_effect?, diff, tests: [{name, blurb}],
///      guardrail?, staged_at? }`
/// All fields except `alias` + `rationale` + `diff` are optional —
/// missing fields collapse to None / empty.
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
