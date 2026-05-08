use super::*;

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

pub(crate) fn confirm_allowlist_key(tool: &str, target: &str) -> String {
    format!("{tool} {target}")
}
