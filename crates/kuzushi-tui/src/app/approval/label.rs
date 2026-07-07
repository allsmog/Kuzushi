use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmKind {
    NetworkEgress,
    FsWriteOutsideKuzushi,
    DestructiveVerb,
    PwnCandidateAttempt,
}

impl ConfirmKind {
    pub fn label(self) -> &'static str {
        match self {
            ConfirmKind::NetworkEgress => "CONFIRM · network egress",
            ConfirmKind::FsWriteOutsideKuzushi => "CONFIRM · fs:write outside .kuzushi/",
            ConfirmKind::DestructiveVerb => "REFUSED · destructive verb",
            ConfirmKind::PwnCandidateAttempt => "CONFIRM · pwn candidate attempts",
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
        if refuses_confirm_yes(&request, outcome) {
            return Some(PendingConfirm {
                remembered: false,
                ..request
            });
        }
        request.remembered = outcome && remember;
        self.remember_confirm_decision(&request, outcome, remember);
        self.log_confirm_resolution(&request, outcome, remember);
        Some(request)
    }

    fn remember_confirm_decision(
        &mut self,
        request: &PendingConfirm,
        outcome: bool,
        remember: bool,
    ) {
        if !remember {
            return;
        }
        let key = confirm_allowlist_key(&request.tool, &request.target);
        self.engagement.remember_confirm_decision(key, outcome);
    }

    fn log_confirm_resolution(&mut self, request: &PendingConfirm, outcome: bool, remember: bool) {
        self.log(
            "system",
            format!(
                "{} {}: {} {}",
                confirm_resolution_glyph(outcome),
                confirm_resolution_verb(outcome, remember),
                request.tool,
                request.target
            ),
        );
    }
}

pub(crate) fn confirm_allowlist_key(tool: &str, target: &str) -> String {
    format!("{tool} {target}")
}

fn refuses_confirm_yes(request: &PendingConfirm, outcome: bool) -> bool {
    !request.kind.allows_yes() && outcome
}

fn confirm_resolution_glyph(outcome: bool) -> &'static str {
    if outcome {
        "✓"
    } else {
        "✗"
    }
}

fn confirm_resolution_verb(outcome: bool, remember: bool) -> &'static str {
    match (outcome, remember) {
        (true, true) => "allowed (remembered for run)",
        (true, false) => "allowed once",
        (false, true) => "denied (added to denylist)",
        (false, false) => "denied once",
    }
}
