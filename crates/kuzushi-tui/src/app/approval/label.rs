use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmKind {
    NetworkEgress,
    FsWriteOutsideKuzushi,
    DestructiveVerb,
    PwnCandidateAttempt,
    DescriptorEffect,
    InvestigationAllowance,
    InvestigationWork,
}

impl ConfirmKind {
    pub fn label(self) -> &'static str {
        match self {
            ConfirmKind::NetworkEgress => "CONFIRM · network egress",
            ConfirmKind::FsWriteOutsideKuzushi => "CONFIRM · fs:write outside .kuzushi/",
            ConfirmKind::DestructiveVerb => "REFUSED · destructive verb",
            ConfirmKind::PwnCandidateAttempt => "CONFIRM · pwn candidate attempts",
            ConfirmKind::DescriptorEffect => "CONFIRM · descriptor-declared effect",
            ConfirmKind::InvestigationAllowance => "CONFIRM · investigation allowance",
            ConfirmKind::InvestigationWork => "CONFIRM · finite investigation work",
        }
    }

    pub fn allows_yes(self) -> bool {
        !matches!(self, ConfirmKind::DestructiveVerb)
    }

    pub fn allows_remembered_yes(self) -> bool {
        matches!(
            self,
            ConfirmKind::NetworkEgress
                | ConfirmKind::FsWriteOutsideKuzushi
                | ConfirmKind::PwnCandidateAttempt
        )
    }

    pub(crate) fn allows_action(self, outcome: bool, remember: bool) -> bool {
        !outcome || (self.allows_yes() && (!remember || self.allows_remembered_yes()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RememberedConfirmDecision {
    Allow,
    Deny,
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPatch {
    pub alias: String,
    pub patch_run_id: String,
    pub status: kuzushi_core::PatchStatus,
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
        let advisory = self.advisory_mut();
        advisory.pending_confirm = Some(request);
        advisory.pending_confirm_launch = None;
    }

    pub(crate) fn request_confirm_for_run(
        &mut self,
        request: PendingConfirm,
        launch: RunToolLaunch,
    ) {
        self.request_confirm(request);
        self.advisory_mut().pending_confirm_launch = Some(launch);
    }

    pub fn resolve_confirm(&mut self, outcome: bool, remember: bool) -> Option<PendingConfirm> {
        let pending = self.advisory().pending_confirm.as_ref()?;
        if !pending.kind.allows_action(outcome, remember) {
            return None;
        }
        if outcome && !super::allowance::approval_visible(self) {
            return None;
        }
        let mut request = self.advisory_mut().pending_confirm.take()?;
        request.remembered = remember;
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

pub(crate) fn remembered_confirm_decision(
    request: &PendingConfirm,
    allowlist: &std::collections::BTreeSet<String>,
    denylist: &std::collections::BTreeSet<String>,
) -> RememberedConfirmDecision {
    let key = confirm_allowlist_key(&request.tool, &request.target);
    if denylist.contains(&key) {
        return RememberedConfirmDecision::Deny;
    }
    if request.kind.allows_remembered_yes() && allowlist.contains(&key) {
        return RememberedConfirmDecision::Allow;
    }
    RememberedConfirmDecision::Ask
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

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;
    use std::collections::BTreeSet;

    fn descriptor_confirm() -> PendingConfirm {
        PendingConfirm {
            kind: ConfirmKind::DescriptorEffect,
            tool: "recon:nmap".to_string(),
            target: "127.0.0.1".to_string(),
            rationale: None,
            allowlist: None,
            actor: None,
            remembered: false,
        }
    }

    #[test]
    fn remembered_denial_wins_over_a_contradictory_allow() {
        let request = descriptor_confirm();
        let key = confirm_allowlist_key(&request.tool, &request.target);
        let allowlist = BTreeSet::from([key.clone()]);
        let denylist = BTreeSet::from([key]);

        assert_eq!(
            remembered_confirm_decision(&request, &allowlist, &denylist),
            RememberedConfirmDecision::Deny
        );
    }

    #[test]
    fn descriptor_confirm_ignores_legacy_remembered_allow() {
        let request = descriptor_confirm();
        let key = confirm_allowlist_key(&request.tool, &request.target);

        assert_eq!(
            remembered_confirm_decision(&request, &BTreeSet::from([key]), &BTreeSet::new()),
            RememberedConfirmDecision::Ask
        );
    }

    #[test]
    fn direct_resolver_rejects_descriptor_remembered_allow_without_mutation() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.advisory_mut().pending_confirm = Some(descriptor_confirm());
        let log_len = app.log_len();

        assert!(app.resolve_confirm(true, true).is_none());
        assert!(app.advisory().pending_confirm.is_some());
        assert!(app.engagement.confirm_allowlist().is_empty());
        assert!(app.engagement.confirm_denylist().is_empty());
        assert_eq!(app.log_len(), log_len);
    }

    #[test]
    fn remembering_a_new_decision_removes_the_opposite_entry() {
        let mut app = ShellApp::new(V2Config::default(), None);
        let key = "sandbox:run https://example.test".to_string();

        app.engagement.remember_confirm_decision(key.clone(), true);
        app.engagement.remember_confirm_decision(key.clone(), false);
        assert!(!app.engagement.confirm_allowlist().contains(&key));
        assert!(app.engagement.confirm_denylist().contains(&key));

        app.engagement.remember_confirm_decision(key.clone(), true);
        assert!(app.engagement.confirm_allowlist().contains(&key));
        assert!(!app.engagement.confirm_denylist().contains(&key));
    }
}
