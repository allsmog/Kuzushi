use crate::{ConfirmKind, PendingConfirm, ShellApp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfirmCardModel {
    pub(crate) header_glyph: &'static str,
    pub(crate) header_label: &'static str,
    pub(crate) header_danger: bool,
    pub(crate) tool: String,
    pub(crate) target: String,
    pub(crate) actor: Option<String>,
    pub(crate) rationale: Option<String>,
    pub(crate) allowlist: Option<String>,
    pub(crate) allows_decision: bool,
    pub(crate) allows_remembered_yes: bool,
}

pub(crate) fn confirm_card_model(app: &ShellApp) -> Option<ConfirmCardModel> {
    app.advisory().pending_confirm.as_ref().map(|confirm| {
        let mut model = ConfirmCardModel::from_confirm(confirm);
        model.allows_decision &= crate::app::allowance::approval_visible(app);
        model
    })
}

impl ConfirmCardModel {
    fn from_confirm(confirm: &PendingConfirm) -> Self {
        Self {
            header_glyph: header_glyph(confirm.kind),
            header_label: confirm.kind.label(),
            header_danger: confirm.kind == ConfirmKind::DestructiveVerb,
            tool: confirm.tool.clone(),
            target: confirm.target.clone(),
            actor: confirm.actor.clone(),
            rationale: confirm.rationale.clone(),
            allowlist: confirm.allowlist.clone(),
            allows_decision: confirm.kind.allows_yes(),
            allows_remembered_yes: confirm.kind.allows_remembered_yes(),
        }
    }
}

fn header_glyph(kind: ConfirmKind) -> &'static str {
    match kind {
        ConfirmKind::DestructiveVerb => "✗",
        _ => "⚠",
    }
}

#[cfg(test)]
mod tests;
