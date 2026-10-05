use super::{confirm_card_model, cost_model, format_session_cost};
use crate::{ConfirmDialogFooter, ConfirmDialogSnapshot, ConfirmDialogStatus, ShellApp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfirmDialogModel {
    pub(crate) status: ConfirmDialogStatus,
    pub(crate) body_rows: Vec<String>,
    pub(crate) footer: ConfirmDialogFooter,
}

pub(crate) fn confirm_dialog_model(app: &ShellApp) -> ConfirmDialogModel {
    app.confirm_dialog_snapshot()
        .cloned()
        .map(ConfirmDialogModel::from)
        .unwrap_or_else(|| default_confirm_dialog_model(app))
}

impl From<ConfirmDialogSnapshot> for ConfirmDialogModel {
    fn from(snapshot: ConfirmDialogSnapshot) -> Self {
        Self {
            status: snapshot.status,
            body_rows: snapshot.body_rows,
            footer: snapshot.footer,
        }
    }
}

fn default_confirm_dialog_model(app: &ShellApp) -> ConfirmDialogModel {
    ConfirmDialogModel {
        status: default_status(app),
        body_rows: default_body_rows(app),
        footer: default_footer(app),
    }
}

fn default_status(app: &ShellApp) -> ConfirmDialogStatus {
    ConfirmDialogStatus {
        target: app
            .target()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string()),
        ctx: "not built".to_string(),
        model: app
            .config()
            .model
            .clone()
            .unwrap_or_else(|| "unconfigured".to_string()),
        module: "approval".to_string(),
        cost: default_cost(app),
    }
}

fn default_cost(app: &ShellApp) -> String {
    cost_model(app)
        .budget_status
        .map(|status| status.cells[1].clone())
        .unwrap_or_else(|| format_session_cost(0.0))
}

fn default_body_rows(app: &ShellApp) -> Vec<String> {
    let Some(confirm) = confirm_card_model(app) else {
        return vec![
            "--:--:--  ·  approvals · no pending runtime gate".to_string(),
            String::new(),
            " -- CONFIRM ------------------------------------------------------------------------------------------------------------".to_string(),
            "   no tool dispatch is waiting for operator approval".to_string(),
        ];
    };
    let action_row = confirm_dialog_action_row(&confirm);
    vec![
        "--:--:--  ◆  pending runtime approval".to_string(),
        String::new(),
        format!("   {} {}", confirm.header_glyph, confirm.header_label),
        format!("   tool          {}", confirm.tool),
        format!("   target        {}", confirm.target),
        optional_row("actor", confirm.actor),
        optional_row("rationale", confirm.rationale),
        optional_row("allowlist", confirm.allowlist),
        String::new(),
        action_row,
    ]
    .into_iter()
    .filter(|row| !row.is_empty())
    .collect()
}

fn confirm_dialog_action_row(confirm: &super::ConfirmCardModel) -> String {
    if !confirm.allows_decision {
        if !confirm.header_danger {
            return "   PgUp/PgDn review terms · Esc cancel".to_string();
        }
        return "   this request is refused unconditionally".to_string();
    }
    if confirm.allows_remembered_yes {
        return "   y allow once · Y remember · n deny once · N deny + remember".to_string();
    }
    "   y allow once · n deny once · N deny + remember".to_string()
}

fn optional_row(label: &str, value: Option<String>) -> String {
    value
        .map(|value| format!("   {label:<13} {value}"))
        .unwrap_or_default()
}

fn default_footer(app: &ShellApp) -> ConfirmDialogFooter {
    ConfirmDialogFooter {
        stage: if app.advisory().pending_confirm.is_some() {
            "pending confirm".to_string()
        } else {
            "no pending confirms".to_string()
        },
        findings: app.findings_total_count(),
        keybinds: confirm_dialog_footer_keybinds(app),
        prompt_module: None,
    }
}

fn confirm_dialog_footer_keybinds(app: &ShellApp) -> Vec<(String, String)> {
    let Some(confirm) = confirm_card_model(app) else {
        return vec![("Esc".to_string(), "back".to_string())];
    };
    if !confirm.allows_decision {
        return vec![
            ("n/Esc".to_string(), "close refusal".to_string()),
            ("N".to_string(), "deny + remember".to_string()),
        ];
    }
    let mut keybinds = vec![("y/n".to_string(), "once".to_string())];
    if confirm.allows_remembered_yes {
        keybinds.push(("Y/N".to_string(), "remember".to_string()));
    } else {
        keybinds.push(("N".to_string(), "deny + remember".to_string()));
    }
    keybinds.push(("Esc".to_string(), "deny once".to_string()));
    keybinds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConfirmKind, PendingConfirm};
    use kuzushi_core::V2Config;

    fn app_with_confirm(kind: ConfirmKind) -> ShellApp {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.advisory_mut().pending_confirm = Some(PendingConfirm {
            kind,
            tool: "recon:nmap".to_string(),
            target: "127.0.0.1".to_string(),
            rationale: None,
            allowlist: None,
            actor: None,
            remembered: false,
        });
        app
    }

    #[test]
    fn descriptor_dialog_omits_remembered_allow_from_body_and_footer() {
        let app = app_with_confirm(ConfirmKind::DescriptorEffect);

        let model = confirm_dialog_model(&app);

        assert!(model
            .body_rows
            .iter()
            .any(|row| row.contains("y allow once")));
        assert!(model
            .body_rows
            .iter()
            .any(|row| row.contains("N deny + remember")));
        assert!(model
            .body_rows
            .iter()
            .all(|row| !row.contains("Y remember")));
        assert!(model
            .footer
            .keybinds
            .iter()
            .all(|(key, _)| !key.contains('Y')));
    }

    #[test]
    fn allowlistable_dialog_keeps_remembered_allow() {
        let app = app_with_confirm(ConfirmKind::NetworkEgress);

        let model = confirm_dialog_model(&app);

        assert!(model.body_rows.iter().any(|row| row.contains("Y remember")));
        assert!(model.footer.keybinds.iter().any(|(key, _)| key == "Y/N"));
    }
}
