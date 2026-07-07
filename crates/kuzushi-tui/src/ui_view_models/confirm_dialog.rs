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
        if confirm.allows_decision {
            "   y allow once · Y remember · n deny once · N deny + remember".to_string()
        } else {
            "   this request is refused unconditionally".to_string()
        },
    ]
    .into_iter()
    .filter(|row| !row.is_empty())
    .collect()
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
        keybinds: vec![
            ("y/n".to_string(), "once".to_string()),
            ("Y/N".to_string(), "remember".to_string()),
            ("Esc".to_string(), "back".to_string()),
        ],
        prompt_module: None,
    }
}
