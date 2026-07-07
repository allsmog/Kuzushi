use super::{cost_model, format_session_cost};
use crate::{
    commands::shell_command_specs, CommandPaletteFooter, CommandPaletteSnapshot,
    CommandPaletteStatus, ShellApp,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandPaletteModel {
    pub(crate) status: CommandPaletteStatus,
    pub(crate) body_rows: Vec<String>,
    pub(crate) footer: CommandPaletteFooter,
}

pub(crate) fn command_palette_model(app: &ShellApp) -> CommandPaletteModel {
    app.command_palette_snapshot()
        .cloned()
        .map(CommandPaletteModel::from)
        .unwrap_or_else(|| default_command_palette_model(app))
}

impl From<CommandPaletteSnapshot> for CommandPaletteModel {
    fn from(snapshot: CommandPaletteSnapshot) -> Self {
        Self {
            status: snapshot.status,
            body_rows: snapshot.body_rows,
            footer: snapshot.footer,
        }
    }
}

fn default_command_palette_model(app: &ShellApp) -> CommandPaletteModel {
    CommandPaletteModel {
        status: default_status(app),
        body_rows: default_body_rows(app),
        footer: default_footer(app),
    }
}

fn default_body_rows(app: &ShellApp) -> Vec<String> {
    let query = app.router.command_palette().query();
    let matches = app.palette_matches();
    let mut rows = vec![
        "--:--:--  *  Ctrl-G".to_string(),
        String::new(),
        format!("   ›  {query}"),
        palette_match_count_row(matches.len()),
        String::new(),
        " -- MATCHES -----------------------------------------------------------------------------------------------------------".to_string(),
    ];
    rows.extend(
        matches
            .into_iter()
            .take(10)
            .map(|spec| format!("    /{:<28} command · {}", spec.command, spec.description)),
    );
    if rows.len() == 6 {
        rows.push("    no matching commands".to_string());
    }
    rows.push(String::new());
    rows.push(
        " -- ACTIONS -----------------------------------------------------------------------------------------------------------"
            .to_string(),
    );
    rows.push("      enter load · ↑/↓ or Ctrl-P/Ctrl-N move · Esc close".to_string());
    rows.push(String::new());
    rows.push(
        " -- TIPS --------------------------------------------------------------------------------------------------------------"
            .to_string(),
    );
    rows.push(
        "      type a command name, alias, or help topic to narrow the command list".to_string(),
    );
    rows
}

fn palette_match_count_row(match_count: usize) -> String {
    let shown = match_count.min(10);
    format!("  matches {match_count}  ·  shown {shown}  ·  source built-ins")
}

fn default_status(app: &ShellApp) -> CommandPaletteStatus {
    CommandPaletteStatus {
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
        module: "palette".to_string(),
        cost: default_cost(app),
    }
}

fn default_cost(app: &ShellApp) -> String {
    cost_model(app)
        .budget_status
        .map(|status| status.cells[1].clone())
        .unwrap_or_else(|| format_session_cost(0.0))
}

fn default_footer(app: &ShellApp) -> CommandPaletteFooter {
    CommandPaletteFooter {
        stage: format!(
            "palette · \"{}\" · {} commands",
            app.router.command_palette().query(),
            shell_command_specs().count()
        ),
        findings: app.findings_total_count(),
        keybinds: vec![
            ("↑/↓".to_string(), "match".to_string()),
            ("enter".to_string(), "load".to_string()),
            ("Esc".to_string(), "close".to_string()),
        ],
        prompt_module: Some("palette".to_string()),
    }
}
