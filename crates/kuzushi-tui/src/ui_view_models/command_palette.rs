use super::{cost_model, format_session_cost};
use crate::{CommandPaletteFooter, CommandPaletteSnapshot, CommandPaletteStatus, ShellApp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandPaletteModel {
    pub(crate) status: CommandPaletteStatus,
    pub(crate) rows: Vec<PaletteRow>,
    pub(crate) footer: CommandPaletteFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PaletteRow {
    Query(String),
    Summary(String),
    Section(&'static str),
    Match {
        label: String,
        kind: &'static str,
        description: String,
        selected: bool,
    },
    Empty(String),
    Guidance(String),
    Blank,
    Legacy(String),
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
            rows: snapshot
                .body_rows
                .into_iter()
                .map(PaletteRow::Legacy)
                .collect(),
            footer: snapshot.footer,
        }
    }
}

fn default_command_palette_model(app: &ShellApp) -> CommandPaletteModel {
    CommandPaletteModel {
        status: default_status(app),
        rows: default_rows(app),
        footer: default_footer(app),
    }
}

fn default_rows(app: &ShellApp) -> Vec<PaletteRow> {
    let query = app.router.command_palette().query();
    let matches = app.palette_matches();
    let cursor = app
        .router
        .command_palette()
        .cursor()
        .min(matches.len().saturating_sub(1));
    let window_start = cursor.saturating_sub(6);
    let mut rows = palette_header_rows(query, matches.len());
    rows.extend(palette_entry_rows(&matches, cursor, window_start));
    if matches.is_empty() {
        rows.push(PaletteRow::Empty("no matching commands".to_string()));
    }
    rows.extend(palette_guidance_rows());
    rows
}

fn palette_header_rows(query: &str, match_count: usize) -> Vec<PaletteRow> {
    vec![
        PaletteRow::Query(query.to_string()),
        PaletteRow::Summary(palette_match_count_row(match_count)),
        PaletteRow::Blank,
        PaletteRow::Section("MATCHES"),
    ]
}

fn palette_entry_rows(
    matches: &[crate::app::PaletteEntry],
    cursor: usize,
    window_start: usize,
) -> Vec<PaletteRow> {
    matches
        .iter()
        .enumerate()
        .skip(window_start)
        .take(7)
        .map(|(index, entry)| PaletteRow::Match {
            label: entry.label.clone(),
            kind: entry.kind.label(),
            description: entry.description.clone(),
            selected: index == cursor,
        })
        .collect()
}

fn palette_guidance_rows() -> Vec<PaletteRow> {
    vec![
        PaletteRow::Blank,
        PaletteRow::Guidance(
            "Enter load · ↑/↓ move · Esc close · commands, tools, and modules".to_string(),
        ),
    ]
}

fn palette_match_count_row(match_count: usize) -> String {
    let shown = match_count.min(7);
    format!("  matches {match_count}  ·  shown {shown}  ·  commands/tools/modules")
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
            app.palette_entry_count()
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

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn recon_query_includes_ranked_tool_and_module_entries() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.open_command_palette();
        for ch in "recon".chars() {
            app.palette_input(ch);
        }

        let matches = app.palette_matches();
        assert!(matches
            .iter()
            .any(|entry| entry.kind.label() == "tool" && entry.label == "recon:import"));
        assert!(matches
            .iter()
            .any(|entry| entry.kind.label() == "module" && entry.label == "recon"));
        assert!(matches
            .first()
            .is_some_and(|entry| entry.label.to_ascii_lowercase().starts_with("recon")));
    }

    #[test]
    fn selected_palette_row_stays_windowed_and_has_non_color_marker() {
        let mut app = ShellApp::new(V2Config::default(), None);
        app.open_command_palette();
        for _ in 0..14 {
            app.palette_move(1);
        }

        let model = command_palette_model(&app);
        let selected = model
            .rows
            .iter()
            .filter(|row| matches!(row, PaletteRow::Match { selected: true, .. }))
            .collect::<Vec<_>>();
        assert_eq!(selected.len(), 1, "{:?}", model.rows);
    }
}
