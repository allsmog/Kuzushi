use super::*;
pub(in crate::renderer) use super::*;
use crate::ui_view_models::{
    help_model, quickstart_model, transcript_model_from_log_index, HelpCommandRow,
};

const HELP_COMMAND_COLUMN: usize = 0;
const HELP_ALIASES_COLUMN: usize = 1;
const HELP_DESCRIPTION_COLUMN: usize = 2;

pub(crate) fn help_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = help_model(app.router.help().filter());
    lines.extend(help_header_lines(
        model.intro,
        model.glossary,
        model.filter_note.as_deref(),
        &model.examples,
        area.width,
    ));
    for category in &model.categories {
        lines.push(blank());
        lines.push(category_divider(category.label, category.blurb, area.width));
        for row in &category.commands {
            lines.extend(help_command_lines(row, area.width));
        }
    }
    lines
}

fn help_header_lines(
    intro: &str,
    glossary: &str,
    filter_note: Option<&str>,
    examples: &[&str],
    width: u16,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        blank(),
        divider("HELP", width),
        muted(&fit(intro, width as usize)),
        muted(&fit(glossary, width as usize)),
    ];
    if let Some(note) = filter_note {
        lines.push(muted(&fit(note, width as usize)));
    }
    if !examples.is_empty() {
        lines.push(muted(&fit(
            &format!("Examples: {}", examples.join("  ·  ")),
            width as usize,
        )));
    }
    lines
}

/// One command as one or more lines. Wide terminals keep the three-column
/// grid and wrap an overflowing description onto indented continuation
/// lines; narrow terminals stack the aliases on their own subtle line so
/// neither the aliases nor the description is ever cut to an ellipsis.
fn help_command_lines(row: &HelpCommandRow, width: u16) -> Vec<Line<'static>> {
    let total = width as usize;
    if total >= 96 {
        wide_help_command_lines(row, total)
    } else {
        stacked_help_command_lines(row, total)
    }
}

fn wide_help_command_lines(row: &HelpCommandRow, total: usize) -> Vec<Line<'static>> {
    const COMMAND_WIDTH: usize = 28;
    const ALIASES_WIDTH: usize = 32;
    let description_indent = COMMAND_WIDTH + 2 + ALIASES_WIDTH + 2;
    let description_width = total.saturating_sub(description_indent).max(20);
    let chunks = wrap_text(&row.cells[HELP_DESCRIPTION_COLUMN], description_width);
    let mut lines = vec![table_row(
        &[
            &fit(&row.cells[HELP_COMMAND_COLUMN], COMMAND_WIDTH),
            &fit(&row.cells[HELP_ALIASES_COLUMN], ALIASES_WIDTH),
            chunks.first().map(String::as_str).unwrap_or(""),
        ],
        &[COMMAND_WIDTH, ALIASES_WIDTH, description_width],
    )];
    for chunk in chunks.iter().skip(1) {
        lines.push(muted(&format!(
            "{:indent$}{chunk}",
            "",
            indent = description_indent
        )));
    }
    lines
}

fn stacked_help_command_lines(row: &HelpCommandRow, total: usize) -> Vec<Line<'static>> {
    let command = &row.cells[HELP_COMMAND_COLUMN];
    let column = command.chars().count().max(24);
    let description_width = total.saturating_sub(column + 2).max(16);
    let chunks = wrap_text(&row.cells[HELP_DESCRIPTION_COLUMN], description_width);
    let mut lines = vec![table_row(
        &[
            command.as_str(),
            chunks.first().map(String::as_str).unwrap_or(""),
        ],
        &[column, description_width],
    )];
    for chunk in chunks.iter().skip(1) {
        lines.push(muted(&format!(
            "{:indent$}{chunk}",
            "",
            indent = column + 2
        )));
    }
    for alias_chunk in wrap_text(
        &format!("aliases / examples: {}", row.cells[HELP_ALIASES_COLUMN]),
        total.saturating_sub(2).max(16),
    ) {
        lines.push(Line::styled(format!("  {alias_chunk}"), theme::subtle()));
    }
    lines
}

pub(crate) fn quickstart_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    let model = quickstart_model(app);
    lines.push(blank());
    lines.push(divider("QUICKSTART", area.width));
    lines.push(blank());
    lines.push(Line::styled(
        "Welcome to kuzushi. Operator path:",
        theme::heading(),
    ));
    lines.push(blank());
    for step in &model.steps {
        lines.push(Line::from(vec![
            Span::styled(format!("  {}. ", step.number), theme::accent()),
            Span::styled(
                fit(&step.text, area.width.saturating_sub(5) as usize),
                theme::primary(),
            ),
        ]));
    }
    lines.push(blank());
    lines.push(muted(&fit(
        "Tip: Ctrl+O toggles the session story.",
        area.width as usize,
    )));
    lines.push(muted(&fit(&model.first_finding_tip, area.width as usize)));
    lines.push(blank());
    lines.push(muted(&fit(
        "Type `help` for the full command reference, or `back` to return.",
        area.width as usize,
    )));
    lines
}

/// Full-screen scrollable transcript view (M1 §1.1). Unlike the embedded
/// 2-row transcript strip at the bottom of every other view, this paints
/// the entire log buffer; `j`/`k`/`g`/`G`/`PgUp`/`PgDn` page through it.
pub(crate) fn logs_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("LOGS", area.width));
    let total = app.log_len();
    let hint =
        format!("{total} log lines · j/k scroll · g/G jump · PgUp/PgDn page · back to return");
    lines.push(muted(&fit(&hint, area.width as usize)));
    lines.push(blank());
    let model = transcript_model_from_log_index(app, 0);
    for row in model.rows {
        lines.push(transcript_line_dated(
            &row.prefix,
            &row.body,
            row.continuation,
            row.time_secs,
        ));
    }
    lines
}
