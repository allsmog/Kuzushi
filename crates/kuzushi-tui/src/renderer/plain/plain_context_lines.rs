use super::*;
use crate::ui_view_models::{
    plain_context_model, plain_workspace_projection, project_model, strategy_queue_model,
    PlainContextModel, PlainWorkspaceProjection, ProjectModel, StrategyQueueModel,
    StrategyQueueRow,
};

pub(crate) fn plain_context_lines(app: &ShellApp, width: usize) -> Vec<String> {
    if let Some(snapshot) = app.context_screen_snapshot() {
        return plain_context_snapshot_lines(snapshot.clone(), width);
    }

    let mut lines = plain_context_strip(app, width);
    let model = plain_context_model(app);

    push_plain_context_summary(&mut lines, &model, width);
    lines
}

fn plain_context_snapshot_lines(view: ContextScreenSnapshot, width: usize) -> Vec<String> {
    let mut lines = vec![
        format!(
            " KUZUSHI  target {}  ctx ✓ {}  model {}  module {}  cost {}",
            view.status.target,
            view.status.ctx,
            view.status.model,
            view.status.module,
            view.status.cost
        ),
        "─".repeat(width),
        String::new(),
    ];
    lines.extend(view.body_rows);
    lines.push(String::new());
    lines.push("─".repeat(width));
    lines.push(context_footer_stage_line(width, &view.footer));
    lines.push(context_footer_keybind_line(&view.footer));
    lines.push(match view.footer.prompt_module {
        Some(module) => format!(" kuzushi ({module})>"),
        None => " kuzushi>".to_string(),
    });
    lines
}

fn context_footer_stage_line(width: usize, footer: &ContextScreenFooter) -> String {
    let left = format!(" stage {} · routing direct", footer.stage);
    let right = format!("Ctrl+C quit · findings {}", footer.findings);
    let gap = width
        .saturating_sub(left.chars().count() + right.chars().count())
        .saturating_sub(1);
    format!("{left}{}{right}", " ".repeat(gap))
}

fn context_footer_keybind_line(footer: &ContextScreenFooter) -> String {
    let body = footer
        .keybinds
        .iter()
        .map(|(key, label)| format!("{key} {label}"))
        .collect::<Vec<_>>()
        .join("   ");
    format!(" {body}")
}

fn push_plain_context_summary(lines: &mut Vec<String>, model: &PlainContextModel, width: usize) {
    lines.push(String::new());
    lines.push(plain_section_divider(model.title, width));
    lines.extend(model.summary_rows.iter().cloned());
    lines.extend(model.body_rows.iter().cloned());
    lines.push(String::new());
    lines.push(model.next_hint.to_string());
}

pub(crate) fn plain_workspace_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let model = plain_workspace_projection(app);

    push_plain_workspace_summary(&mut lines, &model, width);
    lines
}

pub(crate) fn plain_project_model_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let model = project_model(app);

    push_plain_project_model_summary(&mut lines, &model, width);
    lines
}

pub(crate) fn plain_strategy_queue_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let model = strategy_queue_model(app);

    push_plain_strategy_queue_summary(&mut lines, &model, width);
    lines
}

fn push_plain_project_model_summary(lines: &mut Vec<String>, model: &ProjectModel, width: usize) {
    lines.push(String::new());
    lines.push(plain_section_divider("PROJECT MODEL", width));
    lines.push(format!("scope: {}", model.scope_label));
    lines.push(format!("revision: {}", model.revision_label));
    lines.extend(model.rows.iter().map(|row| {
        format!(
            "{} {} [{}:{}] {}",
            row.origin.glyph(),
            row.section,
            row.origin.label(),
            row.state,
            row.summary
        )
    }));
    lines.push(String::new());
    lines.push(model.next_hint.to_string());
}

fn push_plain_strategy_queue_summary(
    lines: &mut Vec<String>,
    model: &StrategyQueueModel,
    width: usize,
) {
    lines.push(String::new());
    lines.push(plain_section_divider(model.title, width));
    for row in &model.detail_rows {
        lines.push(format!("{}: {}", row.cells[0], row.cells[1]));
    }
    lines.push(model.summary.clone());
    if model.rows.is_empty() {
        push_plain_strategy_queue_empty(lines, model);
        return;
    }
    push_plain_strategy_queue_rows(lines, model);
    lines.push(format!("commands: {}", model.commands.join(" · ")));
}

fn push_plain_strategy_queue_empty(lines: &mut Vec<String>, model: &StrategyQueueModel) {
    lines.push(String::new());
    lines.push(model.empty_state.title.to_string());
    lines.extend(
        model
            .empty_state
            .explanations
            .iter()
            .map(|line| line.to_string()),
    );
    lines.push(format!(
        "commands: {}",
        model.empty_state.commands.join(" · ")
    ));
}

fn push_plain_strategy_queue_rows(lines: &mut Vec<String>, model: &StrategyQueueModel) {
    for row in &model.rows {
        lines.extend(strategy_queue_plain_rows(row));
    }
}

fn strategy_queue_plain_rows(row: &StrategyQueueRow) -> Vec<String> {
    vec![
        format!(
            "{} {} {} {} yield:{} rounds:{} est:{} actual:{} outcome:{} preflight:{} runtime:{} risk:{}",
            row.cells[0],
            row.cells[1],
            row.cells[2],
            row.cells[3],
            row.cells[4],
            row.cells[5],
            row.cells[6],
            row.cells[7],
            row.cells[8],
            row.cells[9],
            row.cells[10],
            row.cells[11]
        ),
        format!("  lineage: {}", row.lineage),
        format!("  why: {} · source {}", row.rationale, row.source_run),
    ]
}

fn push_plain_workspace_summary(
    lines: &mut Vec<String>,
    model: &PlainWorkspaceProjection,
    width: usize,
) {
    lines.push(String::new());
    lines.push(plain_section_divider(model.title, width));
    lines.extend(model.summary_rows.iter().cloned());
    lines.extend(model.empty_rows.iter().cloned());
    lines.push(String::new());
    lines.push(model.next_hint.to_string());
}
