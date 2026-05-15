use super::*;
use crate::ui_view_models::{
    plain_context_model, plain_workspace_model, PlainContextModel, PlainWorkspaceModel,
};

pub(crate) fn plain_context_lines(app: &ShellApp, width: usize) -> Vec<String> {
    let mut lines = plain_context_strip(app, width);
    let model = plain_context_model(app);

    push_plain_context_summary(&mut lines, &model, width);
    lines
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
    let model = plain_workspace_model(app);

    push_plain_workspace_summary(&mut lines, &model, width);
    lines
}

fn push_plain_workspace_summary(
    lines: &mut Vec<String>,
    model: &PlainWorkspaceModel,
    width: usize,
) {
    lines.push(String::new());
    lines.push(plain_section_divider(model.title, width));
    lines.extend(model.summary_rows.iter().cloned());
    lines.extend(model.empty_rows.iter().cloned());
    lines.push(String::new());
    lines.push(model.next_hint.to_string());
}
