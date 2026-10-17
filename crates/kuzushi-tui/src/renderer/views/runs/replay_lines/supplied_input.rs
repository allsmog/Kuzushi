use super::*;
use crate::ui_view_models::ReplayModel;
use kuzushi_core::run_artifacts::RunResultDocument;

pub(super) fn lines(app: &ShellApp, area: Rect, model: &ReplayModel) -> Vec<Line<'static>> {
    let title = if crate::ui_view_models::replay_switch_owns_input(app) {
        "REPLAY · Inputs · Tab receipt"
    } else {
        "REPLAY · Inputs"
    };
    let mut lines = vec![divider(title, area.width)];
    append_selected_document(&mut lines, model, area.width);
    lines.push(blank());
    lines.push(muted(
        "Reading this historical input starts no request and changes no active context.",
    ));
    lines.push(muted(
        "Safe terminal display escapes controls, redacts secrets and wraps long lines.",
    ));
    lines
}

fn append_selected_document(lines: &mut Vec<Line<'static>>, model: &ReplayModel, width: u16) {
    if !crate::ui_view_models::replay_summary_available(model) {
        lines.push(styled("This receipt needs attention. Return to the full receipt before inspecting supplied input.", theme::warn()));
        return;
    }
    match &model.document {
        Some(Ok(document)) => append_selected_input(lines, document, width),
        Some(Err(error)) => lines.push(styled(&format!("Supplied input unavailable: {error}"), theme::warn())),
        None => lines.push(muted("Supplied input is loading or unavailable. Return to the receipt to inspect its saved artifacts.")),
    }
}

fn append_selected_input(lines: &mut Vec<Line<'static>>, document: &RunResultDocument, width: u16) {
    if document.supplied_input.is_none() {
        lines.push(muted("No supplied-input document is recorded for this result. Inspect its saved artifacts in the receipt."));
        return;
    }
    append_document(lines, document, width);
}

pub(super) fn append_document(
    lines: &mut Vec<Line<'static>>,
    document: &RunResultDocument,
    width: u16,
) {
    let Some(input) = &document.supplied_input else {
        return;
    };
    lines.push(divider("SUPPLIED INPUT", width));
    match input {
        Ok(rows) => lines.extend(
            rows.iter()
                .map(|row| styled(row.as_str(), theme::primary())),
        ),
        Err(error) => lines.push(styled(
            &format!(
                "Supplied input unavailable: {error}. Inspect the saved artifact in the receipt."
            ),
            theme::warn(),
        )),
    }
}
