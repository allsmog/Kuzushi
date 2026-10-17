use super::*;
use crate::ui_view_models::ReplayModel;
use kuzushi_core::run_artifacts::RunResultDocument;
mod compact;

pub(super) fn lines(
    app: &ShellApp,
    area: Rect,
    model: &ReplayModel,
    document: &RunResultDocument,
) -> Vec<Line<'static>> {
    let owns_tabs = crate::ui_view_models::replay_switch_owns_input(app);
    let title = if owns_tabs && crate::ui_view_models::replay_has_inputs(app) {
        "REPLAY · Result · Tab inputs"
    } else if owns_tabs {
        "REPLAY · Result · Tab receipt"
    } else {
        "REPLAY · Result"
    };
    let mut lines = vec![divider(title, area.width)];
    append_document_outcome(&mut lines, model, document, area.width);
    if area.width <= 60 {
        compact::append_output(&mut lines, document);
    } else {
        append_output(&mut lines, document, area.width);
    }
    lines.push(blank());
    let controls = if owns_tabs && crate::ui_view_models::replay_has_inputs(app) {
        "Tab opens supplied inputs, then the full receipt."
    } else if owns_tabs {
        "Tab opens the full receipt, artifacts and timeline."
    } else {
        "Navigate mode enables result / receipt controls."
    };
    lines.push(muted(controls));
    lines.push(muted(
        "Safe terminal display escapes controls, redacts secrets and wraps long lines.",
    ));
    lines
}

fn append_document_outcome(
    lines: &mut Vec<Line<'static>>,
    model: &ReplayModel,
    document: &RunResultDocument,
    width: u16,
) {
    if width <= 60 {
        compact::append_outcome(lines, model);
    } else {
        failure_summary::append_outcome_status(lines, model);
    }
    let issue = model.issue.as_ref().filter(|issue| {
        !document_rows(document).any(|line| line.as_str().trim() == issue.message.trim())
    });
    append_replay_issue(lines, issue);
}

fn document_rows(
    document: &RunResultDocument,
) -> impl Iterator<Item = &kuzushi_core::run_lifecycle::SafeText> {
    document
        .summary
        .iter()
        .chain(&document.output)
        .chain(&document.warnings)
        .chain(&document.errors)
}

pub(super) fn append_output(
    lines: &mut Vec<Line<'static>>,
    document: &RunResultDocument,
    width: u16,
) {
    lines.extend(
        document
            .summary
            .iter()
            .map(|line| styled(line.as_str(), theme::accent())),
    );
    lines.push(divider("SAVED OUTPUT", width));
    lines.extend(
        document
            .output
            .iter()
            .map(|line| styled(line.as_str(), theme::primary())),
    );
    append_messages(lines, "Warning", &document.warnings, document);
    append_messages(lines, "Error", &document.errors, document);
}

fn append_messages(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    messages: &[kuzushi_core::run_lifecycle::SafeText],
    document: &RunResultDocument,
) {
    let displayed = document
        .output
        .iter()
        .map(|line| line.as_str().trim())
        .chain(document.summary.iter().map(|line| line.as_str().trim()))
        .collect::<std::collections::BTreeSet<_>>();
    lines.extend(
        messages
            .iter()
            .filter(|message| !displayed.contains(message.as_str().trim()))
            .map(|message| styled(&format!("{label}: {message}"), theme::warn())),
    );
}

#[cfg(test)]
mod tests;
