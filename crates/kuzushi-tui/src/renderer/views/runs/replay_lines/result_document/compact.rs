use super::*;

pub(super) fn append_outcome(lines: &mut Vec<Line<'static>>, model: &ReplayModel) {
    let Some((_, terminal)) = model.presentation.as_ref().and_then(replay_terminal) else {
        return;
    };
    let full = kuzushi_core::run_lifecycle::cost_label(terminal.cost);
    let cost = full.strip_suffix(" (metering incomplete)").unwrap_or(&full);
    lines.push(styled(
        &format!("Outcome · {} · {cost}", terminal.status.label()),
        theme::primary(),
    ));
}

pub(super) fn append_output(lines: &mut Vec<Line<'static>>, document: &RunResultDocument) {
    lines.extend(
        document
            .summary
            .iter()
            .map(|row| styled(row.as_str(), theme::accent())),
    );
    let offset = summary_prefix(document);
    lines.extend(
        document.output[offset..]
            .iter()
            .map(|row| styled(row.as_str(), theme::primary())),
    );
    append_messages(lines, "Warning", &document.warnings, document);
    append_messages(lines, "Error", &document.errors, document);
}

fn summary_prefix(document: &RunResultDocument) -> usize {
    if document.output.starts_with(&document.summary) {
        document.summary.len()
    } else {
        0
    }
}
