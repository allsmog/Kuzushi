use super::*;
use crate::ui_view_models::ReplayModel;
use kuzushi_core::run_lifecycle::RunPresentationV1;

pub(super) fn lines(
    app: &ShellApp,
    area: Rect,
    model: &ReplayModel,
    summary: &RunPresentationV1,
) -> Vec<Line<'static>> {
    let heading = match (
        model.issue.is_some() && !crate::ui_view_models::replay_document_available(model),
        crate::ui_view_models::replay_switch_owns_input(app),
        crate::ui_view_models::replay_has_inputs(app),
    ) {
        (true, true, true) => "REPLAY · Summary · Tab inputs",
        (true, true, false) => "REPLAY · Summary · Tab receipt",
        (true, false, _) => "REPLAY · Summary",
        (false, true, true) => "REPLAY · Result · Tab inputs",
        (false, true, false) => "REPLAY · Result · Tab receipt",
        (false, false, _) => "REPLAY · Result",
    };
    let mut lines = vec![divider(heading, area.width)];
    append_summary_outcome(&mut lines, model);
    lines.extend(context_strip(app, area));
    lines.push(blank());
    append_presentation_summary(&mut lines, summary, None, area.width);
    append_document_state(&mut lines, model);
    lines.push(blank());
    lines.push(muted("Full receipt includes work, artifacts and timeline."));
    lines
}

pub(super) fn append_summary_outcome(lines: &mut Vec<Line<'static>>, model: &ReplayModel) {
    let Some(terminal) = append_summary_status(lines, model) else {
        return;
    };
    if let Some(tool) = model.issue.as_ref().and_then(|issue| issue.tool.as_ref()) {
        lines.push(muted(&format!("Reported by {tool}.")));
    }
    lines.push(muted(&format!(
        "NEXT · {}",
        terminal.continuation.operator_label()
    )));
}

pub(super) fn append_summary_status<'a>(
    lines: &mut Vec<Line<'static>>,
    model: &'a ReplayModel,
) -> Option<&'a kuzushi_core::run_lifecycle::TerminalPresentationV1> {
    let terminal = append_outcome_status(lines, model)?;
    append_replay_issue(lines, model.issue.as_ref());
    Some(terminal)
}

pub(super) fn append_outcome_status<'a>(
    lines: &mut Vec<Line<'static>>,
    model: &'a ReplayModel,
) -> Option<&'a kuzushi_core::run_lifecycle::TerminalPresentationV1> {
    let (_, terminal) = model.presentation.as_ref().and_then(replay_terminal)?;
    lines.push(styled(
        &format!(
            "Outcome · {} · {}",
            terminal.status.label(),
            kuzushi_core::run_lifecycle::cost_label(terminal.cost)
        ),
        theme::primary(),
    ));
    Some(terminal)
}

fn append_document_state(lines: &mut Vec<Line<'static>>, model: &ReplayModel) {
    if !crate::ui_view_models::replay_document_available(model) {
        return;
    }
    let message = match &model.document {
        Some(Err(error)) => format!("Saved output unavailable: {error}. Preview retained. Reopen replay to retry this read; Tab inspects the receipt."),
        None => "Saved output loading; this is the bounded result preview.".into(),
        Some(Ok(_)) => return,
    };
    lines.push(styled(&message, theme::warn()));
}

#[cfg(test)]
mod tests;
