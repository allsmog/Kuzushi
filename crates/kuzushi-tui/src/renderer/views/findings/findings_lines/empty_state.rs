use super::*;

pub(super) fn append_empty_findings(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let hint = if app.context_view.exists {
        "scan runs configured scanners against the active target."
    } else {
        "scan dispatches the umbrella scanner once context-snapshot exists."
    };
    let context_cta = if app.context_view.exists {
        None
    } else {
        Some(("context build", "build the snapshot first if you have time"))
    };
    lines.push(divider("FINDINGS · empty", area.width));
    lines.extend(empty_state_panel(
        "no findings yet",
        &[
            "kuzushi keeps the ledger in .kuzushi/v2/findings.sqlite3.",
            "nothing has been promoted on this workspace.",
        ],
        &[Some(("scan", hint)), context_cta]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>(),
    ));
}
