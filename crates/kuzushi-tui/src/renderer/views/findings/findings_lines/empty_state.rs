use super::*;
use crate::ui_view_models::FindingsModel;

pub(super) fn append_empty_findings(
    model: &FindingsModel,
    area: Rect,
    lines: &mut Vec<Line<'static>>,
) {
    lines.push(divider("FINDINGS · empty", area.width));
    lines.extend(empty_state_panel(
        "no findings yet",
        &[
            "kuzushi keeps the ledger in .kuzushi/v2/findings.sqlite3.",
            "nothing has been promoted on this workspace.",
        ],
        &[Some(("scan", model.empty.hint)), model.empty.context_cta]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>(),
    ));
}
