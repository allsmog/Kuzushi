use super::*;
use crate::ui_view_models::{findings_db_relative_path, FindingsModel};

pub(super) fn append_empty_findings(
    model: &FindingsModel,
    area: Rect,
    lines: &mut Vec<Line<'static>>,
) {
    lines.push(divider("FINDINGS · empty", area.width));
    let ledger_detail = format!(
        "kuzushi keeps the ledger in {}.",
        findings_db_relative_path()
    );
    lines.extend(empty_state_panel(
        "no findings yet",
        &[
            ledger_detail.as_str(),
            "nothing has been promoted on this workspace.",
        ],
        &[Some(("scan", model.empty.hint)), model.empty.context_cta]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>(),
    ));
}
