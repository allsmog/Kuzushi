use super::*;
use crate::ui_view_models::{threat_model_picker, ThreatModelHeadRow};

pub(super) fn append_model_lines(app: &ShellApp, area: Rect, lines: &mut Vec<Line<'static>>) {
    let picker = threat_model_picker(app);
    lines.push(section_header_line("THREAT MODEL LINEAGES", area.width));
    lines.push(detail("status", &picker.status));
    if picker.rows.is_empty() {
        lines.push(empty_hint_line(&picker.status));
        append_actions(lines, area.width);
        return;
    }
    for (index, row) in picker.rows.iter().enumerate() {
        lines.extend(model_lines(index, row, area.width));
    }
    append_actions(lines, area.width);
}

fn model_lines(index: usize, row: &ThreatModelHeadRow, width: u16) -> Vec<Line<'static>> {
    let marker = if row.active_lineage { "▸" } else { " " };
    let head = format!(
        "{marker} {}. {} · {} · {}",
        index + 1,
        row.label,
        row.methodology,
        row.verification
    );
    let active = active_revision_label(row);
    vec![
        Line::styled(fit(&head, width as usize), model_style(row)),
        detail("model", row.model_id.as_str()),
        detail("head", row.revision_id.as_str()),
        detail("scope", &format!("{} · {}", row.scope, row.scope_status)),
        detail("active", &active),
    ]
}

fn active_revision_label(row: &ThreatModelHeadRow) -> String {
    if row.active_head {
        return "head".to_string();
    }
    row.active_revision_id
        .as_ref()
        .map(|revision| format!("historical {revision}"))
        .unwrap_or_else(|| "no".to_string())
}

fn model_style(row: &ThreatModelHeadRow) -> Style {
    if row.active_lineage {
        theme::selection()
    } else {
        theme::primary()
    }
}

fn append_actions(lines: &mut Vec<Line<'static>>, width: u16) {
    lines.push(blank());
    lines.push(section_header_line("ACTIONS", width));
    lines.push(detail("activate", "m next model · M previous model"));
    lines.push(detail(
        "activate",
        "threats activate <model-id>[@<revision-id>]",
    ));
    lines.push(detail("history", "threats revisions <model-id>"));
    lines.push(detail("restore", "threats restore <revision-id>"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::capabilities::threat_model::{ThreatModelId, ThreatModelRevisionId};

    #[test]
    fn active_historical_revision_is_disclosed_instead_of_called_the_head() {
        let row = ThreatModelHeadRow {
            model_id: ThreatModelId::parse("tm_11111111111111111111111111111111").unwrap(),
            revision_id: ThreatModelRevisionId::parse("tmr_22222222222222222222222222222222")
                .unwrap(),
            sha256: "sha256:head".to_string(),
            label: "root".to_string(),
            methodology: "stride".to_string(),
            scope: ".".to_string(),
            scope_status: "current".to_string(),
            verification: "verified".to_string(),
            active_lineage: true,
            active_head: false,
            active_revision_id: Some(
                ThreatModelRevisionId::parse("tmr_11111111111111111111111111111111").unwrap(),
            ),
            active_sha256: Some("sha256:old".to_string()),
            active_verification: Some("verified".to_string()),
        };

        assert!(active_revision_label(&row).starts_with("historical tmr_"));
    }
}
