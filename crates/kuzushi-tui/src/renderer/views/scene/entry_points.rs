use crate::theme;
use crate::ui_view_models::{EntryPointBreakdown, EntryPointItem};
use ratatui::prelude::{Line, Span};

mod browser;
pub(crate) use browser::EntryPointBrowser;

pub(super) fn entry_point_lines(width: usize, model: &EntryPointBreakdown) -> Vec<Line<'static>> {
    if let Some(hint) = &model.empty_hint {
        return crate::renderer::empty_state_panel(
            "no entry points",
            &[hint],
            &[("threat-model:build", "discover ingress surfaces")],
        );
    }
    let mut lines = crate::renderer::shared::text::wrap_text(&breakdown_label(model), width)
        .into_iter()
        .map(|text| Line::styled(text, theme::accent()))
        .collect::<Vec<_>>();
    for zone in &model.zones {
        lines.push(Line::from(String::new()));
        lines.push(Line::styled(
            fit(
                &format!(
                    "{} · {}",
                    zone.name.replace('_', " ").to_uppercase(),
                    zone.count
                ),
                width,
            ),
            theme::label(),
        ));
        for (index, entry) in model
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.trust_zone == zone.name)
        {
            append_entry(&mut lines, width, index, entry);
        }
    }
    lines
}

fn breakdown_label(model: &EntryPointBreakdown) -> String {
    format!(
        "ENTRY POINTS · {} found · {} kinds · {} zones · {}/{} DFD links",
        model.entries.len(),
        model.kinds.len(),
        model.zones.len(),
        model.linked_target_count,
        model.target_count,
    )
}

fn responsive_summary(width: usize, model: &EntryPointBreakdown) -> String {
    let full = breakdown_label(model);
    let medium = format!(
        "{} entries · {} kinds · {} zones · DFD {}/{}",
        model.entries.len(),
        model.kinds.len(),
        model.zones.len(),
        model.linked_target_count,
        model.target_count
    );
    let narrow = format!(
        "{} entries · DFD {}/{}",
        model.entries.len(),
        model.linked_target_count,
        model.target_count
    );
    let value = if full.chars().count() <= width {
        full
    } else if medium.chars().count() <= width {
        medium
    } else {
        narrow
    };
    fit(&value, width)
}

fn append_entry(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    index: usize,
    entry: &EntryPointItem,
) {
    lines.push(Line::from(String::new()));
    lines.push(Line::styled(
        fit(
            &format!(
                "{}. [{}] {}",
                index + 1,
                entry.kind.replace('_', " "),
                entry.name
            ),
            width,
        ),
        theme::heading(),
    ));
    lines.extend(entry_detail_lines(width, entry).into_iter().skip(1));
}

fn entry_detail_lines(width: usize, entry: &EntryPointItem) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(fit(&entry.name, width), theme::heading())];
    append_field(&mut lines, width, "kind", &entry.kind.replace('_', " "));
    append_field(
        &mut lines,
        width,
        "zone",
        &entry.trust_zone.replace('_', " "),
    );
    append_optional_field(
        &mut lines,
        width,
        "ingress",
        &entry.ingress,
        "not specified",
    );
    append_optional_field(&mut lines, width, "summary", &entry.description, "");
    append_optional_field(&mut lines, width, "source", &entry.source, "not recorded");
    append_targets(&mut lines, width, entry);
    append_optional_field(&mut lines, width, "evidence", &entry.evidence, "");
    append_field(&mut lines, width, "id", &entry.id);
    lines
}

fn append_targets(lines: &mut Vec<Line<'static>>, width: usize, entry: &EntryPointItem) {
    let mut targets = entry
        .targets
        .iter()
        .map(|target| target.label.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    if entry.unresolved_target_count > 0 {
        let separator = if targets.is_empty() { "" } else { "; " };
        targets.push_str(&format!(
            "{separator}+{} unresolved",
            entry.unresolved_target_count
        ));
    }
    append_optional_field(lines, width, "targets", &targets, "");
}

fn append_optional_field(
    lines: &mut Vec<Line<'static>>,
    width: usize,
    key: &str,
    value: &str,
    omitted_value: &str,
) {
    if value.is_empty() || value == omitted_value {
        return;
    }
    append_field(lines, width, key, value);
}

fn append_field(lines: &mut Vec<Line<'static>>, width: usize, key: &str, value: &str) {
    let key_width = width.saturating_sub(1).min(11);
    let value_width = width.saturating_sub(key_width).max(1);
    for (index, chunk) in crate::renderer::shared::text::wrap_text(value, value_width)
        .into_iter()
        .enumerate()
    {
        let label = if index == 0 {
            format!("{key:<key_width$}")
        } else {
            " ".repeat(key_width)
        };
        lines.push(Line::from(vec![
            Span::styled(label, theme::muted()),
            Span::styled(chunk, theme::primary()),
        ]));
    }
}

fn fit(value: &str, width: usize) -> String {
    crate::renderer::shared::text::fit(value, width)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui_view_models::{EntryPointGroup, EntryPointTarget};

    #[test]
    fn entry_point_plain_breakdown_stays_within_narrow_width() {
        let model = sample_model();

        let lines = entry_point_lines(32, &model);
        let text = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

        assert!(text.contains("1/1 DFD"), "{text}");
        assert!(text.contains("INTERNET"), "{text}");
        assert!(text.contains("http route"), "{text}");
        assert!(text.contains("Share API"), "{text}");
        assert!(lines.iter().all(|line| line.width() <= 32));
    }

    fn sample_model() -> EntryPointBreakdown {
        EntryPointBreakdown {
            entries: vec![EntryPointItem {
                id: "EP-1".into(),
                name: "POST /admin".into(),
                kind: "http_route".into(),
                trust_zone: "internet".into(),
                description: "Administrative route".into(),
                ingress: "POST /admin".into(),
                source: "src/routes.rs:42".into(),
                evidence: "route registration with authorization middleware".into(),
                targets: vec![EntryPointTarget {
                    id: "N1".into(),
                    label: "N1 Share API · cloud_function".into(),
                }],
                unresolved_target_count: 0,
            }],
            kinds: vec![EntryPointGroup {
                name: "http_route".into(),
                count: 1,
            }],
            zones: vec![EntryPointGroup {
                name: "internet".into(),
                count: 1,
            }],
            linked_target_count: 1,
            target_count: 1,
            empty_hint: None,
        }
    }

    fn line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }
}
