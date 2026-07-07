use super::*;
use crate::ui_view_models::{SourceTreeComponentTier, SourceTreeModel, SourceTreeRow};
use ratatui::prelude::{Line, Span};

pub(in crate::renderer::views::workbench) fn source_title(model: &SourceTreeModel) -> String {
    format!("SOURCE · {} files", model.file_count)
}

pub(in crate::renderer::views::workbench) fn source_pane_lines(
    model: &SourceTreeModel,
    width: usize,
) -> Vec<Line<'static>> {
    if let Some(hint) = model.empty_hint {
        return pane_empty_state(
            "no source tree",
            &[hint],
            &[("scan", "populate finding-bearing files")],
        );
    }
    model
        .rows
        .iter()
        .map(|row| source_row_line(row, width))
        .collect()
}

fn source_row_line(row: &SourceTreeRow, width: usize) -> Line<'static> {
    let indent = " ".repeat(row.depth * 2);
    let name = source_display_name(row);
    let name_style = source_name_style(row);
    let count = source_count_label(row);
    let component = source_component_label(row);
    let Some(name) = fitted_source_name(&indent, component.as_deref(), &name, &count, width) else {
        return Line::from(Span::styled(
            fit(
                &format!("{indent}{}{name}{count}", component.unwrap_or_default()),
                width,
            ),
            name_style,
        ));
    };
    source_row_spans(row, indent, name, name_style, count)
}

fn source_display_name(row: &SourceTreeRow) -> String {
    if row.is_dir {
        format!("{}/", row.name)
    } else {
        row.name.clone()
    }
}

fn source_name_style(row: &SourceTreeRow) -> ratatui::style::Style {
    if row.is_dir {
        theme::label()
    } else {
        theme::primary()
    }
}

fn source_row_spans(
    row: &SourceTreeRow,
    indent: String,
    name: String,
    name_style: ratatui::style::Style,
    count: String,
) -> Line<'static> {
    let mut spans = vec![Span::raw(indent)];
    if let Some(component) = source_component_label(row) {
        spans.push(Span::styled(component, source_component_style(row)));
    }
    spans.push(Span::styled(name, name_style));
    if !count.is_empty() {
        spans.push(Span::styled(count, theme::muted()));
    }
    Line::from(spans)
}

fn source_count_label(row: &SourceTreeRow) -> String {
    if row.finding_count > 0 {
        format!("  · {}", row.finding_count)
    } else {
        String::new()
    }
}

fn source_component_label(row: &SourceTreeRow) -> Option<String> {
    row.component
        .as_ref()
        .map(|component| format!("◆ {} ", component.label))
}

fn source_component_style(row: &SourceTreeRow) -> ratatui::style::Style {
    match row.component.as_ref().map(|component| component.tier) {
        Some(SourceTreeComponentTier::High) => theme::warn(),
        Some(SourceTreeComponentTier::Medium) => theme::accent(),
        _ => theme::muted(),
    }
}

fn fitted_source_name(
    indent: &str,
    component: Option<&str>,
    name: &str,
    count: &str,
    width: usize,
) -> Option<String> {
    let fixed_width =
        display_width(indent) + display_width(component.unwrap_or_default()) + display_width(count);
    let name_width = width.checked_sub(fixed_width)?;
    (name_width > 0).then(|| fit(name, name_width))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_text(line: Line<'static>) -> String {
        line.spans
            .into_iter()
            .map(|span| span.content.into_owned())
            .collect::<String>()
    }

    #[test]
    fn source_rows_fit_the_pane_width_without_wrapping() {
        let model = SourceTreeModel {
            rows: vec![
                SourceTreeRow {
                    depth: 3,
                    name: "applies_size_binary_and_severity_filters.rs".to_string(),
                    is_dir: false,
                    finding_count: 18,
                    component: None,
                },
                SourceTreeRow {
                    depth: 1,
                    name: "benchmark-regression.yml".to_string(),
                    is_dir: false,
                    finding_count: 1,
                    component: None,
                },
            ],
            file_count: 2,
            finding_count: 19,
            empty_hint: None,
        };

        for text in source_pane_lines(&model, 24).into_iter().map(line_text) {
            assert!(text.chars().count() <= 24, "{text}");
            assert!(text.contains('·'), "{text}");
        }
    }
}
