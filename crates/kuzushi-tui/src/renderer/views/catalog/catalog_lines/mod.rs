use super::*;
use crate::ui_view_models::{
    catalog_default_action_hint, catalog_model, catalog_uses_collapsed_layout, CatalogModel,
    CatalogModuleGroup,
};

mod collapsed_state;
mod empty_state;

pub(crate) fn catalog_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    let model = catalog_model(app);
    append_capabilities_header(&mut lines, &model);
    if model.module_count == 0 {
        empty_state::append_empty_catalog(area, &mut lines);
        return lines;
    }

    if catalog_uses_collapsed_layout(&model, area.width) {
        collapsed_state::append_collapsed_catalog(&model, area, &mut lines);
        return lines;
    }

    append_default_next_action(&mut lines, &model, area.width);
    append_module_groups(&mut lines, &model, area.width);
    lines
}

fn append_capabilities_header(lines: &mut Vec<Line<'static>>, model: &CatalogModel) {
    lines.push(Line::from(vec![
        Span::styled("CAPABILITIES", theme::heading()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(model.phase_label, theme::accent()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(
            format!(
                "{} actions{}",
                model.module_count,
                if model.expanded { " · expert" } else { "" }
            ),
            theme::muted(),
        ),
    ]));
    if let Some(warning) = model.collapsed.target_warning {
        lines.push(styled(warning, theme::warn()));
    } else {
        lines.push(muted(
            "Phase-native actions first. Press e for engines and installed integrations.",
        ));
    }
    lines.push(blank());
}

fn append_default_next_action(lines: &mut Vec<Line<'static>>, model: &CatalogModel, width: u16) {
    if let Some(module) = model.default_action.as_ref() {
        let hint = catalog_default_action_hint(module, width);
        lines.push(next_action_line(&hint, width as usize));
        lines.push(blank());
    }
}

fn append_module_groups(lines: &mut Vec<Line<'static>>, model: &CatalogModel, width: u16) {
    for group in &model.groups {
        append_module_group(lines, group, width);
        lines.push(blank());
    }
}

fn append_module_group(lines: &mut Vec<Line<'static>>, group: &CatalogModuleGroup, width: u16) {
    let (label, blurb) = module_category_blurb(group.category);
    let widths = module_table_widths(width.saturating_sub(2));
    lines.push(category_divider(label, blurb, width));
    for module in &group.rows {
        lines.push(catalog_module_row(
            &module.cells[0],
            &module.cells[1],
            module.focused,
            &widths,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;

    #[test]
    fn targetless_catalog_shows_target_and_demo_recovery() {
        let app = ShellApp::new(V2Config::default(), None);
        let text = catalog_lines(&app, Rect::new(0, 0, 120, 40))
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();

        assert!(text.contains("target <path>"), "{text}");
        assert!(text.contains("demo"), "{text}");
    }

    #[test]
    fn module_rows_include_their_gutter_in_narrow_width_budgets() {
        for width in [40, 60, 80] {
            let widths = module_table_widths(width - 2);
            for focused in [false, true] {
                let line = catalog_module_row(
                    "日本語-module-id",
                    "A long module description that must shrink",
                    focused,
                    &widths,
                );
                let rendered_width = line
                    .spans
                    .iter()
                    .map(|span| display_width(span.content.as_ref()))
                    .sum::<usize>();

                assert!(
                    rendered_width <= width as usize,
                    "{rendered_width} > {width}"
                );
            }
        }
    }
}
