use super::*;
use crate::ui_view_models::{catalog_model, CatalogActionModule, CatalogModel, CatalogModuleGroup};

mod collapsed_state;
mod empty_state;

pub(crate) fn catalog_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    let model = catalog_model(app);
    append_modules_header(&mut lines, model.module_count);
    if model.module_count == 0 {
        empty_state::append_empty_catalog(area, &mut lines);
        return lines;
    }

    if collapsed_catalog_active(app, area.width) {
        collapsed_state::append_collapsed_catalog(&model, area, &mut lines);
        return lines;
    }

    append_default_next_action(&mut lines, model.default_action.as_ref(), area.width);
    append_module_groups(&mut lines, &model, area.width);
    lines
}

fn append_modules_header(lines: &mut Vec<Line<'static>>, module_count: usize) {
    lines.push(Line::from(vec![
        Span::styled("KUZUSHI · MODULES", theme::heading()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(format!("{module_count} modules"), theme::muted()),
    ]));
    lines.push(blank());
}

fn append_default_next_action(
    lines: &mut Vec<Line<'static>>,
    module: Option<&CatalogActionModule>,
    width: u16,
) {
    if let Some(module) = module {
        let prefix = format!("Run {} against the active target — ", module.id);
        let budget = next_action_description_budget(width, &prefix);
        let hint = format!("{prefix}{}", short_sentence(&module.description, budget));
        lines.push(next_action_line(&hint, width as usize));
        lines.push(blank());
    }
}

fn next_action_description_budget(width: u16, prefix: &str) -> usize {
    (width as usize)
        .saturating_sub(prefix.chars().count() + 8)
        .max(40)
}

fn append_module_groups(lines: &mut Vec<Line<'static>>, model: &CatalogModel, width: u16) {
    for group in &model.groups {
        append_module_group(lines, group, width);
        lines.push(blank());
    }
}

fn append_module_group(lines: &mut Vec<Line<'static>>, group: &CatalogModuleGroup, width: u16) {
    let (_, blurb) = module_category_blurb(group.category);
    let widths = module_table_widths(width);
    lines.push(category_divider(group.category, blurb, width));
    for module in &group.rows {
        lines.push(catalog_module_row(
            &module.id,
            &module.description,
            module.focused,
            &widths,
        ));
    }
}

fn compact_catalog_width(width: u16) -> bool {
    width < 96
}

fn collapsed_catalog_active(app: &ShellApp, width: u16) -> bool {
    !app.catalog_expanded && compact_catalog_width(width)
}
