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
    append_modules_header(&mut lines, model.module_count);
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

fn append_modules_header(lines: &mut Vec<Line<'static>>, module_count: usize) {
    // View title only — the cockpit strip directly above already carries the
    // KUZUSHI brand, so repeating it here was pure noise.
    lines.push(Line::from(vec![
        Span::styled("MODULES", theme::heading()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(format!("{module_count} modules"), theme::muted()),
    ]));
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
    let (_, blurb) = module_category_blurb(group.category);
    let widths = module_table_widths(width);
    lines.push(category_divider(group.category, blurb, width));
    for module in &group.rows {
        lines.push(catalog_module_row(
            &module.cells[0],
            &module.cells[1],
            module.focused,
            &widths,
        ));
    }
}
