use super::*;
use kuzushi_core::modules::BuiltinModule;
use std::collections::BTreeMap;

mod collapsed_state;
mod empty_state;

const MODULE_CATEGORY_ORDER: &[&str] = &["OFFENSE", "INTEL", "GOVERNANCE", "DEFENSE"];

pub(crate) fn catalog_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    let modules = app.registry.modules().collect::<Vec<_>>();
    append_modules_header(&mut lines, modules.len());
    if modules.is_empty() {
        empty_state::append_empty_catalog(area, &mut lines);
        return lines;
    }

    if collapsed_catalog_active(app, area.width) {
        collapsed_state::append_collapsed_catalog(app, area, &mut lines);
        return lines;
    }

    append_default_next_action(&mut lines, &modules, area.width);
    let grouped = grouped_modules(modules);
    append_module_groups(&mut lines, app, &grouped, area.width);
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
    modules: &[&BuiltinModule],
    width: u16,
) {
    if let Some(module) = preferred_default_module(modules) {
        let prefix = format!("Run {} against the active target — ", module.metadata().id);
        let budget = next_action_description_budget(width, &prefix);
        let hint = format!(
            "{prefix}{}",
            short_sentence(&module.metadata().description, budget)
        );
        lines.push(next_action_line(&hint, width as usize));
        lines.push(blank());
    }
}

fn preferred_default_module<'a>(modules: &'a [&'a BuiltinModule]) -> Option<&'a BuiltinModule> {
    modules
        .iter()
        .copied()
        .find(|module| module.metadata().id == "sast")
        .or_else(|| {
            modules
                .iter()
                .copied()
                .find(|module| module.metadata().id == "semgrep")
        })
        .or_else(|| modules.first().copied())
}

fn next_action_description_budget(width: u16, prefix: &str) -> usize {
    (width as usize)
        .saturating_sub(prefix.chars().count() + 8)
        .max(40)
}

fn grouped_modules(modules: Vec<&BuiltinModule>) -> BTreeMap<&'static str, Vec<&BuiltinModule>> {
    let mut grouped: BTreeMap<&'static str, Vec<_>> = BTreeMap::new();
    for module in modules {
        grouped
            .entry(catalog_module_category(
                &module.metadata().id,
                module.metadata().kind,
            ))
            .or_default()
            .push(module);
    }
    grouped
}

fn append_module_groups(
    lines: &mut Vec<Line<'static>>,
    app: &ShellApp,
    grouped: &BTreeMap<&'static str, Vec<&BuiltinModule>>,
    width: u16,
) {
    let cursor_id = selected_cursor_id(app, grouped);
    let focused_id = app.focused_module.as_deref();
    for category in MODULE_CATEGORY_ORDER {
        let Some(rows) = grouped.get(category) else {
            continue;
        };
        append_module_group(
            lines,
            rows,
            category,
            focused_id,
            cursor_id.as_deref(),
            width,
        );
        lines.push(blank());
    }
}

fn selected_cursor_id(
    app: &ShellApp,
    grouped: &BTreeMap<&'static str, Vec<&BuiltinModule>>,
) -> Option<String> {
    let visible_ids = ordered_visible_module_ids(grouped);
    visible_ids
        .get(app.catalog_cursor.min(visible_ids.len().saturating_sub(1)))
        .cloned()
}

fn ordered_visible_module_ids(
    grouped: &BTreeMap<&'static str, Vec<&BuiltinModule>>,
) -> Vec<String> {
    let mut ids = Vec::new();
    for category in MODULE_CATEGORY_ORDER {
        if let Some(rows) = grouped.get(category) {
            ids.extend(rows.iter().map(|module| module.metadata().id.clone()));
        }
    }
    ids
}

fn append_module_group(
    lines: &mut Vec<Line<'static>>,
    rows: &[&BuiltinModule],
    category: &str,
    focused_id: Option<&str>,
    cursor_id: Option<&str>,
    width: u16,
) {
    let (_, blurb) = module_category_blurb(category);
    let widths = module_table_widths(width);
    lines.push(category_divider(category, blurb, width));
    for module in rows {
        let id = module.metadata().id.as_str();
        lines.push(catalog_module_row(
            &module.metadata().id,
            &module.metadata().description,
            focused_id == Some(id) || cursor_id == Some(id),
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
