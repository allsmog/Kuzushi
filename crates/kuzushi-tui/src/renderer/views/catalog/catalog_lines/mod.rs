use super::*;
use std::collections::BTreeMap;

mod collapsed_state;
mod empty_state;

pub(crate) fn catalog_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    let module_count = app.registry.modules().count();
    lines.push(Line::from(vec![
        Span::styled("KUZUSHI · CATALOG", theme::heading()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(format!("{module_count} modules"), theme::muted()),
    ]));
    lines.push(blank());

    let modules = app.registry.modules().collect::<Vec<_>>();
    if modules.is_empty() {
        empty_state::append_empty_catalog(area, &mut lines);
        return lines;
    }

    if collapsed_catalog_active(app, area.width) {
        collapsed_state::append_collapsed_catalog(app, area, &mut lines);
        return lines;
    }

    if let Some(module) = modules
        .iter()
        .find(|module| module.metadata().id == "sast")
        .or_else(|| {
            modules
                .iter()
                .find(|module| module.metadata().id == "semgrep")
        })
        .or_else(|| modules.first())
    {
        let prefix = format!("Run {} against the active target — ", module.metadata().id);
        let budget = (area.width as usize)
            .saturating_sub(prefix.chars().count() + 8)
            .max(40);
        let hint = format!(
            "{prefix}{}",
            short_sentence(&module.metadata().description, budget)
        );
        lines.push(next_action_line(&hint, area.width as usize));
        lines.push(blank());
    }

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

    let mut visible_ids: Vec<String> = Vec::new();
    for category in ["OFFENSE", "INTEL", "GOVERNANCE", "DEFENSE"] {
        if let Some(rows) = grouped.get(category) {
            for module in rows {
                visible_ids.push(module.metadata().id.clone());
            }
        }
    }
    let cursor_id = if visible_ids.is_empty() {
        None
    } else {
        Some(visible_ids[app.catalog_cursor.min(visible_ids.len() - 1)].clone())
    };

    for category in ["OFFENSE", "INTEL", "GOVERNANCE", "DEFENSE"] {
        let Some(rows) = grouped.get(category) else {
            continue;
        };
        let (_, blurb) = module_category_blurb(category);
        let widths = module_table_widths(area.width);
        lines.push(category_divider(category, blurb, area.width));
        for module in rows {
            let id = module.metadata().id.as_str();
            let highlight =
                app.focused_module.as_deref() == Some(id) || cursor_id.as_deref() == Some(id);
            lines.push(catalog_module_row(
                &module.metadata().id,
                &module.metadata().description,
                highlight,
                &widths,
            ));
        }
        lines.push(blank());
    }

    lines
}

fn compact_catalog_width(width: u16) -> bool {
    width < 96
}

fn collapsed_catalog_active(app: &ShellApp, width: u16) -> bool {
    !app.catalog_expanded && compact_catalog_width(width)
}
