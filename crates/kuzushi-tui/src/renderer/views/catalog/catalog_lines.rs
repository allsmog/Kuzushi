use super::*;
use std::collections::BTreeMap;

pub(crate) fn catalog_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    // Drop the trailing "· kuzushi shell" segment — the user is in the
    // shell already (the prompt and the top-row mode label both say so),
    // and the muted suffix burned cells the catalog title needed for
    // breathing room. Modules count is the more useful sub-title.
    let module_count = app.registry.modules().count();
    lines.push(Line::from(vec![
        Span::styled("KUZUSHI · CATALOG", theme::heading()),
        Span::styled(theme::STATUS_SEPARATOR, theme::subtle()),
        Span::styled(format!("{module_count} modules"), theme::muted()),
    ]));
    lines.push(blank());

    let modules = app.registry.modules().collect::<Vec<_>>();
    if modules.is_empty() {
        // Empty modules registry — almost never happens in production but
        // matters for plugin-loading errors.  Match the mockup panel shape.
        lines.push(divider("MODULES · empty", area.width));
        lines.extend(empty_state_panel(
            "no modules loaded",
            &[
                "the native module registry is empty.",
                "this almost always means a plugin failed to register.",
            ],
            &[
                ("doctor", "preflight checks for missing tools / plugins"),
                ("modules", "re-inspect the native registry"),
            ],
        ));
        return lines;
    }

    if !app.catalog_expanded {
        if app.target.is_none() {
            lines.push(styled(
                "[!] no target selected; `scan .` uses the current directory",
                theme::warn(),
            ));
        } else if app.findings.is_empty() {
            lines.push(styled(
                "[!] active target has no persisted findings yet",
                theme::warn(),
            ));
        }
        lines.push(next_action_line(
            &catalog_next_hint(app),
            area.width as usize,
        ));
        if app.findings.is_empty() {
            lines.push(muted(&fit(&app.first_finding_hint(), area.width as usize)));
        }
        lines.push(Line::from(vec![
            Span::styled("Start here: ", theme::muted()),
            Span::styled("kuzushi doctor --target .", theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled("context build", theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled(app.first_finding_scan_command(), theme::accent()),
            Span::styled(" -> ", theme::subtle()),
            Span::styled("findings", theme::accent()),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Report: ", theme::muted()),
            Span::styled("kuzushi pr-comment", theme::accent()),
        ]));
        // Three labelled CTAs on one row; each label muted, each command
        // accent, with subtle ` · ` separators — mirrors the mockup's
        // colour split for command CTAs in `auth.jsx::m`.
        lines.push(Line::from(vec![
            Span::styled("Quickstart: ", theme::muted()),
            Span::styled("quickstart", theme::accent()),
            Span::styled(" · ", theme::subtle()),
            Span::styled("Context: ", theme::muted()),
            Span::styled("context build", theme::accent()),
            Span::styled(" · ", theme::subtle()),
            Span::styled("Runtime: ", theme::muted()),
            Span::styled("model", theme::accent()),
        ]));
        lines.push(muted(
            "Type help, modules, use <module>, scan, or run <tool> [json].",
        ));
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
        // Reserve space for the leading `▸ NEXT ` glyph + the literal
        // `Run <id> against the active target — ` prefix so the truncation
        // budget tracks the user's actual terminal width instead of an
        // 88-column historical default.
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

    // Compute the row at which the catalog cursor sits.  Walk categories
    // in render order and gather visible modules so the cursor index is
    // stable across renders.  `j`/`k` in `state_transitions` clamp the
    // cursor to the visible row count.
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
            // Row is highlighted when it's either the focused module
            // (set by `use <id>`) or the j/k cursor row.  Both states
            // share the `▌` accent + c-sel background per
            // `design/mockups/catalog.jsx::modRow`.
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
