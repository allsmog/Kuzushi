use super::*;

pub(super) fn context_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled("LESSONS INTO CONTEXT", theme::accent())];
    let count = app.router.lessons.selected.len();
    lines.extend(wrapped(&format!("{count} explicitly selected accepted lessons. This replaces the copy's previous lesson selection. Zero removes lessons."),area.width,theme::primary()));
    if let Some(reference) = &app.router.lessons.context_confirm {
        lines.extend(wrapped(&format!("Base: {} / {}\nCreate a new inactive immutable copy. Original and active context remain unchanged. Inspect and select the copy before approving scans.\nEnter creates copy · Esc returns to base selection",reference.model_id,reference.revision_id),area.width,theme::accent()));
    } else {
        lines.extend(context_rows(app, area));
    }
    lines.extend(notice_lines(app, area.width));
    super::super::shell_view_lines::default_scrolled_lines(app, area, lines)
}

fn context_rows(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let catalog = crate::ui_view_models::study_context::context_catalog(app);
    let mut lines = wrapped(
        "Choose the exact base context · j/k select · Enter inspect confirmation · Esc back",
        area.width,
        theme::accent(),
    );
    if catalog.rows.len() <= 1 {
        lines.extend(wrapped(
            &format!("No immutable base context available. {}", catalog.status),
            area.width,
            theme::warn(),
        ));
        return lines;
    }
    let selected = app
        .router
        .lessons
        .context_cursor
        .max(1)
        .min(catalog.rows.len() - 1);
    let capacity = usize::from(area.height)
        .saturating_sub(lines.len() + 5)
        .max(1);
    let start = selected.saturating_sub(capacity / 2).max(1);
    for (index, row) in catalog.rows.iter().enumerate().skip(start).take(capacity) {
        lines.extend(context_row(&row.label, index == selected, area.width));
    }
    lines
}

fn context_row(label: &str, selected: bool, width: u16) -> Vec<Line<'static>> {
    wrapped(
        &format!("{} {}", if selected { "▸" } else { " " }, safe(label)),
        width,
        if selected {
            theme::accent()
        } else {
            theme::primary()
        },
    )
}
