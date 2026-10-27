use super::*;
use crate::app::{ShellApp, ViewDataState};
use kuzushi_core::findings::{FindingRelationship, FindingRelationshipState};
mod bulk;
mod groups;
mod selection;
pub(crate) use groups::finding_group_page_rows;

pub(super) fn relationship_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    if let Some(review) = &app.router.relationships.bulk {
        return bulk::bulk_lines(app, review, area);
    }
    if app.router.relationships.show_groups {
        return groups::group_lines(app, area);
    }
    if let Some(note) = &app.router.relationships.note {
        return note_view_lines(app, note, area);
    }
    relationship_browser_lines(app, area)
}

pub(super) fn browser_or_batch_page_rows(app: &ShellApp) -> Option<usize> {
    if let Some(review) = &app.router.relationships.bulk {
        return Some(bulk::page_rows(app, review));
    }
    if app.router.relationships.show_groups {
        return None;
    }
    let viewport = app.viewport();
    let area = crate::renderer::workbench_primary_area(
        app,
        Rect::new(0, 0, viewport.columns, viewport.rows),
    );
    Some(usize::from(area.height).max(1))
}

fn relationship_browser_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled("FINDING RELATIONSHIPS", theme::accent())];
    if area.width >= 60 {
        lines.push(Line::raw("Grouping only; verdicts stay separate."));
    }
    lines.extend(selection::recorded_heading(app, area.width as usize));
    lines.extend(narrow_relationship_actions(app, area.width));
    lines.extend(browser_lines(app, area));
    if let Some(notice) = &app.router.relationships.notice {
        lines.extend(
            wrap_text(notice, area.width as usize)
                .into_iter()
                .map(|s| Line::styled(s, theme::warn())),
        );
    }
    if app.input_mode() != crate::InputMode::Navigate {
        lines.extend(
            wrap_text(
                "Esc browse · type a command in the composer",
                area.width as usize,
            )
            .into_iter()
            .map(|s| Line::styled(s, theme::accent())),
        );
    }
    super::shell_view_lines::default_scrolled_lines(app, area, lines)
}

fn narrow_relationship_actions(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    if width >= 60 || app.input_mode() != crate::InputMode::Navigate {
        return Vec::new();
    }
    vec![
        Line::styled("a accept · r separate · u unlink", theme::accent()),
        Line::styled("Space/A review · n/p pages · R refresh", theme::accent()),
    ]
}

fn browser_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let page = match app.relationship_page() {
        ViewDataState::Ready(Ok(page)) => page,
        ViewDataState::Ready(Err(error)) => {
            return vec![Line::styled(
                format!("Relationships unavailable: {error}. R refreshes."),
                theme::warn(),
            )]
        }
        _ => {
            return vec![Line::styled(
                "Loading recorded relationships...",
                theme::muted(),
            )]
        }
    };
    if page.rows.is_empty() {
        return selection::recorded_details(app, area.width as usize).unwrap_or_else(|| {
            vec![
                Line::raw("No relationships recorded for this selection."),
                Line::raw("triage:dedupe proposes duplicates under an approved allowance."),
            ]
        });
    }
    relationship_rows(app, area, &page)
}

fn relationship_rows(
    app: &ShellApp,
    area: Rect,
    page: &kuzushi_core::findings::FindingRelationshipPage,
) -> Vec<Line<'static>> {
    let selected = app.relationship_cursor(page);
    let capacity = usize::from(area.height).saturating_sub(9).clamp(1, 7);
    let start = selected
        .unwrap_or(0)
        .saturating_sub(capacity / 2)
        .min(page.rows.len().saturating_sub(capacity));
    let mut lines = vec![Line::raw(format!(
        "{} relationships on page {} · {} selected{}",
        page.rows.len(),
        page.offset / 50 + 1,
        app.router.relationships.selection.len(),
        if page.has_more {
            " · more available"
        } else {
            ""
        }
    ))];
    lines.extend(
        page.rows
            .iter()
            .enumerate()
            .skip(start)
            .take(capacity)
            .flat_map(|(i, row)| row_lines(app, row, Some(i) == selected, area.width as usize)),
    );
    if let Some(detail) = selection::recorded_details(app, area.width as usize) {
        lines.extend(detail);
    } else if let Some(index) = selected {
        lines.extend(detail_lines(&page.rows[index], area.width as usize));
    }
    lines
}

fn row_lines(
    app: &ShellApp,
    row: &FindingRelationship,
    selected: bool,
    width: usize,
) -> Vec<Line<'static>> {
    let marked = app
        .router
        .relationships
        .selection
        .iter()
        .find(|record| record.id == row.id)
        .map(|record| format!(" · selected v{}", record.revision))
        .unwrap_or_default();
    let text = format!(
        "{} {:?} · {:?} · {} / {}{}",
        if selected { "▸" } else { " " },
        row.kind,
        row.state,
        endpoint_label(app, &row.from),
        endpoint_label(app, &row.to),
        marked,
    );
    let style = if selected {
        theme::accent()
    } else {
        theme::primary()
    };
    wrap_text(&text, width)
        .into_iter()
        .map(|line| Line::styled(line, style))
        .collect()
}

fn endpoint_label(
    app: &ShellApp,
    endpoint: &kuzushi_core::findings::FindingRelationshipEndpoint,
) -> String {
    app.findings()
        .iter()
        .zip(app.finding_aliases())
        .find_map(|(finding, alias)| {
            (finding.id == Some(endpoint.finding_id)).then(|| alias.clone())
        })
        .unwrap_or_else(|| format!("#{}", endpoint.finding_id))
}

fn detail_lines(row: &FindingRelationship, width: usize) -> Vec<Line<'static>> {
    let reason = kuzushi_core::run_lifecycle::SafeText::operator_visible(&row.note);
    let text=format!("Reason: {reason}\nAuthority: {} · revision {}\nRecorded ids: #{} / #{}\nRecorded runs: {} / {}\nOther source revisions need separate review; grouping does not confirm a vulnerability.",row.author,row.revision,row.from.finding_id,row.to.finding_id,row.from.run_id.as_deref().unwrap_or("not recorded"),row.to.run_id.as_deref().unwrap_or("not recorded"));
    let mut lines = wrap_text(&text, width)
        .into_iter()
        .map(Line::raw)
        .collect::<Vec<_>>();
    lines.extend(
        wrap_text(&format!("Relationship: {}", row.id), width)
            .into_iter()
            .map(Line::raw),
    );
    lines
}

fn note_view_lines(
    app: &ShellApp,
    note: &crate::app::RelationshipNote,
    area: Rect,
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::styled(
            format!(
                "{}: {} to {}",
                relationship_action_label(note.state),
                endpoint_label(app, &note.relationship.from),
                endpoint_label(app, &note.relationship.to)
            ),
            theme::accent(),
        ),
        Line::raw("Reason (required):"),
    ];
    let notices = note_notice_lines(app, note, area.width as usize);
    let field_height = usize::from(area.height)
        .saturating_sub(3 + notices.len())
        .max(1);
    lines.extend(crate::renderer::shared::field_editor_lines(
        &note.field,
        area.width as usize,
        field_height,
    ));
    lines.extend(notices);
    lines.push(Line::styled("Enter record · Esc cancel", theme::accent()));
    lines
}

fn relationship_action_label(state: FindingRelationshipState) -> &'static str {
    match state {
        FindingRelationshipState::Accepted => "Accept",
        FindingRelationshipState::Rejected => "Keep separate",
        FindingRelationshipState::Removed => "Unlink",
        FindingRelationshipState::Proposed => "Propose",
    }
}

fn note_notice_lines(
    app: &ShellApp,
    note: &crate::app::RelationshipNote,
    width: usize,
) -> Vec<Line<'static>> {
    let Some(notice) = &app.router.relationships.notice else {
        return Vec::new();
    };
    if notice == "A relationship decision needs a reason." && !note.field.text().trim().is_empty() {
        return Vec::new();
    }
    wrap_text(notice, width)
        .into_iter()
        .take(2)
        .map(|s| Line::styled(s, theme::warn()))
        .collect()
}
