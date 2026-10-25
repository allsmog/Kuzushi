use super::*;

fn recorded_selection(app: &ShellApp) -> Option<(&FindingRelationship, bool)> {
    let ViewDataState::Ready(Ok(page)) = app.relationship_page() else {
        return None;
    };
    let record = app.router.relationships.pinned.as_ref()?;
    let visible = app
        .relationship_cursor(&page)
        .and_then(|index| page.rows.get(index));
    if visible.is_some_and(|visible| visible.revision >= record.revision) {
        return None;
    }
    Some((record, visible.is_none()))
}

pub(super) fn recorded_heading(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    let Some((record, outside_page)) = recorded_selection(app) else {
        return Vec::new();
    };
    let label = if outside_page {
        "Recorded selection outside this page"
    } else {
        "Recorded revision newer than this page"
    };
    let text = format!(
        "{label}\n{:?} · {:?} · {} / {} · v{}",
        record.kind,
        record.state,
        endpoint_label(app, &record.from),
        endpoint_label(app, &record.to),
        record.revision
    );
    wrap_text(&text, width)
        .into_iter()
        .map(|line| Line::styled(line, theme::warn()))
        .collect()
}

pub(super) fn recorded_details(app: &ShellApp, width: usize) -> Option<Vec<Line<'static>>> {
    let (record, _) = recorded_selection(app)?;
    let mut lines = wrap_text("Showing its recorded revision. Another change can block saving. j/k chooses a visible pair; n/p changes pages.", width)
        .into_iter().map(|line| Line::styled(line, theme::muted())).collect::<Vec<_>>();
    lines.extend(detail_lines(record, width));
    Some(lines)
}
