use super::*;

pub(crate) struct CampaignReaderScroll {
    pub(crate) max_offset: usize,
    pub(crate) page_rows: usize,
}

pub(crate) fn campaign_reader_scroll(app: &ShellApp) -> Option<CampaignReaderScroll> {
    if app.shell_view() != ShellView::Campaign || study_editor_is_open(app) {
        return None;
    }
    let viewport = app.viewport();
    let area = crate::renderer::workbench_primary_area(
        app,
        Rect::new(0, 0, viewport.columns, viewport.rows),
    );
    Some(reader_scroll(campaign_lines(app, area).len(), area.height))
}

pub(crate) fn campaign_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let lines = campaign_lines(app, area);
    if study_editor_is_open(app) || lines.len() <= usize::from(area.height) {
        return lines;
    }
    let reader = reader_scroll(lines.len(), area.height);
    let start = app.router.campaign().read_scroll.min(reader.max_offset);
    let end = (start + reader.page_rows).min(lines.len());
    let mut visible = vec![muted(&format!(
        " rows {}-{end}/{} · PgUp/PgDn",
        start + 1,
        lines.len()
    ))];
    visible.extend(lines.into_iter().skip(start).take(reader.page_rows));
    visible.into_iter().take(usize::from(area.height)).collect()
}

fn reader_scroll(total: usize, height: u16) -> CampaignReaderScroll {
    let page_rows = usize::from(height).saturating_sub(1).max(1);
    CampaignReaderScroll {
        max_offset: total.saturating_sub(page_rows),
        page_rows,
    }
}

fn study_editor_is_open(app: &ShellApp) -> bool {
    app.study_engine_picker().is_some()
        || app.context_generation().is_some()
        || app.study_context_picker().is_some()
        || app.router.campaign().batch_scan_config.is_some()
}

#[cfg(test)]
mod tests;
