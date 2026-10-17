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
    let area = campaign_reader_area(app, Rect::new(0, 0, viewport.columns, viewport.rows));
    let total = campaign_lines(app, area).len();
    let pinned = if campaign_is_paged(app, area, total) {
        reader_chrome(app, area).reserved_rows()
    } else {
        0
    };
    Some(reader_scroll(total, area.height, pinned))
}

pub(crate) fn campaign_selection_scroll(app: &ShellApp) -> Option<usize> {
    app.router.campaign().selected_campaign()?;
    let viewport = app.viewport();
    let area = campaign_reader_area(app, Rect::new(0, 0, viewport.columns, viewport.rows));
    let lines = campaign_lines(app, area);
    let selected = lines.iter().position(|line| {
        let text = line.to_string();
        text.starts_with("▸ ") && !text.starts_with("▸ try:")
    })?;
    Some(selected)
}

pub(crate) fn campaign_view_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let lines = campaign_lines(app, area);
    if study_editor_is_open(app) || !campaign_is_paged(app, area, lines.len()) {
        return lines;
    }
    let chrome = reader_chrome(app, area);
    let reader = reader_scroll(lines.len(), area.height, chrome.reserved_rows());
    let mut visible = chrome.notice;
    let start = app.router.campaign().read_scroll.min(reader.max_offset);
    let end = (start + reader.page_rows).min(lines.len());
    visible.push(muted(&super::progress::reader_heading(
        app.router.campaign(),
        start,
        end,
        lines.len(),
        area.width as usize,
    )));
    visible.extend(lines.into_iter().skip(start).take(reader.page_rows));
    visible.extend(chrome.controls);
    visible.into_iter().take(usize::from(area.height)).collect()
}

struct ReaderChrome {
    notice: Vec<Line<'static>>,
    controls: Vec<Line<'static>>,
}
impl ReaderChrome {
    fn reserved_rows(&self) -> usize {
        self.notice.len() + self.controls.len()
    }
}

fn reader_chrome(app: &ShellApp, area: Rect) -> ReaderChrome {
    let mut controls = sticky_controls(app, area.width);
    if compact_campaign_document(app, area) {
        controls.extend(compact_navigation_controls(app, area.width));
    }
    controls.truncate(usize::from(area.height).saturating_sub(2));
    let mut notice = pinned_action_result(app, area.width);
    let available = usize::from(area.height).saturating_sub(controls.len() + 2);
    if available < notice.len() && !notice.is_empty() {
        notice.remove(0);
    }
    notice.truncate(available);
    ReaderChrome { notice, controls }
}

fn compact_navigation_controls(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let actions = [
        ("composer", "prompt_mode", "Esc", "compose"),
        ("global", "command_palette", "Ctrl+G", "commands"),
    ];
    let text = actions
        .into_iter()
        .flat_map(|(context, action, key, label)| {
            app.ui()
                .keymap_binding_labels(context, action, &[key])
                .into_iter()
                .map(move |key| format!("{key} {label}"))
        })
        .collect::<Vec<_>>()
        .join(" · ");
    wrap_text(&text, usize::from(width).max(1))
        .into_iter()
        .map(|text| Line::styled(text, theme::accent()))
        .collect()
}

fn campaign_is_paged(app: &ShellApp, area: Rect, total: usize) -> bool {
    total > usize::from(area.height)
        || compact_campaign_document(app, area)
        || app.router.campaign().job_detail
}

fn compact_campaign_document(app: &ShellApp, area: Rect) -> bool {
    let viewport = app.viewport();
    area.height <= 18
        && compact_campaign_reader(app, Rect::new(0, 0, viewport.columns, viewport.rows))
}

fn sticky_controls(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let deck = app.router.campaign();
    let text = sticky_control_text(deck);
    text.lines()
        .flat_map(|line| wrap_text(line, usize::from(width).max(1)))
        .take(2)
        .map(|line| Line::styled(line, theme::accent()))
        .collect()
}

fn sticky_control_text(deck: &crate::app::CampaignRouteState) -> String {
    if deck.has_dispatcher_failure_notice() {
        return "R report · a plan/allowance\nr refresh · PgUp/Dn".into();
    }
    active_control_text(deck)
}

fn active_control_text(deck: &crate::app::CampaignRouteState) -> String {
    if deck.job_detail {
        return job_detail_controls(deck);
    }
    let commands = super::campaign_lines::deck_commands(deck);
    if deck.dispatcher_stop_requested {
        "Stop requested · saving partial work\nr refresh · PgUp/Dn · q list".into()
    } else if commands.contains(&"K stop") {
        "K stop · L launch · R report\na plan/allowance · ↑↓ jobs · Enter inspect · r refresh · q list".into()
    } else {
        settled_control_text(commands)
    }
}

fn job_detail_controls(deck: &crate::app::CampaignRouteState) -> String {
    if deck.dispatcher_stop_requested {
        return "Stop requested · saving partial work\nq jobs · r refresh · PgUp/Dn read".into();
    }
    if deck.dispatcher_pid.is_some() {
        return "K stop · R report · q jobs\na plan/allowance · ↑↓ jobs · PgUp/Dn read · r refresh"
            .into();
    }
    "R report · q jobs · a plan/allowance\n↑↓ jobs · PgUp/Dn read · r refresh".into()
}

fn settled_control_text(commands: &[&str]) -> String {
    if commands.contains(&"work paused") {
        "R report · a plan/allowance\nwork paused · L resume · ↑↓ jobs · r refresh · q list".into()
    } else if commands.contains(&"work ended") {
        "R report · a plan/allowance\nwork ended · new work needs a new plan".into()
    } else if commands.contains(&"work finished") {
        "R report · a plan/allowance\nwork finished · ↑↓ jobs · Enter inspect · r refresh · q list"
            .into()
    } else {
        commands.join(" · ")
    }
}

fn reader_scroll(total: usize, height: u16, pinned: usize) -> CampaignReaderScroll {
    let page_rows = usize::from(height).saturating_sub(pinned + 1).max(1);
    CampaignReaderScroll {
        max_offset: total.saturating_sub(page_rows),
        page_rows,
    }
}

fn pinned_action_result(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let deck = app.router.campaign();
    if deck.read_scroll == 0 && deck.has_dispatcher_failure_notice() {
        return Vec::new();
    }
    let Some(notice) = deck.notice.as_ref() else {
        return Vec::new();
    };
    let mut lines = vec![Line::styled(
        "Action result · PgUp/PgDn read",
        theme::warn(),
    )];
    lines.extend(
        wrap_text(notice, usize::from(width).max(1))
            .into_iter()
            .take(2)
            .map(|text| Line::styled(text, theme::warn())),
    );
    lines
}

fn study_editor_is_open(app: &ShellApp) -> bool {
    app.study_engine_picker().is_some()
        || app.context_generation().is_some()
        || app.study_context_picker().is_some()
        || app.router.campaign().batch_scan_config.is_some()
}

pub(crate) fn compact_campaign_reader(app: &ShellApp, full: Rect) -> bool {
    full.height <= 18 && campaign_navigation_owns_input(app) && !study_editor_is_open(app)
}

fn campaign_navigation_owns_input(app: &ShellApp) -> bool {
    app.shell_view() == ShellView::Campaign
        && app.input_mode() == crate::InputMode::Navigate
        && !campaign_attention_is_visible(app)
}

fn campaign_attention_is_visible(app: &ShellApp) -> bool {
    app.advisory().pending_confirm.is_some()
        || crate::ui_view_models::answers_visible(app)
        || app.guided_scan_question_model().is_some()
}

fn campaign_reader_area(app: &ShellApp, full: Rect) -> Rect {
    if compact_campaign_reader(app, full) {
        return full;
    }
    crate::renderer::workbench_primary_area(app, full)
}

#[cfg(test)]
mod tests;
