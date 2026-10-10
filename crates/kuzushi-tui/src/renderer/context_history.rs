use super::*;
use crate::ui_view_models::context_history::{
    history_catalog, history_controls, history_detail_lines, history_layout, ContextHistoryCatalog,
};
use ratatui::widgets::{Block, Borders, Clear};

pub(super) fn render(frame: &mut Frame<'_>, app: &ShellApp) -> bool {
    let Some(state) = app.context_history() else {
        return false;
    };
    if app.advisory().pending_confirm.is_some() {
        return false;
    }
    let area = frame.area();
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::subtle())
        .title(history_title(state));
    frame.render_widget(block, area);
    let catalog = history_catalog(app);
    let layout = history_layout(area, state.request.is_some());
    if let Some(list) = layout.list {
        render_rows(frame, state, &catalog, list);
    }
    let position = render_detail(frame, state, &catalog, layout.detail);
    let header = history_header(state, &catalog, position);
    frame.render_widget(
        Paragraph::new(fit(&header, layout.header.width as usize)).style(theme::muted()),
        layout.header,
    );
    frame.render_widget(
        Paragraph::new(
            history_controls(state.request.as_ref())
                .map(Line::from)
                .to_vec(),
        )
        .style(theme::muted()),
        layout.controls,
    );
    true
}

fn history_title(state: &crate::app::ContextHistoryState) -> &'static str {
    match state.request {
        Some(crate::app::ContextHistoryRequest::Read(_)) => " INSPECT CONTEXT ",
        Some(crate::app::ContextHistoryRequest::Compare { .. }) => " COMPARE CONTEXT ",
        None => " THREAT MODEL LINEAGES ",
    }
}

fn history_header(
    state: &crate::app::ContextHistoryState,
    catalog: &ContextHistoryCatalog,
    position: (usize, usize, usize),
) -> String {
    if state.request.is_none() {
        return catalog.status.clone();
    }
    format!(
        "Lines {}-{}/{} · saved context",
        position.0, position.1, position.2
    )
}

fn render_rows(
    frame: &mut Frame<'_>,
    state: &crate::app::ContextHistoryState,
    catalog: &ContextHistoryCatalog,
    area: Rect,
) {
    let selected = catalog.selected_index(Some(state));
    let start = selected
        .unwrap_or(0)
        .saturating_sub((area.height as usize).saturating_sub(1));
    let lines = catalog
        .rows
        .iter()
        .enumerate()
        .skip(start)
        .take(area.height as usize)
        .map(|(index, row)| {
            let marker = if Some(index) == selected { "▸" } else { " " };
            let active = if row.active { " · active" } else { "" };
            let style = if Some(index) == selected {
                theme::selection()
            } else {
                theme::primary()
            };
            Line::styled(
                fit(
                    &format!("{marker} {}{active}", row.label),
                    area.width as usize,
                ),
                style,
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_detail(
    frame: &mut Frame<'_>,
    state: &crate::app::ContextHistoryState,
    catalog: &ContextHistoryCatalog,
    area: Rect,
) -> (usize, usize, usize) {
    let lines = history_detail_lines(state, catalog, area.width as usize);
    let count = lines.len();
    let max = lines.len().saturating_sub(area.height as usize);
    let offset = state.scroll.min(max);
    let lines = lines
        .into_iter()
        .skip(offset)
        .take(area.height as usize)
        .map(|line| Line::styled(line, theme::primary()))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
    (
        offset + 1,
        (offset + area.height as usize).min(count),
        count,
    )
}
