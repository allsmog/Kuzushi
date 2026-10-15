use super::*;

pub(crate) struct QuitDisclosureViewport {
    pub(crate) offset: usize,
    pub(crate) page_size: usize,
    pub(crate) max_offset: usize,
}

struct QuitLayout {
    body: Rect,
    expanded: bool,
}

const MIN_DISCLOSURE_ROWS: usize = 8;

pub(crate) fn quit_disclosure_viewport(app: &ShellApp) -> QuitDisclosureViewport {
    let terminal = app.viewport();
    let full = Rect::new(0, 0, terminal.columns, terminal.rows);
    let body = quit_layout(app, full).body;
    let model = quit_confirm_model(app);
    let page_size = visible_rows(&model, body);
    let total = quit_disclosure_lines(&model, body.width as usize).len();
    let max_offset = total.saturating_sub(page_size);
    QuitDisclosureViewport {
        offset: app.router.quit_confirm_scroll().min(max_offset),
        page_size,
        max_offset,
    }
}

pub(crate) fn render_compact_quit(frame: &mut Frame<'_>, app: &ShellApp) -> bool {
    if app.shell_view() != ShellView::QuitConfirm {
        return false;
    }
    let full = frame.area();
    let layout = quit_layout(app, full);
    if !layout.expanded {
        return false;
    }
    let lines = quit_page_lines(app, layout.body);
    frame.render_widget(Clear, full);
    frame.render_widget(quit_block(), full);
    frame.render_widget(Paragraph::new(lines), layout.body);
    true
}

fn quit_layout(app: &ShellApp, full: Rect) -> QuitLayout {
    let body = ordinary_body(app, full);
    let expanded = visible_rows(&quit_confirm_model(app), body) < MIN_DISCLOSURE_ROWS;
    QuitLayout {
        body: if expanded {
            quit_block().inner(full)
        } else {
            body
        },
        expanded,
    }
}

fn ordinary_body(app: &ShellApp, full: Rect) -> Rect {
    let primary = crate::renderer::primary_body_area(app, full);
    if app
        .router
        .overlay_origin()
        .is_some_and(|view| view != ShellView::QuitConfirm)
    {
        let overlay = system_overlay_area(primary, ShellView::QuitConfirm);
        return overlay_content_area(contextual_overlay_body_area(overlay));
    }
    primary
}

fn visible_rows(model: &QuitConfirmModel, body: Rect) -> usize {
    usize::from(body.height).saturating_sub(quit_actions(model, body.width as usize).len() + 1)
}

fn quit_block() -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(theme::subtle())
        .title(Span::styled(" QUIT ", theme::heading()))
}
