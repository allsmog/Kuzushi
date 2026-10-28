use super::*;

pub(super) fn render_context_matrix(
    frame: &mut Frame<'_>,
    app: &ShellApp,
    config: &BatchScanConfig,
    area: Rect,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" CONTEXT CASES ");
    let inner = block.inner(area).inner(ratatui::layout::Margin::new(1, 0));
    frame.render_widget(block, area);
    let body = crate::ui_view_models::matrix_body(area, config.study.matrix.results);
    frame.render_widget(
        Paragraph::new(
            crate::ui_view_models::matrix_allowance_lines(app, inner.width.into()).join("\n"),
        ),
        Rect {
            height: body.y.saturating_sub(inner.y).min(inner.height),
            ..inner
        },
    );
    let lines = matrix_surface_lines(app, config, body);
    frame.render_widget(ratatui::widgets::Paragraph::new(lines.join("\n")), body);
    if config.study.matrix.results {
        render_matrix_result_controls(frame, app, inner);
    } else {
        render_matrix_controls(frame, inner)
    };
}

fn matrix_surface_lines(app: &ShellApp, config: &BatchScanConfig, body: Rect) -> Vec<String> {
    if config.study.matrix.results {
        return crate::ui_view_models::matrix_result_lines(
            app,
            body.width as usize,
            body.height as usize,
        );
    }
    crate::ui_view_models::context_matrix_lines(config, body.width as usize, body.height as usize)
}

fn render_matrix_result_controls(frame: &mut Frame<'_>, app: &ShellApp, inner: Rect) {
    let hints = crate::ui_view_models::matrix_result_controls(app);
    let height = (hints.len() as u16).min(inner.height);
    frame.render_widget(
        ratatui::widgets::Paragraph::new(hints.join("\n")),
        Rect::new(
            inner.x,
            inner.bottom().saturating_sub(height),
            inner.width,
            height,
        ),
    );
}

fn render_matrix_controls(frame: &mut Frame<'_>, inner: Rect) {
    let (hints, height) = if inner.width < 50 {
        (
            "↑↓ · Enter inspect · n rename\na add · b baseline · p passes\nx remove · c clear · v results\nL next · Esc back",
            4,
        )
    } else {
        (
            "↑↓ · Enter inspect · n rename · a add\nb baseline · p passes · x remove · c clear\nv results · L next · Esc back",
            3,
        )
    };
    frame.render_widget(
        ratatui::widgets::Paragraph::new(hints),
        Rect::new(
            inner.x,
            inner.bottom().saturating_sub(height),
            inner.width,
            height,
        ),
    );
}

pub(super) fn render_context_results(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" COMPARE CONTEXT EXPERIMENT ");
    let inner = block.inner(area).inner(ratatui::layout::Margin::new(1, 0));
    frame.render_widget(block, area);
    let lines = crate::ui_view_models::study_config::context_result_lines(
        app,
        inner.width as usize,
        inner.height.saturating_sub(2) as usize,
    );
    frame.render_widget(
        Paragraph::new(lines.into_iter().map(Line::from).collect::<Vec<_>>()),
        Rect {
            height: inner.height.saturating_sub(2),
            ..inner
        },
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::from("↑↓ pass · Enter compare · Esc back"),
            Line::from("r refresh · x clear · no work starts"),
        ]),
        Rect {
            y: inner.bottom().saturating_sub(2),
            height: 2,
            ..inner
        },
    );
}
