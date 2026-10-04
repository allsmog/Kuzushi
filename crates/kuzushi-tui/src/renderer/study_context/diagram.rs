use super::*;
use crate::renderer::views::DfdDiagram;
use crate::ui_view_models::study_context::diagram::{
    diagram_body, diagram_detail_lines, diagram_identity, diagram_status,
};

pub(super) fn render(frame: &mut Frame<'_>, app: &ShellApp, area: Rect) {
    let Some(picker) = app.study_context_picker() else {
        return;
    };
    let Some((state, preview)) = picker.diagram.as_ref().zip(picker.preview.as_ref()) else {
        return;
    };
    frame.render_widget(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::subtle())
            .title(Span::styled(" CONTEXT DATA FLOW ", theme::heading())),
        area,
    );
    let identity = Rect::new(area.x + 1, area.y + 1, area.width.saturating_sub(2), 1);
    frame.render_widget(
        Paragraph::new(fit(&diagram_identity(app), identity.width as usize))
            .style(theme::heading()),
        identity,
    );
    frame.render_widget(
        Paragraph::new(fit(&diagram_status(app), identity.width as usize)).style(theme::muted()),
        Rect {
            y: identity.y + 1,
            ..identity
        },
    );
    let body = diagram_body(area);
    let progress = if state.details {
        Some(render_details(frame, app, body, state.scroll))
    } else {
        render_topology(frame, body, &preview.dfd, state.selection);
        None
    };
    render_controls(frame, area, progress.as_deref());
}

fn render_topology(
    frame: &mut Frame<'_>,
    area: Rect,
    model: &crate::ui_view_models::DfdModel,
    selection: usize,
) {
    if let Some(hint) = &model.empty_hint {
        let lines = wrap_text(&format!("No diagram for this revision. {hint}. Esc returns to context review; generation requires a separate approved plan."), area.width as usize);
        frame.render_widget(Paragraph::new(lines.join("\n")).style(theme::muted()), area);
        return;
    }
    frame.render_widget(
        DfdDiagram {
            model: model.clone(),
            selection: Some(selection),
            detail_scroll: 0,
            focused: false,
            context_selection: 0,
        },
        area,
    );
}

fn render_details(
    frame: &mut Frame<'_>,
    app: &ShellApp,
    area: Rect,
    requested_scroll: usize,
) -> String {
    let lines = diagram_detail_lines(app, area.width as usize);
    let total = lines.len();
    let offset = requested_scroll.min(total.saturating_sub(area.height as usize));
    let last = (offset + area.height as usize).min(total);
    let shown = lines
        .into_iter()
        .skip(offset)
        .take(area.height as usize)
        .map(|line| Line::styled(line, theme::primary()))
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(shown), area);
    format!("{}–{last}/{total}", (offset + 1).min(total))
}

fn render_controls(frame: &mut Frame<'_>, area: Rect, progress: Option<&str>) {
    let controls = Rect::new(
        area.x + 1,
        area.bottom().saturating_sub(3),
        area.width.saturating_sub(2),
        2,
    );
    let action = progress.map_or_else(
        || "Enter details".into(),
        |range| format!("Enter diagram · PgUp/Dn {range}"),
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("↑↓ element · Esc context", theme::muted()),
            Line::styled(action, theme::accent()),
        ]),
        controls,
    );
}
