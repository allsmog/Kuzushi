use super::*;
use crate::ui_view_models::RailSection;

/// The context rail: a fixed-width right column of ambient engagement facts.
/// Separation from the body is one subtle `│` gutter — no boxes, no borders;
/// section headings in `theme::label()` above their rows, one blank row
/// between sections.
pub(in crate::renderer) fn render_context_rail(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    if area.width < 4 || area.height == 0 {
        return;
    }
    let content_width = usize::from(area.width) - 3;
    let lines = rail_lines(app, content_width, usize::from(area.height));
    let rows = lines.into_iter().map(gutter_line).collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(rows), area);
}

/// `│ <content…>` — every rail row carries the gutter so the seam stays
/// unbroken for the full terminal height.
fn gutter_line(content: Line<'static>) -> Line<'static> {
    let mut spans = vec![Span::styled("│ ", theme::subtle())];
    spans.extend(content.spans);
    Line::from(spans)
}

fn rail_lines(app: &ShellApp, width: usize, height: usize) -> Vec<Line<'static>> {
    let sections = crate::ui_view_models::rail_sections(app, width);
    let mut lines = Vec::new();
    for section in sections {
        if !lines.is_empty() {
            lines.push(Line::raw(""));
        }
        lines.extend(section_lines(section));
    }
    lines.truncate(height);
    // The gutter seam runs the full terminal height even past the content,
    // so the rail reads as a column, not a floating card.
    while lines.len() < height {
        lines.push(Line::raw(""));
    }
    lines
}

fn section_lines(section: RailSection) -> Vec<Line<'static>> {
    let mut lines = vec![Line::styled(section.title, theme::label())];
    lines.extend(section.rows);
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::V2Config;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn rendered_rows(app: &ShellApp, width: u16, height: u16) -> Vec<String> {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| {
                let area = frame.area();
                render_context_rail(frame, area, app);
            })
            .expect("draw rail");
        let buffer = terminal.backend().buffer().clone();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn rail_renders_gutter_on_every_row() {
        let app = ShellApp::new(V2Config::default(), None);
        let rows = rendered_rows(&app, 36, 12);

        assert!(rows.iter().all(|row| row.starts_with("│ ")));
    }

    #[test]
    fn rail_leads_with_target_before_engagement_and_ends_with_cost() {
        // Engagement chrome stays hidden until `Start Map` commits it, so an
        // uncommitted shell anchors the rail on its TARGET section.
        let app = ShellApp::new(V2Config::default(), None);
        let rows = rendered_rows(&app, 36, 12);

        assert!(rows[0].contains("TARGET"));
        assert!(rows.iter().any(|row| row.contains("COST")));
        assert!(rows.iter().any(|row| row.contains("no target")));
    }

    #[test]
    fn degenerate_widths_render_nothing() {
        let app = ShellApp::new(V2Config::default(), None);
        let rows = rendered_rows(&app, 3, 4);

        assert!(rows.iter().all(|row| row.trim().is_empty()));
    }
}
