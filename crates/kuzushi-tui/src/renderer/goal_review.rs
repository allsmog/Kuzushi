use super::*;
use crate::app::goal_review::GoalReviewState;
use crate::ui_view_models::goal_review as model;

pub(super) fn render(frame: &mut Frame<'_>, app: &ShellApp) -> bool {
    let Some(state) = app.goal_review() else {
        return false;
    };
    let area = frame.area();
    let sections = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(1),
        Constraint::Length(4),
    ])
    .split(area);
    let heading = model::heading(state);
    let parts = heading.lines().collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(
            parts
                .into_iter()
                .map(|line| Line::styled(fit(line, area.width as usize), theme::heading()))
                .collect::<Vec<_>>(),
        ),
        sections[0],
    );
    render_body(frame, state, sections[1]);
    frame.render_widget(
        Paragraph::new(model::controls(state))
            .wrap(ratatui::widgets::Wrap { trim: false })
            .style(theme::accent()),
        sections[2],
    );
    true
}

fn render_body(frame: &mut Frame<'_>, state: &GoalReviewState, area: Rect) {
    if state.editing
        || state.discarding
        || state.show_brief
        || state.show_keys
        || state.show_history
    {
        render_detail(frame, state, area);
        return;
    }
    if area.width >= 100 {
        let parts = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);
        render_list(frame, state, parts[0]);
        let divider = ratatui::widgets::Block::default()
            .borders(ratatui::widgets::Borders::LEFT)
            .border_style(theme::subtle());
        let detail = divider.inner(parts[1]);
        frame.render_widget(divider, parts[1]);
        render_detail(frame, state, detail);
    } else {
        let parts = Layout::vertical([
            Constraint::Length((area.height / 3).clamp(1, 6)),
            Constraint::Min(1),
        ])
        .split(area);
        render_list(frame, state, parts[0]);
        render_detail(frame, state, parts[1]);
    }
}

fn render_list(frame: &mut Frame<'_>, state: &GoalReviewState, area: Rect) {
    let Some(Ok(page)) = &state.page else {
        return;
    };
    let selected = state.selected().and_then(|row| {
        page.rows
            .iter()
            .position(|candidate| candidate.basis == row.basis)
    });
    let height = usize::from(area.height);
    let start = selected
        .unwrap_or(0)
        .saturating_sub(height / 2)
        .min(page.rows.len().saturating_sub(height));
    let lines = page
        .rows
        .iter()
        .enumerate()
        .skip(start)
        .take(height)
        .map(|(index, row)| {
            let text = format!(
                "{} {} · {}",
                if selected == Some(index) { "▸" } else { " " },
                row.label(),
                row.finding.title
            );
            let text = kuzushi_core::run_lifecycle::SafeText::operator_visible(&text).to_string();
            Line::styled(
                fit(&text, area.width as usize),
                if selected == Some(index) {
                    theme::accent()
                } else {
                    theme::primary()
                },
            )
        })
        .collect::<Vec<_>>();
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_detail(frame: &mut Frame<'_>, state: &GoalReviewState, area: Rect) {
    if let Some(form) = reason_form(state) {
        render_reason(frame, state, form, area);
        return;
    }
    let mut texts = model::detail(state);
    if let Some(notice) = &state.notice {
        texts.insert(0, notice.clone());
    }
    let lines = texts
        .into_iter()
        .flat_map(|text| wrap_text(&text, area.width as usize))
        .map(Line::raw)
        .collect::<Vec<_>>();
    let max = lines.len().saturating_sub(area.height as usize);
    frame.render_widget(
        Paragraph::new(
            lines
                .into_iter()
                .skip(state.scroll.min(max))
                .take(area.height as usize)
                .collect::<Vec<_>>(),
        ),
        area,
    );
}

fn render_reason(
    frame: &mut Frame<'_>,
    state: &GoalReviewState,
    form: &crate::app::goal_review::GoalAssessmentForm,
    area: Rect,
) {
    let parts = Layout::vertical([Constraint::Length(2), Constraint::Min(1)]).split(area);
    let title = model::reason_heading(state, form);
    frame.render_widget(
        Paragraph::new(title)
            .wrap(ratatui::widgets::Wrap { trim: false })
            .style(theme::accent()),
        parts[0],
    );
    frame.render_widget(
        Paragraph::new(shared::field_editor_lines(
            &form.reason,
            parts[1].width as usize,
            parts[1].height as usize,
        )),
        parts[1],
    );
}

fn reason_form(state: &GoalReviewState) -> Option<&crate::app::goal_review::GoalAssessmentForm> {
    if !state.editing || state.discarding {
        return None;
    }
    state.form.as_ref().filter(|form| !form.confirming)
}
