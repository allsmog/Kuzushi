use super::*;
use crate::ui_view_models::{prereq_prompt_model, PrereqPromptModel, PrereqPromptStepModel};

const PREREQ_HEADER_ROWS: usize = 2;
const PREREQ_MIN_ROWS: usize = 4;

pub(crate) fn prereq_prompt_card_height(app: &ShellApp, area: Rect) -> u16 {
    let Some(prompt) = prereq_prompt_model(app) else {
        return 0;
    };
    if area.height < 8 {
        return 0;
    }
    prereq_prompt_rows(
        &prompt,
        area.width as usize,
        area.height.saturating_sub(8) as usize,
    )
    .len() as u16
}

pub(crate) fn render_prereq_prompt_card(frame: &mut Frame<'_>, area: Rect, app: &ShellApp) {
    let Some(prompt) = prereq_prompt_model(app) else {
        return;
    };
    render_lines(
        frame,
        area,
        prereq_prompt_rows(&prompt, area.width as usize, area.height as usize),
    );
}

fn prereq_prompt_rows(
    prompt: &PrereqPromptModel,
    width: usize,
    max_rows: usize,
) -> Vec<Line<'static>> {
    if max_rows < PREREQ_MIN_ROWS || width == 0 {
        return Vec::new();
    }
    let actions = prereq_action_rows(width, max_rows > PREREQ_MIN_ROWS);
    let fixed_rows = PREREQ_HEADER_ROWS + actions.len();
    let context_budget = max_rows.saturating_sub(fixed_rows);
    let context = prereq_context_rows(prompt, width, context_budget);
    let detail_budget = context_budget.saturating_sub(context.len());
    let mut rows = prereq_header_rows(prompt, width);
    rows.extend(context);
    rows.extend(
        prereq_detail_rows(prompt, width)
            .into_iter()
            .take(detail_budget),
    );
    rows.extend(actions);
    rows
}

fn prereq_header_rows(prompt: &PrereqPromptModel, width: usize) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            fit(" PREREQUISITE PLAN", width),
            theme::accent(),
        )),
        prereq_field_line("final tool", &prompt.final_tool, width, theme::primary()),
    ]
}

fn prereq_context_rows(
    prompt: &PrereqPromptModel,
    width: usize,
    budget: usize,
) -> Vec<Line<'static>> {
    if budget == 0 {
        return Vec::new();
    }
    if prompt.steps.is_empty() {
        return vec![Line::from(Span::styled(
            fit(
                "  no prerequisite steps · final tool can start directly",
                width,
            ),
            theme::muted(),
        ))];
    }
    prereq_step_context_rows(prompt, width, budget)
}

fn prereq_step_context_rows(
    prompt: &PrereqPromptModel,
    width: usize,
    budget: usize,
) -> Vec<Line<'static>> {
    if budget == 1 {
        return vec![prereq_step_line_with_omitted(
            &prompt.steps[0],
            prompt.steps.len().saturating_sub(1),
            width,
        )];
    }
    let shown_steps = prompt.steps.len().min(budget.saturating_sub(1));
    let omitted = prompt.steps.len().saturating_sub(shown_steps);
    let mut rows = prompt
        .steps
        .iter()
        .take(shown_steps)
        .map(|step| prereq_step_line(step, width))
        .collect::<Vec<_>>();
    if omitted > 0 {
        rows.push(prereq_omitted_steps_line(omitted, width));
    }
    rows
}

fn prereq_step_line_with_omitted(
    step: &PrereqPromptStepModel,
    omitted: usize,
    width: usize,
) -> Line<'static> {
    if omitted == 0 {
        return prereq_step_line(step, width);
    }
    let prefix = "  ";
    let state_width = width.saturating_sub(8).min(5);
    let state = fit(&step.state_label, state_width);
    let separator = " via ";
    let suffix = format!(" +{omitted} more");
    let fixed_width = display_width(prefix)
        + display_width(&state)
        + display_width(separator)
        + display_width(&suffix);
    if fixed_width >= width {
        return compact_prereq_step_with_omitted(step, omitted, width);
    }
    let tool_width = width - fixed_width;
    Line::from(vec![
        Span::raw(prefix),
        Span::styled(state, prereq_state_style(step)),
        Span::styled(separator, theme::muted()),
        Span::styled(fit(&step.tool, tool_width), theme::label()),
        Span::styled(suffix, theme::warn()),
    ])
}

fn compact_prereq_step_with_omitted(
    step: &PrereqPromptStepModel,
    omitted: usize,
    width: usize,
) -> Line<'static> {
    let count = format!("+{omitted}");
    let suffix = if display_width(&count) < width {
        format!(" {count}")
    } else {
        count
    };
    let suffix = fit(&suffix, width);
    let tool_width = width.saturating_sub(display_width(&suffix));
    Line::from(vec![
        Span::styled(fit(&step.tool, tool_width), prereq_state_style(step)),
        Span::styled(suffix, theme::warn()),
    ])
}

fn prereq_omitted_steps_line(omitted: usize, width: usize) -> Line<'static> {
    Line::from(Span::styled(
        fit(&format!("  +{omitted} more prerequisite step(s)"), width),
        theme::warn(),
    ))
}

fn prereq_step_line(step: &PrereqPromptStepModel, width: usize) -> Line<'static> {
    if width < 8 {
        return prereq_field_line("tool", &step.tool, width, theme::label());
    }
    let prefix = "  ";
    let state_width = width.saturating_sub(8).min(9);
    let state = fit(&step.state_label, state_width);
    let separator = " via ";
    let tool_width = width
        .saturating_sub(display_width(prefix))
        .saturating_sub(display_width(&state))
        .saturating_sub(display_width(separator));
    Line::from(vec![
        Span::raw(prefix),
        Span::styled(state, prereq_state_style(step)),
        Span::styled(separator, theme::muted()),
        Span::styled(fit(&step.tool, tool_width), theme::label()),
    ])
}

fn prereq_state_style(step: &PrereqPromptStepModel) -> Style {
    if step.cached {
        theme::success()
    } else {
        theme::warn()
    }
}

fn prereq_detail_rows(prompt: &PrereqPromptModel, width: usize) -> Vec<Line<'static>> {
    let mut rows = vec![prereq_field_line(
        "recommended",
        &prompt.recommended_action,
        width,
        theme::success(),
    )];
    rows.extend(
        prompt
            .steps
            .iter()
            .flat_map(|step| prereq_step_detail_rows(step, width))
            .collect::<Vec<_>>(),
    );
    rows
}

fn prereq_step_detail_rows(step: &PrereqPromptStepModel, width: usize) -> Vec<Line<'static>> {
    let mut rows = vec![
        prereq_field_line("artifact", &step.artifact_label, width, theme::primary()),
        prereq_field_line("writes", &step.writes, width, theme::muted()),
        prereq_field_line("risk", &step.risk, width, theme::muted()),
        prereq_field_line("cost", &step.cost_hint, width, theme::muted()),
    ];
    if let Some(hint) = step.state_hint {
        rows.push(prereq_field_line("state", hint, width, theme::warn()));
    }
    rows
}

fn prereq_field_line(label: &str, value: &str, width: usize, value_style: Style) -> Line<'static> {
    let full_prefix = format!("  {label:<11}");
    let prefix = if width >= display_width(&full_prefix) + 4 {
        full_prefix
    } else {
        format!("{label} ")
    };
    let prefix = fit(&prefix, width);
    let value_width = width.saturating_sub(display_width(&prefix));
    Line::from(vec![
        Span::styled(prefix, theme::muted()),
        Span::styled(fit(value, value_width), value_style),
    ])
}

fn prereq_action_rows(width: usize, expanded: bool) -> Vec<Line<'static>> {
    if !expanded {
        return vec![compact_prereq_action_line(width)];
    }
    vec![
        action_pair_line(
            ("a", "approve", "ok", theme::success()),
            ("r", "reuse cached", "reuse", theme::primary()),
            width,
        ),
        action_pair_line(
            ("g", "regenerate", "regen", theme::warn()),
            ("n", "cancel", "cancel", theme::danger()),
            width,
        ),
    ]
}

fn compact_prereq_action_line(width: usize) -> Line<'static> {
    if width < 21 {
        return compact_prereq_keys(width);
    }
    Line::from(vec![
        Span::styled("a", theme::success()),
        Span::styled(" ok ", theme::muted()),
        Span::styled("r", theme::primary()),
        Span::styled(" use ", theme::muted()),
        Span::styled("g", theme::warn()),
        Span::styled(" new ", theme::muted()),
        Span::styled("n", theme::danger()),
        Span::styled(" no", theme::muted()),
    ])
}

fn compact_prereq_keys(width: usize) -> Line<'static> {
    let keys = [
        ("a", theme::success()),
        ("r", theme::primary()),
        ("g", theme::warn()),
        ("n", theme::danger()),
    ];
    let separator_width = width.saturating_sub(keys.len()).min(keys.len() - 1);
    let mut spans = Vec::new();
    for (index, (key, style)) in keys.into_iter().enumerate() {
        if index > 0 && index <= separator_width {
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled(fit(key, usize::from(index < width)), style));
    }
    Line::from(spans)
}

fn action_pair_line(
    left: (&str, &str, &str, Style),
    right: (&str, &str, &str, Style),
    width: usize,
) -> Line<'static> {
    let indent = usize::from(width >= 24) * 2;
    if width < indent + 6 {
        return action_key_line(left.0, left.3, right.0, right.3, width);
    }
    let label_budget = width.saturating_sub(indent + 6);
    let left_budget = label_budget / 2;
    let right_budget = label_budget.saturating_sub(left_budget);
    Line::from(vec![
        Span::raw(" ".repeat(indent)),
        Span::styled(left.0.to_string(), left.3),
        Span::raw(" "),
        Span::styled(action_label(left.1, left.2, left_budget), theme::muted()),
        Span::raw("  "),
        Span::styled(right.0.to_string(), right.3),
        Span::raw(" "),
        Span::styled(action_label(right.1, right.2, right_budget), theme::muted()),
    ])
}

fn action_key_line(
    left_key: &str,
    left_style: Style,
    right_key: &str,
    right_style: Style,
    width: usize,
) -> Line<'static> {
    let separator = usize::from(width >= 3);
    let key_width = width.saturating_sub(separator);
    let left_width = key_width / 2;
    let right_width = key_width.saturating_sub(left_width);
    Line::from(vec![
        Span::styled(fit(left_key, left_width), left_style),
        Span::raw(" ".repeat(separator)),
        Span::styled(fit(right_key, right_width), right_style),
    ])
}

fn action_label(full: &str, compact: &str, width: usize) -> String {
    if display_width(full) <= width {
        full.to_string()
    } else {
        fit(compact, width)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constrained_projection_pins_tools_and_all_action_keys() {
        let prompt = prompt_with_step();
        let rows = prereq_prompt_rows(&prompt, 28, PREREQ_MIN_ROWS + 1);
        let text = row_texts(&rows);

        assert_eq!(rows.len(), PREREQ_MIN_ROWS + 1);
        assert!(text[0].contains("PREREQUISITE PLAN"), "{text:?}");
        assert!(text[1].contains("final tool"), "{text:?}");
        assert!(text[1].contains("final-tool"), "{text:?}");
        assert!(text[2].contains("prep"), "{text:?}");
        assert!(text[3].contains("a approve"), "{text:?}");
        assert!(text[3].contains("r reuse"), "{text:?}");
        assert!(text[4].contains("g regen"), "{text:?}");
        assert!(text[4].contains("n cancel"), "{text:?}");
        assert_rows_fit(&rows, 28);
    }

    #[test]
    fn empty_plan_has_honest_context_and_keeps_actions() {
        let prompt = PrereqPromptModel {
            final_tool: "final-tool:run".to_string(),
            recommended_action: "approve".to_string(),
            steps: Vec::new(),
        };
        let text = row_texts(&prereq_prompt_rows(&prompt, 32, PREREQ_MIN_ROWS + 1));

        assert!(text[2].contains("no prerequisite steps"), "{text:?}");
        assert!(text[3].contains("a approve"), "{text:?}");
        assert!(text[4].contains("n cancel"), "{text:?}");
    }

    #[test]
    fn four_row_projection_keeps_context_and_every_action_key() {
        let rows = prereq_prompt_rows(&prompt_with_step(), 21, PREREQ_MIN_ROWS);
        let text = row_texts(&rows);

        assert_eq!(rows.len(), PREREQ_MIN_ROWS);
        assert!(text[1].contains("final"), "{text:?}");
        assert!(text[2].contains("prep"), "{text:?}");
        for key in ["a", "r", "g", "n"] {
            assert!(text[3].contains(key), "missing {key}: {text:?}");
        }
        assert_rows_fit(&rows, 21);
    }

    #[test]
    fn constrained_plan_discloses_omitted_steps_before_actions() {
        let mut prompt = prompt_with_step();
        prompt.steps.push(prompt.steps[0].clone());
        let text = row_texts(&prereq_prompt_rows(&prompt, 28, PREREQ_MIN_ROWS + 1));

        assert!(text[2].contains("prep"), "{text:?}");
        assert!(text[2].contains("+1 more"), "{text:?}");
        assert!(text[4].contains("g regen"), "{text:?}");
    }

    #[test]
    fn minimum_projection_is_width_safe() {
        let prompt = prompt_with_step();
        for width in 1..=40 {
            assert_rows_fit(&prereq_prompt_rows(&prompt, width, PREREQ_MIN_ROWS), width);
        }
    }

    #[test]
    fn omitted_step_projection_is_width_safe_at_every_compact_width() {
        let mut prompt = prompt_with_step();
        prompt.steps.push(prompt.steps[0].clone());
        for width in 1..=40 {
            let rows = prereq_prompt_rows(&prompt, width, PREREQ_MIN_ROWS);
            assert_rows_fit(&rows, width);
            if width >= 2 {
                assert!(row_text(&rows[2]).contains("+1"), "width {width}: {rows:?}");
            }
        }
    }

    fn prompt_with_step() -> PrereqPromptModel {
        PrereqPromptModel {
            final_tool: "final-tool:run-with-options".to_string(),
            recommended_action: "approve".to_string(),
            steps: vec![PrereqPromptStepModel {
                state_label: "missing".to_string(),
                cached: false,
                state_hint: None,
                artifact_label: "context snapshot".to_string(),
                tool: "prep-tool:build-context".to_string(),
                writes: ".kuzushi/context.json".to_string(),
                risk: "model-backed".to_string(),
                cost_hint: "unknown".to_string(),
            }],
        }
    }

    fn row_texts(rows: &[Line<'static>]) -> Vec<String> {
        rows.iter().map(row_text).collect()
    }

    fn row_text(row: &Line<'static>) -> String {
        row.spans.iter().map(|span| span.content.as_ref()).collect()
    }

    fn assert_rows_fit(rows: &[Line<'static>], width: usize) {
        for row in rows {
            assert!(display_width(&row_text(row)) <= width, "{row:?}");
        }
    }
}
