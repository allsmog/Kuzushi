use super::*;
use crate::app::PlanningOptionEdit;

struct EditorLayout {
    errors: Vec<String>,
    field_height: usize,
    error_height: usize,
    paged: bool,
}

impl EditorLayout {
    fn new(app: &ShellApp, area: Rect) -> Self {
        let errors: Vec<_> = app
            .engagement
            .planning_picker()
            .option_error()
            .into_iter()
            .flat_map(|text| wrap_text(text, area.width as usize))
            .collect();
        let available = (area.height as usize).saturating_sub(3);
        let field_height = if errors.is_empty() {
            available
        } else {
            available.div_ceil(2)
        };
        let error_budget = available.saturating_sub(field_height);
        let paged = errors.len() > error_budget;
        let error_height = error_budget.saturating_sub(usize::from(paged));
        Self {
            errors,
            field_height,
            error_height,
            paged,
        }
    }

    fn max_scroll(&self) -> usize {
        self.errors.len().saturating_sub(self.error_height)
    }

    fn error_lines(&self, scroll: usize) -> Vec<Line<'static>> {
        let start = scroll.min(self.max_scroll());
        let mut lines: Vec<_> = self
            .errors
            .iter()
            .skip(start)
            .take(self.error_height)
            .map(|text| styled(text, theme::danger()))
            .collect();
        if self.paged && self.error_height > 0 {
            lines.push(muted(&format!(
                "Error {}–{}/{} · PgUp/PgDn",
                start + 1,
                (start + self.error_height).min(self.errors.len()),
                self.errors.len()
            )));
        }
        lines
    }
}

pub(super) fn option_editor_lines(
    app: &ShellApp,
    edit: &PlanningOptionEdit,
    area: Rect,
) -> Vec<Line<'static>> {
    let layout = EditorLayout::new(app, area);
    let width = area.width as usize;
    let mut lines = vec![
        divider(
            &format!("EDITING OPTION · {}", edit.task.tool_name()),
            area.width,
        ),
        option_identity(app, edit, width),
    ];
    lines.extend(crate::renderer::shared::field_editor_lines(
        &edit.field,
        width,
        layout.field_height,
    ));
    lines.extend(layout.error_lines(edit.error_scroll));
    lines.push(responsive_keybind_hint_line(
        width,
        &[("←/→", "cursor"), ("Enter", "save"), ("Esc", "cancel")],
        &[("Enter", "save"), ("Esc", "cancel")],
    ));
    lines
}

fn option_identity(app: &ShellApp, edit: &PlanningOptionEdit, width: usize) -> Line<'static> {
    let label = app
        .planning_option_spec(edit.task, &edit.option_name)
        .map(|spec| {
            format!(
                "{} · {}",
                option_display_name(&spec.name),
                option_input_kind(&spec)
            )
        })
        .unwrap_or_else(|| edit.option_name.clone());
    muted(&fit(&label, width))
}

pub(crate) fn planning_option_error_scroll(app: &ShellApp, direction: isize) -> Option<usize> {
    let edit = app.engagement.planning_picker().option_edit()?;
    app.engagement.planning_picker().option_error()?;
    let viewport = app.viewport();
    let area =
        crate::renderer::primary_body_area(app, Rect::new(0, 0, viewport.columns, viewport.rows));
    let layout = EditorLayout::new(app, area);
    let start = edit.error_scroll.min(layout.max_scroll());
    Some(
        start
            .saturating_add_signed(direction * layout.error_height as isize)
            .min(layout.max_scroll()),
    )
}
