use super::*;
use crate::ui_view_models::{permission_policy_model, PermissionPolicyModel, PermissionPolicyRow};

pub(crate) fn permission_policy_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.extend(permission_policy_document_lines(
        permission_policy_model(),
        area.width as usize,
    ));
    lines
}

fn permission_policy_document_lines(
    model: PermissionPolicyModel,
    width: usize,
) -> Vec<Line<'static>> {
    let mut lines = vec![divider(model.title, width as u16)];
    lines.extend(wrapped_line(" ", model.scope, width));
    for row in model.rows {
        push_policy_row(&mut lines, row, width);
    }
    lines.push(blank());
    lines.extend(wrapped_line(" NOTE  ", model.limitation, width));
    lines.push(blank());
    lines.push(command_list_line(model.next_commands, width));
    lines
}

fn push_policy_row(lines: &mut Vec<Line<'static>>, row: PermissionPolicyRow, width: usize) {
    lines.push(blank());
    lines.push(Line::raw(fit(
        &format!(" {}  [{}]", row.label, row.state),
        width,
    )));
    lines.extend(wrapped_line(" policy    ", row.policy, width));
    lines.extend(wrapped_line(" boundary  ", row.boundary, width));
}

fn wrapped_line(prefix: &str, value: &str, width: usize) -> Vec<Line<'static>> {
    let budget = width.saturating_sub(prefix.chars().count()).max(12);
    wrap_text(value, budget)
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| {
            let prefix = if index == 0 {
                prefix
            } else {
                &" ".repeat(prefix.chars().count())
            };
            Line::raw(format!("{prefix}{chunk}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_document_is_width_safe_and_names_real_enforcement_scope() {
        let width = 60;
        let rendered = permission_policy_document_lines(permission_policy_model(), width)
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>();
        let text = rendered.join("\n");
        let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");

        assert!(text.contains("PERMISSION POLICY"));
        assert!(text.contains("MODEL / RUNTIME  [ENFORCED]"));
        assert!(text.contains("SHELL RISK GATES  [PRE-DISPATCH]"));
        assert!(normalized.contains("not an OS sandbox"));
        assert!(rendered.iter().all(|line| line.chars().count() <= width));
    }
}
