use super::*;
use crate::app::TargetCandidate;

pub(crate) fn target_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(divider("CHOOSE A TARGET", area.width));
    lines.push(blank());
    lines.push(muted(
        "Kuzushi anchors scans, findings, and artifacts to a target directory.",
    ));
    lines.push(muted(
        "Nothing defaults to cwd silently — pick it, a repo, or a submodule explicitly.",
    ));
    lines.push(blank());
    let candidates = app.router.target_picker().candidates();
    let label_width = candidate_label_width(candidates);
    for (idx, candidate) in candidates.iter().enumerate() {
        lines.push(target_picker_row(
            app,
            idx,
            candidate,
            label_width,
            area.width,
        ));
    }
    lines.push(blank());
    lines.push(muted("any other directory: Esc, then `target <path>`"));
    lines.push(muted(
        "no repo or no key yet: press `d` for the offline fixture",
    ));
    lines.push(blank());
    lines.push(keybind_hint_line(&[
        ("↑/↓/j/k", "move"),
        (":", "type a command"),
        ("d", "offline fixture"),
        ("Enter", "select"),
        ("Esc/q", "browse without a target"),
    ]));
    lines
}

fn candidate_label_width(candidates: &[TargetCandidate]) -> usize {
    candidates
        .iter()
        .map(|candidate| candidate.label.chars().count())
        .max()
        .unwrap_or(0)
}

fn target_picker_row(
    app: &ShellApp,
    idx: usize,
    candidate: &TargetCandidate,
    label_width: usize,
    width: u16,
) -> Line<'static> {
    let marker = if idx == app.router.target_picker().cursor() {
        ">"
    } else {
        " "
    };
    let body = format!(
        "  {marker} {label:<label_width$}   {hint}",
        label = candidate.label,
        hint = candidate_hint(candidate),
    );
    let style = if idx == app.router.target_picker().cursor() {
        theme::success().add_modifier(Modifier::BOLD)
    } else {
        theme::primary()
    };
    Line::styled(fit(&body, width as usize), style)
}

fn candidate_hint(candidate: &TargetCandidate) -> String {
    candidate
        .scope
        .as_ref()
        .map(|scope| format!("{} · scope:{}", candidate.hint, scope.id))
        .unwrap_or_else(|| candidate.hint.to_string())
}
