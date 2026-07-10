use super::*;
use crate::app::TargetCandidate;

pub(crate) fn target_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = target_picker_intro(area.width);
    lines.extend(target_candidate_lines(app, area.width));
    lines.extend(target_picker_footer(area.width));
    lines
}

fn target_picker_intro(width: u16) -> Vec<Line<'static>> {
    let mut lines = vec![divider("CHOOSE A TARGET", width), blank()];
    lines.extend(
        wrap_text(
            "Kuzushi anchors scans, findings, and artifacts to a target directory.",
            width as usize,
        )
        .into_iter()
        .map(|line| muted(&line)),
    );
    lines.extend(
        wrap_text(
            "Nothing defaults to cwd silently — pick it, a repo, or a persisted scope explicitly.",
            width as usize,
        )
        .into_iter()
        .map(|line| muted(&line)),
    );
    lines.push(blank());
    lines
}

fn target_candidate_lines(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let candidates = app.router.target_picker().candidates();
    let label_width = candidate_label_width(candidates);
    candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| target_picker_row(app, index, candidate, label_width, width))
        .collect()
}

fn target_picker_footer(width: u16) -> Vec<Line<'static>> {
    let mut lines = vec![blank()];
    lines.extend(
        wrap_text(
            "any other directory: Esc, then `target <path>`",
            width as usize,
        )
        .into_iter()
        .map(|line| muted(&line)),
    );
    lines.extend(
        wrap_text(
            "no repo or no key yet: press `d` for the offline fixture",
            width as usize,
        )
        .into_iter()
        .map(|line| muted(&line)),
    );
    lines.push(blank());
    lines.push(responsive_keybind_hint_line(
        width as usize,
        &[
            ("↑/↓/j/k", "move"),
            (":", "type a command"),
            ("d", "offline fixture"),
            ("Enter", "select"),
            ("Esc/q", "browse without a target"),
        ],
        &[
            ("↑/↓", "move"),
            ("Enter", "select"),
            ("d", "demo"),
            ("Esc", "browse"),
        ],
    ));
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
    let body = format!(
        "{label:<label_width$}   {hint}",
        label = candidate.label,
        hint = candidate_hint(candidate),
    );
    selection_band(
        &body,
        idx == app.router.target_picker().cursor(),
        width as usize,
    )
}

fn candidate_hint(candidate: &TargetCandidate) -> String {
    candidate
        .scope
        .as_ref()
        .map(|scope| format!("{} · scope:{}", candidate.hint, scope.id))
        .unwrap_or_else(|| candidate.hint.to_string())
}
