use super::*;
use crate::app::TargetCandidate;

pub(crate) fn target_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let intro = target_picker_intro(area.width);
    let consent = target_consent_lines(app, area.width);
    let footer = target_picker_footer(area.width);
    let candidate_budget = (area.height as usize)
        .saturating_sub(intro.len() + consent.len() + footer.len())
        .max(1);
    let mut lines = intro;
    lines.extend(target_candidate_window_lines(
        app,
        area.width,
        candidate_budget,
    ));
    lines.extend(consent);
    lines.extend(footer);
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

fn target_candidate_window_lines(
    app: &ShellApp,
    width: u16,
    line_budget: usize,
) -> Vec<Line<'static>> {
    let candidates = app.router.target_picker().candidates();
    let label_width = candidate_label_width(candidates);
    let show_window_label = candidates.len() > line_budget;
    let row_budget = line_budget
        .saturating_sub(usize::from(show_window_label))
        .max(1);
    let range = visible_candidate_range(
        candidates.len(),
        app.router.target_picker().cursor(),
        row_budget,
    );
    let mut lines = Vec::new();
    if show_window_label {
        lines.push(candidate_window_label(
            range.start,
            range.end,
            candidates.len(),
        ));
    }
    lines.extend(
        range.map(|index| target_picker_row(app, index, &candidates[index], label_width, width)),
    );
    lines
}

fn visible_candidate_range(
    total: usize,
    cursor: usize,
    row_budget: usize,
) -> std::ops::Range<usize> {
    let visible = row_budget.min(total).max(1);
    let centered = cursor.saturating_sub(visible / 2);
    let start = centered.min(total.saturating_sub(visible));
    start..(start + visible).min(total)
}

fn candidate_window_label(start: usize, end: usize, total: usize) -> Line<'static> {
    muted(&format!(
        " targets {}-{} of {} · ↑/↓ scroll",
        start + 1,
        end,
        total
    ))
}

fn target_consent_lines(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let Some(candidate) = app.router.target_picker().selected() else {
        return Vec::new();
    };
    vec![
        blank(),
        target_identity_line("Enter selects", &candidate.path, width as usize),
    ]
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
