use super::*;
use crate::app::TargetCandidate;

pub(crate) fn target_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let intro = target_picker_intro(area.width);
    let consent = target_consent_lines(app, area.width);
    let footer = target_picker_footer(area.width);
    if intro.len() + consent.len() + footer.len() + 1 > area.height as usize {
        return compact_target_picker_lines(app, area);
    }
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

fn compact_target_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = vec![
        divider("CHOOSE A TARGET", area.width),
        muted(&fit(
            "Pick explicitly · cwd is never assumed",
            area.width as usize,
        )),
    ];
    let consent = compact_target_consent_line(app, area.width);
    let footer = compact_target_footer();
    let fixed_rows = lines.len() + consent.len() + footer.len();
    let candidate_budget = (area.height as usize).saturating_sub(fixed_rows).max(1);
    lines.extend(target_candidate_window_lines(
        app,
        area.width,
        candidate_budget,
    ));
    lines.extend(consent);
    lines.extend(footer);
    lines
}

fn compact_target_consent_line(app: &ShellApp, width: u16) -> Vec<Line<'static>> {
    let mut lines = app
        .router
        .target_picker()
        .selected()
        .map(|candidate| target_identity_line("Enter selects", &candidate.path, width as usize))
        .into_iter()
        .collect::<Vec<_>>();
    if let Some(facts) = app.router.target_picker().facts() {
        lines.push(muted(&fit(
            &format!(
                " {} · {}{} files · {} scope(s) · {} prior artifact(s)",
                facts.repository_kind,
                facts.file_count,
                if facts.file_count_capped { "+" } else { "" },
                facts.nested_scopes.len(),
                facts.prior_artifact_count,
            ),
            width as usize,
        )));
    }
    lines
}

fn compact_target_footer() -> Vec<Line<'static>> {
    vec![
        muted(" ↑/↓ move · Enter select · d demo"),
        muted(" Esc browse · : command"),
    ]
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
    let mut lines = vec![
        blank(),
        target_identity_line("Enter selects", &candidate.path, width as usize),
    ];
    lines.extend(target_fact_lines(app, width as usize));
    lines
}

fn target_fact_lines(app: &ShellApp, width: usize) -> Vec<Line<'static>> {
    if app.router.target_picker().facts_loading() {
        return vec![muted(" Inspecting selected target…")];
    }
    let Some(facts) = app.router.target_picker().facts() else {
        return Vec::new();
    };
    let labels = target_fact_labels(facts);
    vec![
        muted(&fit(
            &format!(
                " {} · {}@{} · {} · {}",
                facts.repository_kind, labels.branch, labels.revision, labels.dirty, labels.files
            ),
            width,
        )),
        muted(&fit(
            &format!(" {} · {}", labels.languages, labels.builds),
            width,
        )),
        muted(&fit(
            &format!(" {} · {}", labels.scopes, labels.prior),
            width,
        )),
    ]
}

struct TargetFactLabels {
    branch: String,
    revision: String,
    dirty: &'static str,
    files: String,
    languages: String,
    builds: String,
    scopes: String,
    prior: String,
}

fn target_fact_labels(facts: &crate::app::TargetCandidateFacts) -> TargetFactLabels {
    TargetFactLabels {
        branch: facts
            .branch
            .clone()
            .unwrap_or_else(|| "detached/non-git".to_string()),
        revision: facts
            .revision
            .as_deref()
            .map(|sha| sha.chars().take(10).collect())
            .unwrap_or_else(|| "-".to_string()),
        dirty: facts
            .dirty
            .map(|value| if value { "dirty" } else { "clean" })
            .unwrap_or("n/a"),
        files: format!(
            "{}{} files",
            facts.file_count,
            if facts.file_count_capped { "+" } else { "" }
        ),
        languages: joined_fact_label("languages", &facts.languages, "detecting"),
        builds: joined_fact_label("build", &facts.build_systems, "none detected"),
        scopes: joined_fact_label("nested scopes", &facts.nested_scopes, "none"),
        prior: prior_artifact_label(facts),
    }
}

fn joined_fact_label(label: &str, values: &[String], empty: &str) -> String {
    if values.is_empty() {
        format!("{label}: {empty}")
    } else {
        format!("{label}: {}", values.join(", "))
    }
}

fn prior_artifact_label(facts: &crate::app::TargetCandidateFacts) -> String {
    if facts.prior_artifacts.is_empty() {
        return "prior Kuzushi: none".to_string();
    }
    format!(
        "prior Kuzushi: {} artifact(s) · {}",
        facts.prior_artifact_count,
        facts.prior_artifacts.join(", ")
    )
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
