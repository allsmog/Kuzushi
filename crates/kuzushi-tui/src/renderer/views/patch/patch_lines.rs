use super::*;
use crate::ui_view_models::{
    patch_review_model, ui_runs_root_relative_path, PatchReviewModel, PatchReviewTestRow,
};

pub(crate) fn patch_lines(app: &ShellApp, area: Rect, alias: &str) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());

    let Some(patch) = patch_review_model(app, alias) else {
        push_empty_patch_lines(&mut lines, alias, area.width);
        return lines;
    };

    push_rationale_lines(&mut lines, &patch, area.width);
    push_diff_lines(&mut lines, &patch, area.width);
    push_tests_lines(&mut lines, &patch, area.width);
    push_guardrail_lines(&mut lines, &patch, area.width);
    push_staged_line(&mut lines, &patch);
    lines
}

fn push_empty_patch_lines(lines: &mut Vec<Line<'static>>, alias: &str, width: u16) {
    lines.push(divider(&format!("PATCH · {alias} · empty"), width));
    let staged_detail = format!(
        "patches are produced by `patch:run` and staged under {}/.",
        ui_runs_root_relative_path()
    );
    lines.extend(empty_state_panel(
        "no patch staged",
        &[
            staged_detail.as_str(),
            "the operator approves with /patch apply or rejects with /patch reject.",
        ],
        &[
            ("use patch", "focus the patch module"),
            (
                "run patch:run --finding F-…",
                "stage a patch for a verified finding",
            ),
            ("findings", "browse persisted findings to pick one"),
        ],
    ));
}

fn push_rationale_lines(lines: &mut Vec<Line<'static>>, patch: &PatchReviewModel, width: u16) {
    lines.push(divider(
        &format!("PATCH · {} · RATIONALE", patch.alias),
        width,
    ));
    for line in wrap_text(&patch.rationale, width.saturating_sub(3) as usize) {
        lines.push(indent(styled(&line, theme::primary()), 3));
    }
    if let Some(side) = &patch.side_effect {
        lines.push(indent(
            Line::from(vec![
                Span::styled("side-effect: ", theme::muted()),
                Span::styled(side.clone(), theme::primary()),
            ]),
            3,
        ));
    }
    lines.push(blank());
}

fn push_diff_lines(lines: &mut Vec<Line<'static>>, patch: &PatchReviewModel, width: u16) {
    let summary = patch_diff_summary(&patch.diff);
    lines.push(divider(
        &format!(
            "DIFF · {files} file{plural} · +{adds} −{dels}",
            files = summary.files,
            plural = if summary.files == 1 { "" } else { "s" },
            adds = summary.adds,
            dels = summary.dels,
        ),
        width,
    ));
    for line in patch_diff_lines(&patch.diff, width) {
        lines.push(line);
    }
    lines.push(blank());
}

fn push_tests_lines(lines: &mut Vec<Line<'static>>, patch: &PatchReviewModel, width: u16) {
    if patch.tests.is_empty() {
        return;
    }
    lines.push(divider(
        &format!("TESTS · added · {}", patch.tests.len()),
        width,
    ));
    for test in &patch.tests {
        lines.push(test_line(test));
    }
    lines.push(blank());
}

fn test_line(test: &PatchReviewTestRow) -> Line<'static> {
    Line::from(vec![
        Span::raw("   "),
        Span::styled(" ✓ ", theme::success()),
        Span::styled(test.name.clone(), theme::primary()),
        Span::raw("  "),
        Span::styled(test.blurb.clone(), theme::muted()),
    ])
}

fn push_guardrail_lines(lines: &mut Vec<Line<'static>>, patch: &PatchReviewModel, width: u16) {
    if let Some(guard) = &patch.guardrail {
        lines.push(divider("GUARDRAIL", width));
        lines.push(Line::from(vec![
            Span::raw("   "),
            Span::styled(" ! ", theme::warn()),
            Span::raw(" "),
            Span::styled(guard.clone(), theme::primary()),
            Span::styled(
                " — patch is staged, NOT applied".to_string(),
                theme::muted(),
            ),
        ]));
        lines.push(command_list_line(
            &[
                "/patch apply",
                "/patch reject",
                "/patch regen --style defensive",
            ],
            width as usize,
        ));
        lines.push(blank());
    }
}

fn push_staged_line(lines: &mut Vec<Line<'static>>, patch: &PatchReviewModel) {
    if let Some(staged) = &patch.staged_at {
        lines.push(Line::from(vec![
            Span::styled(" staged at ", theme::muted()),
            Span::styled(staged.clone(), theme::primary()),
        ]));
    }
}
