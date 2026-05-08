use super::*;

pub(crate) fn patch_lines(app: &ShellApp, area: Rect, alias: &str) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());

    let Some(patch) = app.pending_patch.as_ref().filter(|p| p.alias == alias) else {
        lines.push(divider(&format!("PATCH · {alias} · empty"), area.width));
        lines.extend(empty_state_panel(
            "no patch staged",
            &[
                "patches are produced by `patch:run` and staged under .kuzushi/runs/.",
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
        return lines;
    };

    // RATIONALE
    lines.push(divider(
        &format!("PATCH · {} · RATIONALE", patch.alias),
        area.width,
    ));
    for line in wrap_text(&patch.rationale, area.width.saturating_sub(3) as usize) {
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

    // DIFF
    let summary = patch_diff_summary(&patch.diff);
    lines.push(divider(
        &format!(
            "DIFF · {files} file{plural} · +{adds} −{dels}",
            files = summary.files,
            plural = if summary.files == 1 { "" } else { "s" },
            adds = summary.adds,
            dels = summary.dels,
        ),
        area.width,
    ));
    for line in patch_diff_lines(&patch.diff, area.width) {
        lines.push(line);
    }
    lines.push(blank());

    // TESTS
    if !patch.tests.is_empty() {
        lines.push(divider(
            &format!("TESTS · added · {}", patch.tests.len()),
            area.width,
        ));
        for (name, blurb) in &patch.tests {
            lines.push(Line::from(vec![
                Span::raw("   "),
                Span::styled(" ✓ ", theme::success()),
                Span::styled(name.clone(), theme::primary()),
                Span::raw("  "),
                Span::styled(blurb.clone(), theme::muted()),
            ]));
        }
        lines.push(blank());
    }

    // GUARDRAIL
    if let Some(guard) = &patch.guardrail {
        lines.push(divider("GUARDRAIL", area.width));
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
            area.width as usize,
        ));
        lines.push(blank());
    }

    if let Some(staged) = &patch.staged_at {
        lines.push(Line::from(vec![
            Span::styled(" staged at ", theme::muted()),
            Span::styled(staged.clone(), theme::primary()),
        ]));
    }
    lines
}
