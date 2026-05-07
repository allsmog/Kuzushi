use super::*;

pub(in crate::renderer) fn chat_bubble_header(
    tag: &str,
    tag_style: Style,
    width: u16,
) -> Line<'static> {
    let safe_width = width.max(8) as usize;
    let used = 1 + tag.chars().count() + 2;
    let fill = safe_width.saturating_sub(used).max(1);
    Line::from(vec![
        Span::raw(" "),
        Span::styled(tag.to_string(), tag_style),
        Span::raw(" "),
        Span::styled(theme::RULE_CHAR.repeat(fill), theme::subtle()),
    ])
}

/// Render a single `█████░░░░░░ N/total` rollup bar matching
/// `design/mockups/workspace.jsx::rollupBar`. Bar is 28 cells wide, with
/// the filled portion in the severity tint and the unfilled portion in
/// `theme::subtle()`.

pub(in crate::renderer) fn agent_chat_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());

    let Some(agent) = &app.agent_chat else {
        // No question yet — render the mockup empty-state panel so the
        // operator sees how to start a chat instead of a flat
        // `No active question.` muted line.
        lines.push(divider("AGENT · empty", area.width));
        lines.extend(empty_state_panel(
            "no question yet",
            &[
                "agent chat dispatches a single question through pi-agent-core.",
                "tools and findings are read-only; the chat doesn't write to disk.",
            ],
            &[
                ("ask <question>", "explicit agent route"),
                ("?<text>", "always-on agent route from any view"),
                ("model <provider:id>", "pick the model the agent will use"),
            ],
        ));
        return lines;
    };
    lines.push(divider("AGENT", area.width));

    let status = if agent.abort_requested {
        "abort requested"
    } else if agent.running {
        "running"
    } else if agent.error.is_some() {
        "failed"
    } else {
        "answered"
    };
    lines.push(detail("mode", "agent chat"));
    lines.push(detail("status", status));
    lines.push(detail(
        "model",
        app.config.model.as_deref().unwrap_or("unconfigured"),
    ));
    lines.push(blank());
    // Multi-turn bubbles: render `agent.history` (oldest first) before
    // the active turn so the operator sees the full conversation per
    // `design/mockups/agent-chat.jsx::bubble`.  Each prior turn is
    // rendered with a max of 6 answer lines so a long session doesn't
    // blow the viewport — full text remains in the underlying log.
    let body_w = area.width.saturating_sub(3) as usize;
    for turn in &agent.history {
        lines.push(chat_bubble_header("  you  ", theme::accent(), area.width));
        for line in wrap_text(&turn.question, body_w) {
            lines.push(indent(styled(&line, theme::primary()), 3));
        }
        lines.push(blank());
        if let Some(error) = &turn.error {
            lines.push(chat_bubble_header(" error ", theme::danger(), area.width));
            for line in wrap_text(error, body_w).into_iter().take(6) {
                lines.push(indent(styled(&line, theme::danger()), 3));
            }
        } else if let Some(answer) = &turn.answer {
            lines.push(chat_bubble_header(" agent ", theme::success(), area.width));
            for line in wrap_text(answer, body_w).into_iter().take(6) {
                lines.push(indent(styled(&line, theme::primary()), 3));
            }
        } else {
            lines.push(chat_bubble_header(" agent ", theme::success(), area.width));
            lines.push(indent(muted("(no answer)"), 3));
        }
        lines.push(blank());
    }

    // Active turn — full bubble with up to 12 answer lines.
    lines.push(chat_bubble_header("  you  ", theme::accent(), area.width));
    for line in wrap_text(&agent.question, body_w) {
        lines.push(indent(styled(&line, theme::primary()), 3));
    }
    lines.push(blank());

    if let Some(error) = &agent.error {
        lines.push(chat_bubble_header(" error ", theme::danger(), area.width));
        for line in wrap_text(error, body_w) {
            lines.push(indent(styled(&line, theme::danger()), 3));
        }
    } else if let Some(answer) = &agent.answer {
        lines.push(chat_bubble_header(" agent ", theme::success(), area.width));
        for line in wrap_text(answer, body_w).into_iter().take(12) {
            lines.push(indent(styled(&line, theme::primary()), 3));
        }
    } else if agent.abort_requested {
        lines.push(chat_bubble_header(" agent ", theme::success(), area.width));
        lines.push(indent(
            muted("Abort requested; waiting for pi-agent-core to return. Process kill is not confirmed."),
            3,
        ));
    } else {
        lines.push(chat_bubble_header(" agent ", theme::success(), area.width));
        lines.push(indent(muted("…streaming"), 3));
    }

    lines.push(blank());
    lines.push(command_list_line(
        &["ask <question>", "?text", "model provider:model-id", "back"],
        area.width as usize,
    ));
    lines
}

pub(in crate::renderer) fn history_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("COMMAND HISTORY", area.width));

    let entries = app
        .command_history
        .iter()
        .rev()
        .take(50)
        .collect::<Vec<_>>();
    if entries.is_empty() {
        lines.extend(empty_state_panel(
            "no commands run yet",
            &[
                "session history records every operator-typed command line.",
                "type something at the prompt and it will land here.",
            ],
            &[
                ("help", "browse the full command catalog"),
                ("modules", "see what's loaded"),
                ("scan .", "smallest one-shot run"),
            ],
        ));
    } else {
        let start = app.command_history.len().saturating_sub(entries.len()) + 1;
        let width = (start + entries.len()).to_string().len();
        for (offset, command) in entries.into_iter().rev().enumerate() {
            lines.push(row(&[
                format!("{:>width$}", start + offset, width = width),
                fit(command, area.width.saturating_sub(8) as usize),
            ]));
        }
    }

    lines.push(blank());
    lines.push(command_list_line(
        &["clear", "run <tool>", "show runs", "back"],
        area.width as usize,
    ));
    lines
}

pub(in crate::renderer) fn story_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("SESSION STORY · live event timeline", area.width));
    if let Some(scan) = &app.scan {
        let label = if scan.running {
            if scan.abort_requested {
                "abort requested"
            } else if app.is_scan_paused() {
                "paused"
            } else {
                "running"
            }
        } else {
            "idle"
        };
        lines.push(row(&[
            pad("scan", 10),
            fit(
                &format!(
                    "{label} · stage={} · findings={}",
                    scan.stage, scan.findings_count
                ),
                area.width.saturating_sub(14) as usize,
            ),
        ]));
    }
    lines.push(blank());

    let max_events = (area.height as usize).saturating_sub(8).max(8);
    let events = app
        .log
        .iter()
        .filter(|line| line.prefix != ">")
        .rev()
        .take(max_events)
        .collect::<Vec<_>>();
    if events.is_empty() {
        lines.extend(empty_state_panel(
            "no session events yet",
            &[
                "the timeline replays prior scan / agent / module events.",
                "run something to populate it.",
            ],
            &[
                ("scan <target>", "umbrella scan against a workspace"),
                ("ask <question>", "single-shot agent question"),
                ("run <tool>", "dispatch a registered tool"),
            ],
        ));
    } else {
        for line in events.into_iter().rev() {
            let body_width = area.width.saturating_sub(14) as usize;
            lines.push(row(&[pad(&line.prefix, 10), fit(&line.body, body_width)]));
        }
    }

    lines.push(blank());
    lines.push(command_list_line(
        &[
            "Ctrl+O toggle",
            "/history commands",
            "/show runs",
            "/replay <runId>",
            "/trace <runId>",
        ],
        area.width as usize,
    ));
    lines
}
