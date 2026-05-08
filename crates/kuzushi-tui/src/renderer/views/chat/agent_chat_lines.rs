use super::*;

pub(crate) fn agent_chat_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
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
