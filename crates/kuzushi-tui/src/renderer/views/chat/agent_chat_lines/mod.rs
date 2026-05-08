use super::*;

mod history;
mod turn_text;

pub(crate) fn agent_chat_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());

    let Some(agent) = &app.agent_chat else {
        append_agent_empty_state(&mut lines, area.width);
        return lines;
    };
    lines.push(divider("AGENT", area.width));
    append_agent_status(&mut lines, app, agent);

    let body_w = area.width.saturating_sub(3) as usize;
    history::append_agent_history(&mut lines, agent, body_w, area.width);
    turn_text::append_active_agent_turn(&mut lines, agent, body_w, area.width);

    lines.push(blank());
    lines.push(command_list_line(
        &["ask <question>", "?text", "model provider:model-id", "back"],
        area.width as usize,
    ));
    lines
}

fn append_agent_empty_state(lines: &mut Vec<Line<'static>>, width: u16) {
    lines.push(divider("AGENT · empty", width));
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
}

fn append_agent_status(lines: &mut Vec<Line<'static>>, app: &ShellApp, agent: &AgentChatView) {
    let status = agent_status_label(agent);
    lines.push(detail("mode", "agent chat"));
    lines.push(detail("status", status));
    lines.push(detail(
        "model",
        app.config.model.as_deref().unwrap_or("unconfigured"),
    ));
    lines.push(blank());
}

fn agent_status_label(agent: &AgentChatView) -> &'static str {
    if agent.abort_requested {
        "abort requested"
    } else if agent.running {
        "running"
    } else if agent.error.is_some() {
        "failed"
    } else {
        "answered"
    }
}
