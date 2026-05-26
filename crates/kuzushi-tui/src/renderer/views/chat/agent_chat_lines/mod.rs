use super::*;
use crate::ui_view_models::{
    agent_chat_model, failure_handoff_model, AgentChatModel, AgentChatSession, AgentChatTurn,
    FailureHandoffModel,
};

mod history;
mod turn_text;

pub(crate) fn agent_chat_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());

    let model = agent_chat_model(app);
    let Some(agent) = &model.session else {
        append_agent_empty_state(&mut lines, area.width);
        return lines;
    };
    lines.push(divider("AGENT", area.width));
    append_agent_status(&mut lines, &model);

    let body_w = area.width.saturating_sub(3) as usize;
    append_failure_handoff_panel(&mut lines, agent, body_w, area.width);
    history::append_agent_history(&mut lines, agent, body_w, area.width);
    turn_text::append_active_agent_turn(&mut lines, agent, body_w, area.width);

    lines.push(blank());
    lines.push(command_list_line(
        &["ask <question>", "?text", "model provider:model-id", "back"],
        area.width as usize,
    ));
    lines
}

pub(crate) fn failure_handoff_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines = context_strip(app, area);
    lines.push(blank());
    lines.push(divider("FAILURE HANDOFF", area.width));
    let body_w = area.width.saturating_sub(3) as usize;

    if let Some(model) = failure_handoff_model(app) {
        append_failure_rows(&mut lines, &model, body_w);
    } else {
        append_failure_empty_state(&mut lines);
    }

    lines.push(blank());
    lines.push(command_list_line(
        &["ask <question>", "runs", "replay <run>", "back"],
        area.width as usize,
    ));
    lines
}

fn append_failure_empty_state(lines: &mut Vec<Line<'static>>) {
    lines.extend(empty_state_panel(
        "no failure handoff loaded",
        &[
            "partial and failed tool runs create bounded handoff context.",
            "the next agent question inherits that context once.",
        ],
        &[
            ("runs", "inspect recent run artifacts"),
            ("activity", "watch current module progress"),
            (
                "ask <question>",
                "next /ask inherits this failure context once",
            ),
        ],
    ));
}

fn append_agent_empty_state(lines: &mut Vec<Line<'static>>, width: u16) {
    lines.push(divider("AGENT · empty", width));
    lines.extend(empty_state_panel(
        "no question yet",
        &[
            "agent chat dispatches a single question through LangGraph.",
            "tools and findings are read-only; the chat doesn't write to disk.",
        ],
        &[
            ("ask <question>", "explicit agent route"),
            ("?<text>", "always-on agent route from any view"),
            ("model <provider:id>", "pick the model the agent will use"),
        ],
    ));
}

fn append_agent_status(lines: &mut Vec<Line<'static>>, model: &AgentChatModel) {
    let status = model
        .session
        .as_ref()
        .map(|agent| agent.status)
        .unwrap_or("idle");
    lines.push(detail("mode", "agent chat"));
    lines.push(detail("status", status));
    lines.push(detail("model", &model.model));
    lines.push(blank());
}

fn append_failure_handoff_panel(
    lines: &mut Vec<Line<'static>>,
    agent: &AgentChatSession,
    body_w: usize,
    width: u16,
) {
    let Some(context) = &agent.failure_context else {
        return;
    };
    lines.push(divider("FAILURE HANDOFF", width));
    append_failure_rows(lines, context, body_w);
    lines.push(blank());
}

fn append_failure_rows(lines: &mut Vec<Line<'static>>, model: &FailureHandoffModel, body_w: usize) {
    for row in &model.rows {
        append_failure_detail(lines, row.label, &row.value, body_w);
    }
}

fn append_failure_detail(lines: &mut Vec<Line<'static>>, key: &str, value: &str, body_w: usize) {
    for (index, segment) in wrap_text(value, body_w).into_iter().enumerate() {
        let label = if index == 0 { key } else { "" };
        lines.push(detail(label, &segment));
    }
}
