use super::*;

pub(super) fn append_active_agent_turn(
    lines: &mut Vec<Line<'static>>,
    agent: &AgentChatSession,
    body_w: usize,
    width: u16,
) {
    lines.push(chat_bubble_header("  you  ", theme::accent(), width));
    for line in wrap_text(&agent.question, body_w) {
        lines.push(indent(styled(&line, theme::primary()), 3));
    }
    lines.push(blank());
    append_active_agent_response(lines, agent, body_w, width);
}

fn append_active_agent_response(
    lines: &mut Vec<Line<'static>>,
    agent: &AgentChatSession,
    body_w: usize,
    width: u16,
) {
    if let Some(error) = &agent.error {
        append_limited_agent_text(
            lines,
            " error ",
            error,
            body_w,
            width,
            theme::danger(),
            usize::MAX,
        );
    } else if let Some(answer) = &agent.answer {
        append_limited_agent_text(
            lines,
            " agent ",
            answer,
            body_w,
            width,
            theme::primary(),
            12,
        );
    } else if agent.abort_requested {
        lines.push(chat_bubble_header(" agent ", theme::success(), width));
        lines.push(indent(
            muted(
                "Abort requested; waiting for LangGraph to return. Process kill is not confirmed.",
            ),
            3,
        ));
    } else {
        lines.push(chat_bubble_header(" agent ", theme::success(), width));
        lines.push(indent(muted("…streaming"), 3));
    }
}

pub(super) fn append_limited_agent_text(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    text: &str,
    body_w: usize,
    width: u16,
    style: Style,
    limit: usize,
) {
    let header_style = if label.trim() == "error" {
        theme::danger()
    } else {
        theme::success()
    };
    lines.push(chat_bubble_header(label, header_style, width));
    for line in wrap_text(text, body_w).into_iter().take(limit) {
        lines.push(indent(styled(&line, style), 3));
    }
}
