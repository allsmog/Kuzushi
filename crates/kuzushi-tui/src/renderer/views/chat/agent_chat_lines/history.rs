use super::*;

pub(super) fn append_agent_history(
    lines: &mut Vec<Line<'static>>,
    agent: &AgentChatSession,
    body_w: usize,
    width: u16,
) {
    for turn in &agent.history {
        lines.push(chat_bubble_header("  you  ", theme::accent(), width));
        for line in wrap_text(&turn.question, body_w) {
            lines.push(indent(styled(&line, theme::primary()), 3));
        }
        lines.push(blank());
        append_completed_agent_turn(lines, turn, body_w, width);
        lines.push(blank());
    }
}

fn append_completed_agent_turn(
    lines: &mut Vec<Line<'static>>,
    turn: &AgentChatTurn,
    body_w: usize,
    width: u16,
) {
    if let Some(error) = &turn.error {
        turn_text::append_limited_agent_text(
            lines,
            " error ",
            error,
            body_w,
            width,
            theme::danger(),
            6,
        );
    } else if let Some(answer) = &turn.answer {
        turn_text::append_limited_agent_text(
            lines,
            " agent ",
            answer,
            body_w,
            width,
            theme::primary(),
            6,
        );
    } else {
        lines.push(chat_bubble_header(" agent ", theme::success(), width));
        lines.push(indent(muted("(no answer)"), 3));
    }
}
