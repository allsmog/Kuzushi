use super::*;
use crate::ui_view_models::failure_handoff_context;
use kuzushi_core::run_artifacts::FailureToLlmContext;

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

    if let Some(context) = failure_handoff_context(app) {
        append_failure_identity(&mut lines, &context, body_w);
        append_failure_artifacts(&mut lines, &context, body_w);
        append_failure_recovery(&mut lines, &context, body_w);
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

fn current_failure_context(app: &ShellApp) -> Option<&FailureToLlmContext> {
    app.agent_chat
        .as_ref()
        .and_then(|agent| agent.failure_context.as_ref())
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
            ("ask <question>", "continue with the agent"),
        ],
    ));
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
        &app.config
            .model
            .as_deref()
            .map(crate::app::display_model_selector)
            .unwrap_or_else(|| "unconfigured".to_string()),
    ));
    lines.push(blank());
}

fn append_failure_handoff_panel(
    lines: &mut Vec<Line<'static>>,
    agent: &AgentChatView,
    body_w: usize,
    width: u16,
) {
    let Some(context) = &agent.failure_context else {
        return;
    };
    lines.push(divider("FAILURE HANDOFF", width));
    append_failure_identity(lines, context, body_w);
    append_failure_artifacts(lines, context, body_w);
    append_failure_recovery(lines, context, body_w);
    lines.push(blank());
}

fn append_failure_identity(
    lines: &mut Vec<Line<'static>>,
    context: &FailureToLlmContext,
    body_w: usize,
) {
    append_failure_detail(
        lines,
        "stage",
        failure_text(&context.failed_stage, "unknown"),
        body_w,
    );
    append_failure_detail(
        lines,
        "cause",
        failure_text(&context.cause, "unknown"),
        body_w,
    );
    append_failure_detail(lines, "proof", context.allowed_proof_level.clone(), body_w);
}

fn append_failure_artifacts(
    lines: &mut Vec<Line<'static>>,
    context: &FailureToLlmContext,
    body_w: usize,
) {
    append_failure_detail(
        lines,
        "available",
        format!("{} artifact(s)", context.artifacts_available.len()),
        body_w,
    );
    append_failure_detail(
        lines,
        "missing",
        failure_list(&context.missing_artifacts),
        body_w,
    );
    append_failure_detail(
        lines,
        "next",
        failure_list(&context.next_files_or_artifacts_to_inspect),
        body_w,
    );
}

fn append_failure_recovery(
    lines: &mut Vec<Line<'static>>,
    context: &FailureToLlmContext,
    body_w: usize,
) {
    append_failure_detail(
        lines,
        "recovery",
        context.recovery_options.join(" | "),
        body_w,
    );
    append_failure_detail(
        lines,
        "forbidden",
        failure_list(&context.claims_forbidden),
        body_w,
    );
    append_failure_detail(lines, "prompt", context.fallback_prompt.clone(), body_w);
}

fn append_failure_detail(lines: &mut Vec<Line<'static>>, key: &str, value: String, body_w: usize) {
    for (index, segment) in wrap_text(&value, body_w).into_iter().enumerate() {
        let label = if index == 0 { key } else { "" };
        lines.push(detail(label, &segment));
    }
}

fn failure_text(value: &str, fallback: &str) -> String {
    if value.trim().is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

fn failure_list(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
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
