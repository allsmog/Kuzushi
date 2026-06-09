use super::*;
use crate::app::{auth_ready_for_provider, visible_model_choices, ModelChoice};

pub(crate) fn model_picker_lines(app: &ShellApp, area: Rect) -> Vec<Line<'static>> {
    let mut lines: Vec<Line<'static>> = vec![
        divider("CHOOSE A MODEL", area.width),
        blank(),
        muted("Kuzushi does not silently pick a model for you. Select one to continue."),
        blank(),
    ];
    for (idx, choice) in visible_model_choices(app.config.model.as_deref())
        .iter()
        .enumerate()
    {
        lines.push(model_picker_row(app, idx, choice, area.width));
    }
    lines.push(blank());
    lines.push(keybind_hint_line(&[
        ("↑/↓", "move"),
        ("Enter", "confirm"),
        ("Esc", "defer (you'll need to /model later)"),
    ]));
    lines
}

fn model_picker_row(app: &ShellApp, idx: usize, choice: &ModelChoice, width: u16) -> Line<'static> {
    let marker = if idx == app.model_picker_cursor {
        ">"
    } else {
        " "
    };
    let auth_hint = auth_hint_for(choice);
    let body = format!(
        "  {marker} {label}   {provider}/{thinking}   {auth_hint}",
        label = choice.label,
        provider = crate::app::display_model_provider(choice.provider),
        thinking = choice.thinking_level,
    );
    let style = if idx == app.model_picker_cursor {
        theme::success().add_modifier(Modifier::BOLD)
    } else {
        theme::primary()
    };
    Line::styled(fit(&body, width as usize), style)
}

fn auth_hint_for(choice: &ModelChoice) -> String {
    match choice.provider {
        "anthropic" => {
            if auth_ready_for_provider("anthropic") {
                "auth ready".to_string()
            } else {
                "auth required".to_string()
            }
        }
        "openai" => {
            if auth_ready_for_provider("openai") {
                "API key ready".to_string()
            } else {
                "needs OPENAI_API_KEY or OAuth".to_string()
            }
        }
        "openai-codex" => {
            if auth_ready_for_provider("openai-codex") {
                "OAuth stored".to_string()
            } else {
                "needs OpenAI OAuth login".to_string()
            }
        }
        other => format!("provider {other}"),
    }
}
