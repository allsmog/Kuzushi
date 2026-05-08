use super::*;

pub(crate) fn with_next_step(message: impl Into<String>, next: &str) -> String {
    let message = message.into();
    if message.contains("Next:") {
        return message;
    }
    let separator = if message.ends_with('.') || message.ends_with('!') || message.ends_with('?') {
        " "
    } else {
        ". "
    };
    format!("{message}{separator}Next: {next}")
}

pub(crate) const ASK_SYSTEM_PROMPT: &str = r#"You are Kuzushi's Rust shell assistant.
Answer operator questions about the current repository and Kuzushi workflow.
Do not claim that scans, tools, or model work have run unless the prompt provides that evidence.
Prefer concrete next commands that are routed by the Rust shell."#;
