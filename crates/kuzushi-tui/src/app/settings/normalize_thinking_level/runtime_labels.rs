use super::*;

pub(crate) fn runtime_backend_label(config: &V2Config) -> &'static str {
    match config.runtime.kind {
        RuntimeKind::LangGraph => "LangGraph",
    }
}

pub(crate) fn bridge_command_status(config: &V2Config) -> &'static str {
    if config
        .runtime
        .langgraph_bridge_command
        .as_ref()
        .is_some_and(|command| !command.is_empty())
    {
        "configured"
    } else {
        "bundled/default"
    }
}
