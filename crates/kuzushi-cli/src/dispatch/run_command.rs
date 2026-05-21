use crate::application::run_tool::run_tool_command;
use crate::command::Command;
use anyhow::Result;
use std::path::PathBuf;

pub(super) fn dispatch_run_command(
    command: Command,
    default_target: Option<PathBuf>,
    load: Vec<String>,
    allow_untrusted_module: bool,
) -> Result<()> {
    match command {
        Command::Run {
            tool,
            input,
            options,
        } => run_tool_command(
            tool,
            input,
            options,
            default_target,
            load,
            allow_untrusted_module,
        ),
        _ => unreachable!("non-run command routed to run dispatcher"),
    }
}
