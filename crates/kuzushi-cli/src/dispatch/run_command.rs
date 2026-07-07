use crate::application::run_tool::run_tool_command;
use crate::command::Command;
use anyhow::Result;
use std::path::PathBuf;

pub(super) fn dispatch_run_command(
    command: Command,
    default_target: Option<PathBuf>,
    load: Vec<String>,
) -> Result<()> {
    match command {
        Command::Run {
            tool,
            input,
            options,
        } => run_tool_command(tool, input, options, default_target, load),
        _ => unreachable!("non-run command routed to run dispatcher"),
    }
}
