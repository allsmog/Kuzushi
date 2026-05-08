use crate::command::Command;
use crate::tool_run::run_tool_command;
use anyhow::Result;
use std::path::PathBuf;

pub(super) fn dispatch_run_command(
    command: Command,
    default_target: Option<PathBuf>,
) -> Result<()> {
    match command {
        Command::Run { tool, input } => run_tool_command(tool, input, default_target),
        _ => unreachable!("non-run command routed to run dispatcher"),
    }
}
