use crate::auth_ping::auth_command;
use crate::catalog_commands::{modules_command, tools_command};
use crate::command::Command;
use crate::config_commands::config_command;
use anyhow::Result;
use std::path::PathBuf;

pub(super) fn dispatch_catalog_command(
    command: Command,
    default_target: Option<PathBuf>,
) -> Result<()> {
    match command {
        Command::Config { command } => config_command(command, default_target.clone()),
        Command::Auth { command } => auth_command(command, default_target),
        Command::Modules { json } => modules_command(json),
        Command::Tools { json } => tools_command(json),
        _ => unreachable!("non-catalog command routed to catalog dispatcher"),
    }
}
