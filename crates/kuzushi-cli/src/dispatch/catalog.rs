use crate::application::auth::auth_command;
use crate::application::catalog::{modules_command, tools_command};
use crate::application::config::config_command;
use crate::command::Command;
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
