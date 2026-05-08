use anyhow::Result;
use clap::Parser;

mod application;
mod auth_bridge;
mod auth_oauth;
mod auth_ping;
mod catalog_commands;
mod cli;
mod command;
mod config_commands;
mod dispatch;
mod doctor;
mod findings;
mod mcp;
mod permissions;
mod pr_comment;
mod presentation;
mod runs;
mod runs_output;
mod scan;
mod scan_budget;
mod scan_ci;
mod scan_output;
mod support;
mod suppressions;
mod terminal;
#[cfg(test)]
mod tests;
mod tool_requirements;
mod tool_run;
mod tool_run_artifacts;
mod wants_sast_runtime;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    let plain = terminal::plain_output_requested(cli.plain);
    let command = cli
        .command
        .unwrap_or(command::Command::Shell { target: None });
    dispatch::dispatch_command(command, cli.target, plain).await
}
