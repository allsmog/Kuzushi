use anyhow::Result;
use clap::Parser;

mod adapters;
mod application;
mod cli;
mod command;
mod dispatch;
mod doctor;
mod mcp;
mod presentation;
mod scan_budget;
mod support;
#[cfg(test)]
mod tests;
mod tool_requirements;
mod tool_run_artifacts;

pub async fn run() -> Result<()> {
    let cli = cli::Cli::parse();
    let plain = presentation::plain_output_requested(cli.plain);
    let command = cli
        .command
        .unwrap_or(command::Command::Shell { target: None });
    dispatch::dispatch_command(command, cli.target, plain, cli.load).await
}
