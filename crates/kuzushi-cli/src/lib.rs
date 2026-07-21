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
    let argv = std::env::args().skip(1).collect();
    let cli = cli::Cli::parse();
    let plain = presentation::plain_output_requested(cli.plain);
    let command = cli
        .command
        .unwrap_or(command::Command::Shell { target: None });
    let result = dispatch::dispatch_command(
        command,
        cli.target,
        plain,
        cli.load,
        cli.no_session_persistence,
        argv,
    )
    .await;
    application::config_diagnostics::emit_runtime_diagnostics();
    exit_with_batch_code_on_typed_run_failure(result)
}

/// `kuzushi run` batch contract: a typed run failure exits with its
/// deterministic code (2 prepare, 3 failed, 4 partial) instead of the
/// generic anyhow 1. Mapped only here so in-process callers keep plain
/// `Err` semantics.
fn exit_with_batch_code_on_typed_run_failure(result: Result<()>) -> Result<()> {
    let Err(error) = result else {
        return Ok(());
    };
    if let Some(exit) = error.downcast_ref::<application::run_exit::RunCommandExit>() {
        eprintln!("Error: {error}");
        std::process::exit(exit.code());
    }
    Err(error)
}
