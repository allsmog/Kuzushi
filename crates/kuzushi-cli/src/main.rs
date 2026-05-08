mod prelude;
use prelude::*;
mod siblings;
pub(crate) use siblings::*;
mod cli;
mod command;
mod items_10;
mod items_11;
mod items_12;
mod items_13;
mod items_14;
mod items_15;
mod items_16;
mod items_17;
mod items_18;
mod items_19;
mod items_2;
mod items_20;
mod items_21;
mod items_4;
mod items_5;
mod items_6;
mod items_7;
mod items_8;
mod items_9;
#[cfg(test)]
mod tests;
mod wants_sast_runtime;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let plain = plain_output_requested(cli.plain);
    let command = cli.command.unwrap_or(Command::Shell { target: None });

    match command {
        Command::Shell { target } => {
            let target = target.or(cli.target);
            let workspace = target
                .as_deref()
                .map(WorkspaceTarget::new)
                .transpose()
                .context("Could not resolve shell target")?;
            if should_emit_shell_startup_progress(plain) {
                for line in shell_startup_progress_messages(target.as_deref()) {
                    eprintln!("{line}");
                }
            }
            let config = load_config_for_target(workspace.as_ref().map(WorkspaceTarget::root))?;
            run_shell_with_plain(config, workspace.as_ref(), plain)
        }
        Command::Scan {
            target,
            mode,
            tasks,
            triage,
            json,
            ci,
            budget,
            since,
            include_worktree,
        } => {
            scan_command(
                target,
                mode,
                tasks,
                triage,
                json,
                ci,
                budget,
                since,
                include_worktree,
            )
            .await
        }
        Command::Findings {
            target,
            limit,
            severity,
            verdict,
            name,
            file_path,
            vuln_source,
            json,
        } => findings_command(
            target.or(cli.target),
            FindingListFilter::from_parts_full(
                severity,
                verdict,
                name,
                file_path,
                vuln_source,
                limit,
            )?,
            json,
        ),
        Command::Finding {
            reference,
            target,
            json,
        } => finding_command(target.or(cli.target), reference, json),
        Command::Runs { command } => runs_command(command, cli.target),
        Command::Suppress {
            reference,
            target,
            reason,
            author,
            days,
            json,
        } => suppress_command(target.or(cli.target), reference, reason, author, days, json),
        Command::Suppressions { target, json } => suppressions_command(target.or(cli.target), json),
        Command::Permissions { target, json } => permissions_command(target.or(cli.target), json),
        Command::Config { command } => config_command(command, cli.target),
        Command::Auth { command } => auth_command(command, cli.target),
        Command::Modules { json } => modules_command(json),
        Command::Tools { json } => tools_command(json),
        Command::Doctor { target, json } => doctor_command(target.or(cli.target), json),
        Command::Run { tool, input } => run_tool_command(tool, input, cli.target),
        Command::Mcp { command } => mcp_command(command).await,
        Command::PrComment {
            target,
            repo,
            run_url,
            top_n,
            changed_files,
            run_id,
            model,
            git_sha,
        } => pr_comment_command(
            target.or(cli.target),
            repo,
            run_url,
            top_n,
            changed_files,
            run_id,
            model,
            git_sha,
        ),
    }
}
