use super::target_or_default;
use crate::command::Command;
use crate::doctor::doctor_command;
use crate::findings::{finding_command, findings_command};
use crate::permissions::permissions_command;
use crate::pr_comment::pr_comment_command;
use crate::runs::runs_command;
use crate::suppressions::{suppress_command, suppressions_command};
use anyhow::Result;
use kuzushi_core::FindingListFilter;
use std::path::PathBuf;

pub(super) fn dispatch_reporting_command(
    command: Command,
    default_target: Option<PathBuf>,
) -> Result<()> {
    match command {
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
            target_or_default(target, &default_target),
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
        } => finding_command(target_or_default(target, &default_target), reference, json),
        Command::Runs { command } => runs_command(command, default_target),
        Command::Suppress {
            reference,
            target,
            reason,
            author,
            days,
            json,
        } => suppress_command(
            target_or_default(target, &default_target),
            reference,
            reason,
            author,
            days,
            json,
        ),
        Command::Suppressions { target, json } => {
            suppressions_command(target_or_default(target, &default_target), json)
        }
        Command::Permissions { target, json } => {
            permissions_command(target_or_default(target, &default_target), json)
        }
        Command::Doctor { target, json } => {
            doctor_command(target_or_default(target, &default_target), json)
        }
        Command::PrComment(args) => pr_comment_command(
            target_or_default(args.target, &default_target),
            args.repo,
            args.run_url,
            args.top_n,
            args.changed_files,
            args.run_id,
            args.model,
            args.git_sha,
        ),
        _ => unreachable!("non-reporting command routed to reporting dispatcher"),
    }
}
