use super::target_or_default;
use crate::application::export::export_command;
use crate::application::findings::{finding_command, findings_command};
use crate::application::permissions::permissions_command;
use crate::application::pr_comment::pr_comment_command;
use crate::application::review_decisions::decision_command;
use crate::application::runs::runs_command;
use crate::application::suppressions::{suppress_command, suppressions_command};
use crate::command::Command;
use crate::doctor::doctor_command;
use crate::support::require_cli_target;
use anyhow::Result;
use kuzushi_core::FindingListFilter;
use std::path::PathBuf;

pub(super) fn dispatch_reporting_command(
    command: Command,
    default_target: Option<PathBuf>,
) -> Result<()> {
    match command {
        findings @ Command::Findings { .. } => dispatch_findings_command(findings, default_target),
        Command::Finding { reference, json } => finding_command(default_target, reference, json),
        Command::Decision {
            reference,
            verdict,
            reason,
            json,
        } => decision_command(default_target, reference, verdict, reason, json),
        Command::Runs { command } => runs_command(command, default_target),
        Command::Export {
            format,
            completeness,
            preview,
            allow_empty,
            output,
        } => {
            let target = require_cli_target("export", None, default_target)?;
            export_command(target, output, format, completeness, preview, allow_empty)
        }
        suppress @ Command::Suppress { .. } => dispatch_suppress_command(suppress, default_target),
        Command::Suppressions { json } => suppressions_command(default_target, json),
        Command::Permissions { json } => permissions_command(default_target, json),
        Command::Doctor { json } => doctor_command(default_target, json),
        pr_comment @ Command::PrComment(_) => {
            dispatch_pr_comment_command(pr_comment, default_target)
        }
        _ => unreachable!("non-reporting command routed to reporting dispatcher"),
    }
}

fn dispatch_findings_command(command: Command, default_target: Option<PathBuf>) -> Result<()> {
    let Command::Findings {
        limit,
        severity,
        mut verdict,
        decision,
        completeness,
        status,
        confidence,
        name,
        file_path,
        vuln_source,
        json,
    } = command
    else {
        unreachable!("non-findings command routed to findings dispatcher")
    };
    verdict.extend(decision);
    let filter = FindingListFilter::from_parts_full(
        severity,
        verdict,
        name,
        file_path,
        vuln_source,
        completeness,
        status,
        confidence,
        limit,
    )?;
    findings_command(default_target, filter, json)
}

fn dispatch_suppress_command(command: Command, default_target: Option<PathBuf>) -> Result<()> {
    let Command::Suppress {
        reference,
        reason,
        author,
        days,
        json,
    } = command
    else {
        unreachable!("non-suppress command routed to suppress dispatcher")
    };
    suppress_command(default_target, reference, reason, author, days, json)
}

fn dispatch_pr_comment_command(command: Command, default_target: Option<PathBuf>) -> Result<()> {
    let Command::PrComment(args) = command else {
        unreachable!("non-pr-comment command routed to PR comment dispatcher")
    };
    pr_comment_command(
        target_or_default(args.target, &default_target),
        args.repo,
        args.run_url,
        args.top_n,
        args.changed_files,
        args.run_id,
        args.model,
        args.git_sha,
    )
}
