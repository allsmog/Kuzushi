use crate::application::export::export_command;
use crate::application::findings::{
    finding_command, findings_batch_command, findings_command,
    findings_identity_audit_approve_command, findings_identity_audit_command,
};
use crate::application::permissions::permissions_command;
use crate::application::pr_comment::pr_comment_command;
use crate::application::proof_deferrals::proof_command;
use crate::application::review_decisions::decision_command;
use crate::application::runs::runs_command;
use crate::application::suppressions::{suppress_command, suppressions_command};
use crate::command::Command;
use crate::command::FindingsCommand;
use crate::command::IdentityAuditCommand;
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
        export @ Command::Export { .. } => dispatch_export_command(export, default_target),
        suppress @ Command::Suppress { .. } => dispatch_suppress_command(suppress, default_target),
        Command::Proof { command } => proof_command(command, default_target),
        Command::Suppressions { json } => suppressions_command(default_target, json),
        Command::Permissions { json } => permissions_command(default_target, json),
        Command::Doctor { json } => {
            doctor_command(require_cli_target("doctor", None, default_target)?, json)
        }
        pr_comment @ Command::PrComment(_) => {
            dispatch_pr_comment_command(pr_comment, default_target)
        }
        _ => unreachable!("non-reporting command routed to reporting dispatcher"),
    }
}

fn dispatch_export_command(command: Command, default_target: Option<PathBuf>) -> Result<()> {
    let Command::Export {
        campaign_id,
        format,
        completeness,
        preview,
        allow_empty,
        output,
    } = command
    else {
        unreachable!("non-export command routed to export dispatcher")
    };
    let target = require_cli_target("export", None, default_target)?;
    export_command(
        target,
        output,
        format,
        completeness,
        preview,
        allow_empty,
        campaign_id,
    )
}

fn dispatch_findings_command(command: Command, default_target: Option<PathBuf>) -> Result<()> {
    let Command::Findings {
        command,
        scope,
        scope_record,
        limit,
        severity,
        mut verdict,
        decision,
        completeness,
        status,
        confidence,
        state,
        name,
        file_path,
        vuln_source,
        json,
    } = command
    else {
        unreachable!("non-findings command routed to findings dispatcher")
    };
    if let Some(command) = command {
        return dispatch_findings_subcommand(command, default_target);
    }
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
    )?
    .with_triage_states(state)?
    .with_scope_filters(scope, scope_record)?;
    findings_command(default_target, filter, json)
}

fn dispatch_findings_subcommand(
    command: FindingsCommand,
    default_target: Option<PathBuf>,
) -> Result<()> {
    match command {
        FindingsCommand::Batch { batch_id, json } => {
            findings_batch_command(default_target, batch_id, json)
        }
        FindingsCommand::IdentityAudit { action, json } => match action {
            None => findings_identity_audit_command(default_target, json),
            Some(IdentityAuditCommand::Approve { input, json }) => {
                findings_identity_audit_approve_command(default_target, input, json)
            }
        },
    }
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
    let target = require_cli_target("pr-comment", None, default_target)?;
    pr_comment_command(
        target,
        args.repo,
        args.run_url,
        args.top_n,
        args.changed_files,
        args.run_id,
        args.model,
        args.git_sha,
    )
}
