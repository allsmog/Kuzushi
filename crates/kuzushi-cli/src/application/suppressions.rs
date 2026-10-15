use crate::application::findings::resolve_persisted_finding;
use crate::support::require_cli_target;
use anyhow::Result;
use kuzushi_core::suppressions::{record_finding_suppression, FindingSuppressionRequest};
use kuzushi_core::{
    load_whitebox_suppressions, whitebox_suppression_store_path, FindingStore,
    WhiteboxSuppressionRecord, WorkspaceTarget,
};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn suppress_command(
    target: Option<PathBuf>,
    reference: String,
    reason: String,
    author: String,
    days: u64,
    json: bool,
) -> Result<()> {
    let target = require_cli_target("suppress", target, None)?;
    let workspace = WorkspaceTarget::new(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let finding = resolve_persisted_finding(&store, &reference, &workspace)?;
    let expires_at_unix = now_unix().saturating_add(days.saturating_mul(86_400));
    let result = record_finding_suppression(
        &workspace,
        &finding,
        FindingSuppressionRequest {
            reason: reason.clone(),
            author,
            expires_at_unix,
        },
    )?;
    if !result.structured_rule_written {
        eprintln!(
            "suppress: reason {reason:?} is not a structured suppression reason; review decision and whitebox record were saved"
        );
    }
    print_suppress_command_result(&workspace, &result.record, result.decision_id, json)
}

fn print_suppress_command_result(
    workspace: &WorkspaceTarget,
    record: &WhiteboxSuppressionRecord,
    decision_id: i64,
    json: bool,
) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!("suppression recorded: {}", record.id);
        println!("Review decision: suppressed (saved as decision #{decision_id}).");
        println!(
            "Store: {}",
            whitebox_suppression_store_path(&workspace).display()
        );
        println!(
            "Scope: {}:{}",
            record.scope.file_path, record.scope.start_line
        );
        println!("Expires: {}", record.expires_at_unix);
        println!("Policy: findings remain visible in audit/report output.");
    }
    Ok(())
}

pub(crate) fn suppressions_command(target: Option<PathBuf>, json: bool) -> Result<()> {
    let target = require_cli_target("suppressions", target, None)?;
    let workspace = WorkspaceTarget::new(target)?;
    let suppressions = load_whitebox_suppressions(&workspace)?;
    print!(
        "{}",
        suppressions_command_output(&workspace, &suppressions, json)?
    );
    Ok(())
}

pub(crate) fn suppressions_command_output(
    workspace: &WorkspaceTarget,
    suppressions: &[WhiteboxSuppressionRecord],
    json: bool,
) -> Result<String> {
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(suppressions)?));
    }
    Ok(format!(
        "{}\n",
        suppressions_plain_lines(workspace, suppressions).join("\n")
    ))
}

pub(crate) fn suppressions_plain_lines(
    workspace: &WorkspaceTarget,
    suppressions: &[WhiteboxSuppressionRecord],
) -> Vec<String> {
    let mut lines = vec![
        "Suppressions".to_string(),
        format!(
            "Store: {}",
            whitebox_suppression_store_path(workspace).display()
        ),
    ];

    if suppressions.is_empty() {
        lines.push("none recorded".to_string());
        lines.push(format!(
            "Next: kuzushi suppress F-0001 --reason <reason> --target {}",
            workspace.root().display()
        ));
    } else {
        lines.extend(suppressions.iter().map(suppression_row));
    }

    lines
}

pub(crate) fn suppression_row(record: &WhiteboxSuppressionRecord) -> String {
    format!(
        "{}  {}:{}  expires={}  reason={}",
        record.id,
        record.scope.file_path,
        record.scope.start_line,
        record.expires_at_unix,
        record.reason
    )
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
