use crate::application::findings::resolve_persisted_finding;
use crate::support::require_cli_target;
use anyhow::Result;
use kuzushi_core::findings::{ReviewDecision, ReviewDecisionVerdict, TriageAuthor};
use kuzushi_core::workspace::record_user_review_decision_for_finding;
use kuzushi_core::{
    build_whitebox_suppression_for_finding, load_whitebox_suppressions,
    upsert_whitebox_suppression, whitebox_suppression_store_path, Finding, FindingStore,
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
    let record = build_whitebox_suppression_for_finding(
        workspace.root(),
        &finding,
        reason.clone(),
        author,
        expires_at_unix,
    )?;
    let record = upsert_whitebox_suppression(&workspace, record)?;
    let decision_id = append_suppressed_review_decision(&workspace, &finding, &reason)?;
    print_suppress_command_result(&workspace, &record, decision_id, json)
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
        println!(
            "Review decision: suppressed (saved; will carry forward as decision #{decision_id})."
        );
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

fn append_suppressed_review_decision(
    workspace: &WorkspaceTarget,
    finding: &Finding,
    reason: &str,
) -> Result<i64> {
    record_user_review_decision_for_finding(
        workspace,
        finding,
        &ReviewDecision {
            verdict: ReviewDecisionVerdict::Suppressed,
            author: TriageAuthor::Human,
            confidence: 1.0,
            rationale: reason.to_string(),
            dismiss_reason: None,
            actor: None,
        },
    )
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
