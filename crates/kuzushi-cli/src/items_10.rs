use super::prelude::*;
use super::*;

pub(crate) fn suppress_command(
    target: Option<PathBuf>,
    reference: String,
    reason: String,
    author: String,
    days: u64,
    json: bool,
) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let finding = resolve_persisted_finding(&store, &reference, &workspace)?;
    let expires_at_unix = now_unix().saturating_add(days.saturating_mul(86_400));
    let record = build_whitebox_suppression_for_finding(
        workspace.root(),
        &finding,
        reason,
        author,
        expires_at_unix,
    )?;
    let record = upsert_whitebox_suppression(&workspace, record)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!("suppression recorded: {}", record.id);
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
    let workspace = WorkspaceTarget::new(target.unwrap_or_else(|| PathBuf::from(".")))?;
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
