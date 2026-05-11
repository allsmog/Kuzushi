use anyhow::{Context, Result};
use kuzushi_core::WorkspaceTarget;

pub(crate) fn apply_scan_budget_caps(
    workspace: &WorkspaceTarget,
    budget: Option<&str>,
    hard_ceiling: Option<f64>,
    json: bool,
    ci: bool,
) -> Result<()> {
    let Some(spec) = budget else {
        return Ok(());
    };
    let pairs = kuzushi_core::parse_budget_flag(spec)
        .with_context(|| format!("invalid --budget spec {spec:?}"))?;
    let limiter = kuzushi_core::SpendLimiter::open_with_hard_ceiling(
        workspace.findings_db_path(),
        hard_ceiling,
    )
    .context("could not open spend ledger")?;
    for (op, cap) in &pairs {
        limiter
            .set_cap(*op, *cap)
            .with_context(|| format!("could not set cap for {}", op.as_db_str()))?;
    }
    emit_scan_budget_lines(&pairs, json, ci);
    Ok(())
}

pub(crate) fn emit_scan_budget_lines(
    pairs: &[(kuzushi_core::SpendOperation, f64)],
    json: bool,
    ci: bool,
) {
    if should_emit_scan_budget_lines(json, ci) {
        write_scan_budget_lines(pairs);
    }
}

pub(crate) fn should_emit_scan_budget_lines(json: bool, ci: bool) -> bool {
    !json && !ci
}

pub(crate) fn write_scan_budget_lines(pairs: &[(kuzushi_core::SpendOperation, f64)]) {
    for (op, cap) in pairs {
        eprintln!("budget: {} = ${:.2}", op.as_db_str(), cap);
    }
}
