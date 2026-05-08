use super::prelude::*;
use super::*;

pub(crate) fn scan_worktree_suffix(include_worktree: bool) -> &'static str {
    if include_worktree {
        "(+worktree)"
    } else {
        ""
    }
}

pub(crate) fn apply_scan_budget_caps(
    workspace: &WorkspaceTarget,
    budget: Option<&str>,
    json: bool,
    ci: bool,
) -> Result<()> {
    let Some(spec) = budget else {
        return Ok(());
    };
    let pairs = kuzushi_core::parse_budget_flag(spec)
        .with_context(|| format!("invalid --budget spec {spec:?}"))?;
    let limiter = kuzushi_core::SpendLimiter::open(workspace.findings_db_path())
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

pub(crate) fn scan_tool_input(
    mode: ScanModeArg,
    tasks: &[String],
    triage: bool,
) -> serde_json::Value {
    serde_json::json!({
        "mode": mode.as_input_value(),
        "taskMode": scan_task_mode(tasks),
        "tasks": tasks,
        "triage": triage,
    })
}

pub(crate) fn scan_task_mode(tasks: &[String]) -> &'static str {
    if tasks.is_empty() {
        "auto"
    } else {
        "manual"
    }
}

pub(crate) fn scan_runtime(
    config: &kuzushi_core::V2Config,
    input: &serde_json::Value,
) -> Result<Option<PiAgentCoreRuntime>> {
    if wants_sast_runtime(input) {
        Ok(Some(PiAgentCoreRuntime::from_config(
            config,
            std::env::current_dir()?,
        )?))
    } else {
        Ok(None)
    }
}

pub(crate) fn emit_scan_ci_start(
    ci: bool,
    started: std::time::Instant,
    target: &Path,
    config: &kuzushi_core::V2Config,
    tasks: &[String],
) {
    if ci {
        println!(
            "{}",
            ci_line(started, "scan", &scan_started_body(target, config, tasks))
        );
        println!("{}", ci_line(started, "phase", "(init) → scanning"));
    }
}

pub(crate) fn scan_started_body(
    target: &Path,
    config: &kuzushi_core::V2Config,
    tasks: &[String],
) -> String {
    format!(
        "{} started [model={} tasks={}]",
        target.display(),
        config.model.as_deref().unwrap_or("unconfigured"),
        scan_tasks_label(tasks),
    )
}

pub(crate) fn scan_tasks_label(tasks: &[String]) -> String {
    if tasks.is_empty() {
        "auto".to_string()
    } else {
        tasks.join(",")
    }
}
