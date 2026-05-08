use super::prelude::*;
use super::*;

pub(crate) fn scan_json_output(
    workspace: &WorkspaceTarget,
    data: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "runId": data.get("runId").cloned(),
        "target": data.get("target").cloned(),
        "findingsCount": data.get("findingsCount").cloned(),
        "db": workspace.findings_db_path(),
        "mode": data.get("mode").cloned(),
        "whiteboxStatic": data.get("whiteboxStatic").cloned(),
        "triage": data.get("triage").cloned(),
    })
}

pub(crate) fn ci_line(started: std::time::Instant, prefix: &str, body: &str) -> String {
    let elapsed = started.elapsed();
    format!("[+{:.1}s] {prefix}: {body}", elapsed.as_secs_f64())
}

pub(crate) fn format_duration(elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs();
    if secs >= 60 {
        let minutes = secs / 60;
        let rem = secs % 60;
        format!("{minutes}m {rem}s")
    } else {
        format!("{:.1}s", elapsed.as_secs_f64())
    }
}

pub(crate) fn findings_command(
    target: Option<PathBuf>,
    filter: FindingListFilter,
    json: bool,
) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let report = store.list_findings_filtered(&filter)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if report.findings.is_empty() {
        println!(
            "no findings found at {}\nNext: kuzushi scan {}",
            workspace.findings_db_path().display(),
            workspace.root().display()
        );
    } else {
        println!("{}", report.output());
    }
    Ok(())
}

pub(crate) fn finding_command(
    target: Option<PathBuf>,
    reference: String,
    json: bool,
) -> Result<()> {
    let target = target.unwrap_or_else(|| PathBuf::from("."));
    let workspace = WorkspaceTarget::new(target)?;
    let store = FindingStore::open(workspace.findings_db_path())?;
    let all_findings = store
        .list_findings_filtered(&FindingListFilter::with_limit(FindingListFilter::MAX_LIMIT))?
        .findings;

    let finding = if let Some(alias_finding) = resolve_finding_alias(&all_findings, &reference) {
        store
            .get_finding_by_fingerprint(&alias_finding.fingerprint)?
            .unwrap_or(alias_finding)
    } else {
        store
            .get_finding_by_reference(&reference)?
            .with_context(|| {
                format!(
                    "no finding found for {reference:?} at {}\nNext: kuzushi findings --target {}",
                    workspace.findings_db_path().display(),
                    workspace.root().display()
                )
            })?
    };
    let alias = stable_finding_alias(&all_findings, &finding.fingerprint);
    let patch_results = store.get_patch_results_for_finding(&finding.fingerprint)?;
    let report = FindingDetailReport::new(alias, finding, patch_results);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", report.output());
    }
    Ok(())
}

pub(crate) fn runs_command(command: RunsCommand, global_target: Option<PathBuf>) -> Result<()> {
    match command {
        RunsCommand::List { target, json } => runs_list_command(target.or(global_target), json),
        RunsCommand::Show {
            run_id,
            target,
            json,
        } => runs_show_command(target.or(global_target), &run_id, json),
        RunsCommand::Trace {
            run_id,
            target,
            json,
        } => runs_trace_command(target.or(global_target), &run_id, json),
    }
}

pub(crate) fn runs_list_command(target: Option<PathBuf>, json: bool) -> Result<()> {
    let workspace = WorkspaceTarget::new(target.unwrap_or_else(|| PathBuf::from(".")))?;
    let runs = list_run_summaries(workspace.root())?;
    print!("{}", runs_list_output(&workspace, &runs, json)?);
    Ok(())
}

pub(crate) fn runs_list_output(
    workspace: &WorkspaceTarget,
    runs: &[RunSummary],
    json: bool,
) -> Result<String> {
    if json {
        return Ok(format!("{}\n", serde_json::to_string_pretty(runs)?));
    }
    Ok(runs_list_plain(workspace, runs))
}
