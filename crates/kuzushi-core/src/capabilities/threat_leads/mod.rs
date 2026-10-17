mod analysis;
mod files;
mod markdown;
mod output;
mod patterns;
mod projection;
mod publication;
mod source_inventory;

use analysis::{lead_priority, threat_id_number, threat_lead};
use markdown::render_threat_leads_markdown;
use output::tool_output;

use crate::capabilities::threat_model::persistent_threat_model_path;
use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde_json::{json, Value};
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};

const THREAT_LEADS_ARTIFACT_FILE: &str = "threat-leads.json";
const THREAT_LEADS_SUMMARY_FILE: &str = "threat-leads.md";
const MAX_THREAT_LEADS_BYTES: usize = 16 * 1024 * 1024;
const MAX_THREATS: usize = 256;

pub fn execute_threat_leads_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    match name {
        "threat-leads:build" => build_threat_leads_tool(&input, ctx),
        "threat-leads:read" => read_threat_leads_tool(&input, ctx),
        other => anyhow::bail!("unknown threat-leads tool {other:?}"),
    }
}

pub fn build_threat_leads_tool(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_target(input, ctx)?;
    if input["repairSummary"].as_bool() == Some(true) {
        let report = read_threat_leads(&target)?;
        ctx.ensure_active()?;
        publication::repair(&target, &report)?;
        return Ok(tool_output(&target, report));
    }
    emit_build_start(ctx, &target);
    let report = build_threat_leads_observed(&target, Some(ctx))?;
    ctx.ensure_active()?;
    let publication_warning = publication::publish(&target, &report)?;
    emit_build_done(ctx, &report);
    let mut result = tool_output(&target, report);
    output::append_publication_warning(&mut result, publication_warning);
    Ok(result)
}

pub fn read_threat_leads_tool(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_target(input, ctx)?;
    let report = read_threat_leads(&target)?;
    Ok(tool_output(&target, report))
}

fn emit_build_start(ctx: &ToolExecutionContext<'_>, target: &Path) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                "build",
                format!("threat-leads start · target={}", target.display()),
            )
            .emit();
    }
}

fn emit_build_done(ctx: &ToolExecutionContext<'_>, report: &Value) {
    if let Some(trace) = ctx.trace {
        let count = report["leadCount"].as_u64().unwrap_or_default();
        let _ = trace
            .step(
                "done",
                "build",
                format!("threat-leads complete · {count} lead{}", plural(count)),
            )
            .emit();
    }
}

fn plural(count: u64) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

pub fn build_threat_leads(target: &Path) -> Result<Value> {
    build_threat_leads_observed(target, None)
}

fn build_threat_leads_observed(
    target: &Path,
    ctx: Option<&ToolExecutionContext<'_>>,
) -> Result<Value> {
    let canceled = || ctx.is_some_and(|value| value.is_cancelled());
    source_inventory::ensure_active(&canceled)?;
    let (threat_model, model_sha256) = read_threat_model(target)?;
    let threats = threat_model
        .get("threats")
        .and_then(Value::as_array)
        .context(
            "Threat leads require a threat-model threats array; build or import context first",
        )?;
    let mut heartbeat = crate::progress::HeartbeatGate::new(std::time::Duration::from_secs(1));
    let index = source_inventory::collect(
        target,
        &mut |entries| {
            if heartbeat.ready() {
                emit_inventory_progress(ctx, entries);
            }
        },
        &canceled,
    )?;
    let dfd = &threat_model["dfd"];
    let mut projection = projection::Projection::default();
    let leads = derive_leads(threats, dfd, &index.files, &canceled, &mut projection)?;
    let mut report = threat_leads_report(target, leads);
    report["sources"]["threatModelSha256"] = json!(model_sha256);
    report["sourceCoverage"] = finish_coverage(index.coverage, threats.len());
    if projection.is_partial() {
        report["sourceCoverage"]["status"] = json!("partial");
    }
    report["sourceCoverage"]["contextProjection"] = projection.receipt();
    Ok(report)
}

fn derive_leads(
    threats: &[Value],
    dfd: &Value,
    files: &[files::IndexedFile],
    canceled: &dyn Fn() -> bool,
    projection: &mut projection::Projection,
) -> Result<Vec<Value>> {
    let nodes = projection.elements(dfd.get("nodes").and_then(Value::as_array));
    let flows = projection.elements(dfd.get("flows").and_then(Value::as_array));
    let mut leads = Vec::new();
    for threat in threats.iter().take(MAX_THREATS) {
        source_inventory::ensure_active(canceled)?;
        if let Some(lead) = threat_lead(threat, &nodes, &flows, files, projection) {
            retain_lead(&mut leads, lead, projection);
        }
    }
    sort_leads(&mut leads);
    Ok(leads)
}

fn retain_lead(leads: &mut Vec<Value>, lead: Value, projection: &mut projection::Projection) {
    if projection.admit(&lead) {
        leads.push(lead);
    }
}

fn finish_coverage(mut coverage: Value, threats: usize) -> Value {
    coverage["threatsInContext"] = json!(threats);
    coverage["processedThreats"] = json!(threats.min(MAX_THREATS));
    coverage["unprocessedThreats"] = json!(threats.saturating_sub(MAX_THREATS));
    if threats > MAX_THREATS {
        coverage["status"] = json!("partial");
    }
    coverage
}

fn emit_inventory_progress(ctx: Option<&ToolExecutionContext<'_>>, entries: usize) {
    if let Some(trace) = ctx.and_then(|value| value.trace) {
        let _ = trace
            .step(
                "tool-progress",
                "threat-leads:build",
                format!("repository inventory · {entries} entries examined"),
            )
            .emit();
    }
}

fn sort_leads(leads: &mut [Value]) {
    leads.sort_by(|a, b| {
        lead_priority(b)
            .cmp(&lead_priority(a))
            .then_with(|| threat_id_number(a).cmp(&threat_id_number(b)))
            .then_with(|| a["threatId"].as_str().cmp(&b["threatId"].as_str()))
    });
}

fn threat_leads_report(target: &Path, leads: Vec<Value>) -> Value {
    json!({
        "schemaVersion": 1,
        "target": target.display().to_string(),
        "leadCount": leads.len(),
        "leads": leads,
        "sources": {
            "threatModel": workspace_relative_path(target, &persistent_threat_model_path(target)),
            "xRay": []
        }
    })
}

pub fn read_threat_leads(target: &Path) -> Result<Value> {
    let path = threat_leads_artifact_path(target);
    let text = crate::workspace::read_workspace_text(target, &path, MAX_THREAT_LEADS_BYTES)?;
    let mut report: Value = serde_json::from_str(&text)
        .with_context(|| format!("Could not parse threat leads artifact {}", path.display()))?;
    validate_report(&report)?;
    if report.get("sourceCoverage").is_none() {
        report["sourceCoverage"] = json!({"schemaVersion":1,"status":"legacy-unverified","completeRepositoryCoverage":false});
    }
    Ok(report)
}

fn validate_report(report: &Value) -> Result<()> {
    let leads = report
        .get("leads")
        .and_then(Value::as_array)
        .context("Threat leads artifact requires a leads array")?;
    anyhow::ensure!(
        report["leadCount"].as_u64() == Some(leads.len() as u64),
        "Threat leads count does not match the recorded cards"
    );
    if let Some(coverage) = report.get("sourceCoverage") {
        validate_coverage(coverage)?;
    }
    Ok(())
}

fn validate_coverage(coverage: &Value) -> Result<()> {
    anyhow::ensure!(
        coverage["schemaVersion"] == 1 && coverage["completeRepositoryCoverage"] == false,
        "Threat lead source receipt is unsupported; preserve the artifact and rebuild the hints"
    );
    anyhow::ensure!(
        matches!(
            coverage["status"].as_str(),
            Some("bounded" | "partial" | "legacy-unverified")
        ),
        "Threat lead source receipt status is unsupported"
    );
    Ok(())
}

fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(target) = explicit_target(input, ctx)? {
        return Ok(target);
    }
    ctx.workspace
        .map(|workspace| workspace.root().to_path_buf())
        .context("threat-leads requires an explicit active workspace")
}

fn explicit_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Option<PathBuf>> {
    let Some(target) = input.get("target").and_then(Value::as_str) else {
        return Ok(None);
    };
    let trimmed = target.trim();
    if trimmed.is_empty() {
        anyhow::bail!("threat-leads target may not be blank");
    }
    let path = PathBuf::from(trimmed);
    Ok(Some(if path.is_absolute() {
        path
    } else {
        ctx.workspace
            .map(|workspace| workspace.root().join(path))
            .context("threat-leads requires an explicit active workspace")?
    }))
}

fn read_threat_model(target: &Path) -> Result<(Value, String)> {
    let path = persistent_threat_model_path(target);
    let text = crate::workspace::read_workspace_text(target, &path, MAX_THREAT_LEADS_BYTES)?;
    let model = serde_json::from_str(&text)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    Ok((
        model,
        crate::run_lifecycle::sha256_content_digest(text.as_bytes()),
    ))
}

pub(crate) fn read_threat_leads_context(target: &Path, markdown: bool) -> Result<String> {
    let report = read_threat_leads(target)?;
    let state = publication::inspect_summary(target, &report);
    anyhow::ensure!(
        !markdown || state == publication::SummaryState::Current,
        "Saved threat-lead Markdown does not match its JSON cards"
    );
    Ok(format!(
        "{}\n{}",
        state.message(),
        render_threat_leads_markdown(&report)
    ))
}

pub(super) fn threat_leads_artifact_path(target: &Path) -> PathBuf {
    crate::workspace::workspace_state_root(target).join(THREAT_LEADS_ARTIFACT_FILE)
}

pub(super) fn threat_leads_summary_path(target: &Path) -> PathBuf {
    crate::workspace::workspace_state_root(target).join(THREAT_LEADS_SUMMARY_FILE)
}

fn workspace_relative_path(target: &Path, path: &Path) -> String {
    path.strip_prefix(target)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_leads_paths_use_workspace_state_root() {
        let target = Path::new("/repo");
        let state_root = crate::workspace::workspace_state_root(target);

        assert_eq!(
            threat_leads_artifact_path(target),
            state_root.join(THREAT_LEADS_ARTIFACT_FILE)
        );
        assert_eq!(
            threat_leads_summary_path(target),
            state_root.join(THREAT_LEADS_SUMMARY_FILE)
        );
    }

    #[test]
    fn threat_leads_report_references_persistent_threat_model_artifact() {
        let report = threat_leads_report(Path::new("/repo"), Vec::new());

        assert_eq!(
            report["sources"]["threatModel"],
            workspace_relative_path(
                Path::new("/repo"),
                &persistent_threat_model_path(Path::new("/repo"))
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn threat_leads_writer_rejects_a_symlinked_artifact() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().expect("workspace");
        let mut outside = tempfile::NamedTempFile::new().expect("outside");
        std::io::Write::write_all(&mut outside, b"outside").expect("seed outside");
        fs::create_dir_all(crate::workspace::workspace_state_root(workspace.path()))
            .expect("state dir");
        symlink(outside.path(), threat_leads_artifact_path(workspace.path()))
            .expect("symlink artifact");

        let error = publication::publish(workspace.path(), &serde_json::json!({ "leads": [] }))
            .expect_err("symlink must be rejected");

        assert!(error.to_string().contains("symlink"));
        assert_eq!(fs::read_to_string(outside.path()).unwrap(), "outside");
    }
}
