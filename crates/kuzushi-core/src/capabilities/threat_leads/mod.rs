mod analysis;
mod files;
mod markdown;
mod output;
mod patterns;

use analysis::{lead_priority, map_by_id, threat_id_number, threat_lead};
use files::{collect_scan_files, index_files};
use markdown::render_threat_leads_markdown;
use output::tool_output;

use crate::capabilities::threat_model::persistent_threat_model_path;
use crate::modules::ToolExecutionContext;
use crate::workspace::write_workspace_state_file;
use anyhow::{Context, Result};
use serde_json::{json, Value};
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};

const THREAT_LEADS_ARTIFACT_FILE: &str = "threat-leads.json";
const THREAT_LEADS_SUMMARY_FILE: &str = "threat-leads.md";
const MAX_THREAT_LEADS_BYTES: usize = 16 * 1024 * 1024;

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
    emit_build_start(ctx, &target);
    let report = build_threat_leads(&target)?;
    write_threat_leads(&target, &report)?;
    emit_build_done(ctx, &report);
    Ok(tool_output(&target, report))
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
    let threat_model = read_threat_model(target)?;
    let files = collect_scan_files(target)?;
    let file_index = index_files(target, &files);
    let threats = threat_model
        .get("threats")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let dfd = threat_model
        .get("dfd")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let nodes = map_by_id(dfd.get("nodes").and_then(Value::as_array));
    let flows = map_by_id(dfd.get("flows").and_then(Value::as_array));
    let mut leads = threats
        .iter()
        .filter_map(|threat| threat_lead(threat, &nodes, &flows, &file_index))
        .collect::<Vec<_>>();
    sort_leads(&mut leads);
    Ok(threat_leads_report(target, leads))
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
            "xRay": ["x-ray/entry-points.md", "x-ray/x-ray.md", "x-ray/invariants.md"]
        }
    })
}

pub fn read_threat_leads(target: &Path) -> Result<Value> {
    let path = threat_leads_artifact_path(target);
    let text = crate::workspace::read_workspace_text(target, &path, MAX_THREAT_LEADS_BYTES)?;
    serde_json::from_str(&text)
        .with_context(|| format!("Could not parse threat leads artifact {}", path.display()))
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

fn read_threat_model(target: &Path) -> Result<Value> {
    let path = persistent_threat_model_path(target);
    let text = crate::workspace::read_workspace_text(target, &path, MAX_THREAT_LEADS_BYTES)?;
    serde_json::from_str(&text).with_context(|| format!("Could not parse {}", path.display()))
}

fn write_threat_leads(target: &Path, report: &Value) -> Result<()> {
    let path = threat_leads_artifact_path(target);
    let summary_path = threat_leads_summary_path(target);
    let artifact = format!("{}\n", serde_json::to_string_pretty(report)?);
    let artifact_relative = path
        .strip_prefix(target)
        .context("Threat-leads artifact path escaped the workspace")?;
    let summary_relative = summary_path
        .strip_prefix(target)
        .context("Threat-leads summary path escaped the workspace")?;
    write_workspace_state_file(
        target,
        artifact_relative,
        artifact.as_bytes(),
    )?;
    write_workspace_state_file(
        target,
        summary_relative,
        render_threat_leads_markdown(report).as_bytes(),
    )?;
    Ok(())
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

        let error = write_threat_leads(workspace.path(), &serde_json::json!({ "leads": [] }))
            .expect_err("symlink must be rejected");

        assert!(error.to_string().contains("symlink"));
        assert_eq!(fs::read_to_string(outside.path()).unwrap(), "outside");
    }
}
