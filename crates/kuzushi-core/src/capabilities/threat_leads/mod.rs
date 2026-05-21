mod analysis;
mod files;
mod markdown;
mod output;
mod patterns;

use analysis::{lead_priority, map_by_id, threat_id_number, threat_lead};
use files::{collect_scan_files, index_files};
use markdown::render_threat_leads_markdown;
use output::tool_output;

use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub(super) const ARTIFACT_REL_PATH: &str = ".kuzushi/threat-leads.json";
pub(super) const SUMMARY_REL_PATH: &str = ".kuzushi/threat-leads.md";

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
    if count == 1 { "" } else { "s" }
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
            "threatModel": ARTIFACT_REL_PATH.replace("threat-leads", "threat-model"),
            "xRay": ["x-ray/entry-points.md", "x-ray/x-ray.md", "x-ray/invariants.md"]
        }
    })
}

pub fn read_threat_leads(target: &Path) -> Result<Value> {
    let path = target.join(ARTIFACT_REL_PATH);
    let text = fs::read_to_string(&path)
        .with_context(|| format!("Could not read threat leads artifact {}", path.display()))?;
    serde_json::from_str(&text)
        .with_context(|| format!("Could not parse threat leads artifact {}", path.display()))
}

fn resolve_target(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(target) = explicit_target(input)? {
        return Ok(target);
    }
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    std::env::current_dir().context("Could not resolve current directory")
}

fn explicit_target(input: &Value) -> Result<Option<PathBuf>> {
    let Some(target) = input.get("target").and_then(Value::as_str) else {
        return Ok(None);
    };
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(trimmed);
    Ok(Some(if path.is_absolute() {
        path
    } else {
        std::env::current_dir()?.join(path)
    }))
}

fn read_threat_model(target: &Path) -> Result<Value> {
    let path = target.join(".kuzushi/threat-model.json");
    let text = fs::read_to_string(&path)
        .with_context(|| format!("Could not read threat model {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("Could not parse {}", path.display()))
}

fn write_threat_leads(target: &Path, report: &Value) -> Result<()> {
    let path = target.join(ARTIFACT_REL_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(report)?),
    )
    .with_context(|| format!("Could not write {}", path.display()))?;
    let summary_path = target.join(SUMMARY_REL_PATH);
    fs::write(&summary_path, render_threat_leads_markdown(report))
        .with_context(|| format!("Could not write {}", summary_path.display()))
}
