use crate::capabilities::threat_intel::adapters::load_catalog_from_path;
use crate::capabilities::threat_intel::application::dispatch::{plan_for_entry, DispatchPlan};
use crate::modules::ToolExecutionContext;
use crate::runtime::AgentRuntime;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// Apply a threat-intel catalog: load the TOML, route each entry to
/// the right hunt, return a per-entry result with the dispatch
/// outcome and (when live execution is in scope) the resulting
/// findings count.
///
/// `dispatch_live` controls whether to actually run the hunts or to
/// just plan them. `false` is useful as a dry run / sanity check;
/// `true` invokes the hunts via the supplied dispatcher closure (the
/// closure is passed in instead of called inline because the
/// `ModuleRegistry::execute_tool_with_runtime` lives in
/// `crates/kuzushi-core/src/modules/registry/`, and threading the
/// registry through here would create a circular dependency).
pub fn apply_threat_intel_catalog(
    catalog_path: &Path,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    dispatch_live: bool,
    mut dispatch_tool: impl FnMut(&str, Value, &ToolExecutionContext<'_>, Option<&dyn AgentRuntime>) -> Result<Value>,
) -> Result<Value> {
    let entries = load_catalog_from_path(catalog_path)?;
    let mut results = Vec::with_capacity(entries.len());
    let mut dispatched = 0u32;
    let mut skipped = 0u32;
    let mut failed = 0u32;
    let mut total_findings = 0u64;

    for entry in &entries {
        let plan = plan_for_entry(entry);
        match plan {
            DispatchPlan::Dispatched { tool_name, input } => {
                if dispatch_live {
                    match dispatch_tool(tool_name, input.clone(), ctx, runtime) {
                        Ok(result) => {
                            let count = extract_findings_count(&result);
                            total_findings += count;
                            dispatched += 1;
                            results.push(json!({
                                "id": entry.id,
                                "status": "dispatched",
                                "tool": tool_name,
                                "input": input,
                                "findingsCount": count,
                                "tool_result": result,
                            }));
                        }
                        Err(err) => {
                            failed += 1;
                            results.push(json!({
                                "id": entry.id,
                                "status": "dispatch-failed",
                                "tool": tool_name,
                                "input": input,
                                "error": format!("{err:#}"),
                            }));
                        }
                    }
                } else {
                    dispatched += 1;
                    results.push(json!({
                        "id": entry.id,
                        "status": "planned",
                        "tool": tool_name,
                        "input": input,
                    }));
                }
            }
            DispatchPlan::Skipped { reason } => {
                skipped += 1;
                results.push(json!({
                    "id": entry.id,
                    "status": "skipped",
                    "hunt": entry.hunt.as_str(),
                    "reason": reason,
                }));
            }
        }
    }

    Ok(json!({
        "ok": true,
        "data": {
            "catalogPath": catalog_path.display().to_string(),
            "entries": results,
        },
        "summary": {
            "totalEntries": entries.len(),
            "dispatched": dispatched,
            "skipped": skipped,
            "failed": failed,
            "totalFindings": total_findings,
            "dryRun": !dispatch_live,
        },
    }))
}

pub fn list_threat_intel_catalog(catalog_path: &Path) -> Result<Value> {
    let entries = load_catalog_from_path(catalog_path)?;
    let rows: Vec<Value> = entries
        .iter()
        .map(|entry| {
            json!({
                "id": entry.id,
                "cves": entry.cves,
                "title": entry.title,
                "cwe": entry.cwe,
                "severity": entry.severity.as_str(),
                "hunt": entry.hunt.as_str(),
                "provenance": entry.provenance,
                "fixCommit": entry.fix_commit,
            })
        })
        .collect();
    Ok(json!({
        "ok": true,
        "data": {
            "catalogPath": catalog_path.display().to_string(),
            "entries": rows,
        },
        "summary": {
            "totalEntries": entries.len(),
        },
    }))
}

pub fn resolve_catalog_path(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    if let Some(explicit) = input
        .get("catalogPath")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        let path = PathBuf::from(explicit);
        let resolved = if path.is_absolute() {
            path
        } else if let Some(workspace) = ctx.workspace {
            workspace.root().join(path)
        } else {
            std::env::current_dir()
                .context("threat-intel: could not resolve current directory")?
                .join(path)
        };
        if !resolved.exists() {
            anyhow::bail!(
                "threat-intel: catalogPath {} does not exist",
                resolved.display()
            );
        }
        return Ok(resolved);
    }
    // Default: <target>/.kuzushi/catalogs/<first-toml>.
    let workspace = ctx.workspace.ok_or_else(|| {
        anyhow::anyhow!(
            "threat-intel: no workspace target; pass `catalogPath` explicitly or run with --target"
        )
    })?;
    let dir = workspace.root().join(".kuzushi").join("catalogs");
    if !dir.is_dir() {
        anyhow::bail!(
            "threat-intel: no catalog supplied. Pass `catalogPath` or create one at {}/<name>.toml",
            dir.display()
        );
    }
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(&dir)
        .with_context(|| format!("threat-intel: could not read {}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
        })
        .collect();
    candidates.sort();
    candidates.into_iter().next().ok_or_else(|| {
        anyhow::anyhow!(
            "threat-intel: no .toml files under {}; place a catalog there or pass `catalogPath`",
            dir.display()
        )
    })
}

fn extract_findings_count(result: &Value) -> u64 {
    result
        .get("summary")
        .and_then(|s| s.get("count"))
        .and_then(Value::as_u64)
        .or_else(|| {
            result
                .get("data")
                .and_then(|d| d.get("count"))
                .and_then(Value::as_u64)
        })
        .unwrap_or(0)
}

