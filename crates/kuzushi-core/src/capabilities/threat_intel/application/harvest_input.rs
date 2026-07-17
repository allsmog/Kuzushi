use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::PathBuf;

pub(super) fn parse_cve_list(input: &Value) -> Result<Vec<String>> {
    let raw = input
        .get("cves")
        .context("threat-intel:harvest requires `cves` (array of CVE IDs)")?;
    let items = raw
        .as_array()
        .context("threat-intel:harvest `cves` must be an array of strings")?;
    if items.is_empty() {
        anyhow::bail!("threat-intel:harvest `cves` is empty; pass at least one CVE id");
    }
    items
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            item.as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .with_context(|| format!("cves[{idx}] must be a non-empty string"))
        })
        .collect()
}

pub(super) fn resolve_output_path(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<PathBuf> {
    if let Some(explicit) = input
        .get("outputPath")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        return resolve_explicit_output_path(explicit, ctx);
    }
    let workspace = ctx.workspace.ok_or_else(|| {
        anyhow::anyhow!(
            "{} Or pass `outputPath` in the input.",
            crate::workspace::active_workspace_required_message("threat-intel:harvest")
        )
    })?;
    Ok(crate::capabilities::threat_intel::harvested_threat_intel_catalog_path(
        workspace.root(),
    ))
}

fn resolve_explicit_output_path(raw: &str, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        return Ok(path);
    }
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().join(path));
    }
    anyhow::bail!("threat-intel:harvest requires an explicit active workspace")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cve_list_rejects_empty_array_with_clear_message() {
        let err = parse_cve_list(&serde_json::json!({"cves": []})).unwrap_err();
        let chain = format!("{err:#}");
        assert!(chain.contains("empty"), "must name the problem: {chain}");
    }

    #[test]
    fn parse_cve_list_requires_cves_field() {
        let err = parse_cve_list(&serde_json::json!({})).unwrap_err();
        let chain = format!("{err:#}");
        assert!(chain.contains("`cves`"), "must name the field: {chain}");
    }
}
