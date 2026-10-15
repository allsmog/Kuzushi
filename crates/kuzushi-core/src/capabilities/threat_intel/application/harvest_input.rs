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
    anyhow::ensure!(
        items.len() <= 32,
        "Advisory draft accepts at most 32 supplied ID rows"
    );
    let limit = harvest_advisory_limit(input)?;
    let mut seen = std::collections::BTreeSet::new();
    let mut ids = Vec::new();
    for item in items {
        let id = checked_advisory_id(item)?;
        if seen.insert(id.to_ascii_uppercase()) {
            ids.push(id.to_string());
        }
    }
    anyhow::ensure!(ids.len() <= limit,"Advisory draft exceeds maxCves; revise the explicit list or approve a larger declared bound");
    Ok(ids)
}

fn checked_advisory_id(value: &Value) -> Result<&str> {
    let id = value.as_str().context("Advisory IDs must be text")?.trim();
    anyhow::ensure!(
        !id.is_empty() && id.len() <= 128,
        "Advisory ID must contain 1 to 128 bytes"
    );
    anyhow::ensure!(
        id.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "Advisory ID contains unsupported characters"
    );
    Ok(id)
}

fn harvest_advisory_limit(input: &Value) -> Result<usize> {
    let Some(raw) = input.get("maxCves") else {
        return Ok(8);
    };
    let value = raw.as_u64().context("maxCves must be an integer")?;
    anyhow::ensure!((1..=32).contains(&value), "maxCves must be from 1 to 32");
    Ok(value as usize)
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
    Ok(crate::capabilities::threat_intel::harvested_threat_intel_catalog_path(workspace.root()))
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

    #[test]
    fn advisory_lists_are_finite_and_deduplicate_exact_case_aliases() {
        assert_eq!(
            parse_cve_list(&serde_json::json!({"cves":["OWNED-ONE","owned-one","OWNED-TWO"]}))
                .unwrap(),
            vec!["OWNED-ONE", "OWNED-TWO"]
        );
        for value in [
            serde_json::json!({"cves":vec!["OWNED";33]}),
            serde_json::json!({"cves":["../outside"]}),
            serde_json::json!({"cves":["x".repeat(129)]}),
            serde_json::json!({"cves":["ONE","TWO"],"maxCves":1}),
            serde_json::json!({"cves":["ONE"],"maxCves":0}),
        ] {
            assert!(parse_cve_list(&value).is_err());
        }
    }
}
