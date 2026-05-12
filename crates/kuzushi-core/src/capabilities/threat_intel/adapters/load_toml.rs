use crate::capabilities::threat_intel::domain::{
    CatalogEntry, CatalogFile, CatalogSeverity, HuntKind, RawCatalogEntry,
};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;

pub const SUPPORTED_SCHEMA_VERSIONS: &[&str] = &["1"];

/// Read a catalog TOML file from disk and return validated entries.
/// Bails on schema-version mismatch, duplicate ids, and unknown
/// severity values — those are operator typos and silently dropping
/// them would defeat the catalog's audit trail.
pub fn load_catalog_from_path(path: &Path) -> Result<Vec<CatalogEntry>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("threat-intel: could not read catalog at {}", path.display()))?;
    parse_catalog_str(&raw, path)
}

pub fn parse_catalog_str(toml_text: &str, path: &Path) -> Result<Vec<CatalogEntry>> {
    let file: CatalogFile = toml::from_str(toml_text)
        .with_context(|| format!("threat-intel: invalid TOML in {}", path.display()))?;
    if !SUPPORTED_SCHEMA_VERSIONS.contains(&file.schema_version.as_str()) {
        anyhow::bail!(
            "threat-intel: catalog {} declares schema_version={:?}, supported versions are {:?}",
            path.display(),
            file.schema_version,
            SUPPORTED_SCHEMA_VERSIONS
        );
    }
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut entries = Vec::with_capacity(file.entries.len());
    for (idx, raw) in file.entries.into_iter().enumerate() {
        let entry = validate_entry(raw, path, idx)?;
        if !seen_ids.insert(entry.id.clone()) {
            anyhow::bail!(
                "threat-intel: duplicate entry id {:?} in {}",
                entry.id,
                path.display()
            );
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn validate_entry(raw: RawCatalogEntry, path: &Path, idx: usize) -> Result<CatalogEntry> {
    if raw.id.trim().is_empty() {
        anyhow::bail!(
            "threat-intel: entry[{idx}] in {} is missing `id`",
            path.display()
        );
    }
    if raw.cwe.trim().is_empty() {
        anyhow::bail!(
            "threat-intel: entry {:?} in {} is missing `cwe`",
            raw.id,
            path.display()
        );
    }
    let severity = parse_severity(&raw.severity).with_context(|| {
        format!(
            "threat-intel: entry {:?} in {} has invalid severity {:?}",
            raw.id,
            path.display(),
            raw.severity
        )
    })?;
    let hunt = HuntKind::from_str(&raw.hunt);
    Ok(CatalogEntry {
        id: raw.id,
        cves: raw.cves,
        title: raw.title,
        cwe: raw.cwe,
        severity,
        provenance: raw.provenance,
        source_repo: raw.source_repo,
        fix_commit: raw.fix_commit,
        hunt,
        hunt_config: raw.hunt_config,
    })
}

fn parse_severity(raw: &str) -> Result<CatalogSeverity> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => Ok(CatalogSeverity::Critical),
        "high" => Ok(CatalogSeverity::High),
        "medium" | "med" => Ok(CatalogSeverity::Medium),
        "low" => Ok(CatalogSeverity::Low),
        other => anyhow::bail!("unknown severity {other:?}; expected critical|high|medium|low"),
    }
}
