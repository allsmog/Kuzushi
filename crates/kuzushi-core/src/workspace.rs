use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::findings::{Finding, FindingListFilter, FindingStore};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceTarget {
    root: PathBuf,
}

impl WorkspaceTarget {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let root = if path.exists() {
            fs::canonicalize(path)
                .with_context(|| format!("Could not resolve {}", path.display()))?
        } else {
            anyhow::bail!("Target path does not exist: {}", path.display());
        };

        if !root.is_dir() {
            anyhow::bail!("Target must be a directory: {}", root.display());
        }

        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn state_dir(&self) -> PathBuf {
        self.root.join(".kuzushi").join("v2")
    }

    pub fn findings_db_path(&self) -> PathBuf {
        self.state_dir().join("findings.sqlite3")
    }

    pub fn ensure_state_dir(&self) -> Result<PathBuf> {
        let state_dir = self.state_dir();
        fs::create_dir_all(&state_dir)
            .with_context(|| format!("Could not create {}", state_dir.display()))?;
        Ok(state_dir)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceExportFormat {
    Json,
    Jsonl,
}

impl WorkspaceExportFormat {
    pub fn from_input(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "jsonl" | "ndjson" => Ok(Self::Jsonl),
            other => anyhow::bail!(
                "unsupported workspace findings export format {other:?}. Supported formats: json, jsonl"
            ),
        }
    }

    pub fn from_output_path(path: &Path) -> Result<Self> {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("json") | None => Ok(Self::Json),
            Some("jsonl") | Some("ndjson") => Ok(Self::Jsonl),
            Some(other) => anyhow::bail!(
                "unsupported workspace findings export extension .{other}. Supported extensions: .json, .jsonl"
            ),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceFindingsExport {
    pub output_path: PathBuf,
    pub format: WorkspaceExportFormat,
    pub count: usize,
}

pub fn export_workspace_findings(
    workspace: &WorkspaceTarget,
    output_path: impl AsRef<Path>,
    format: Option<WorkspaceExportFormat>,
) -> Result<WorkspaceFindingsExport> {
    let output_path = output_path.as_ref();
    if output_path.as_os_str().is_empty() {
        anyhow::bail!("workspace findings export needs an output path");
    }
    if output_path.exists() && output_path.is_dir() {
        anyhow::bail!(
            "workspace findings export output must be a file path, not directory: {}",
            output_path.display()
        );
    }

    let format = match format {
        Some(format) => format,
        None => WorkspaceExportFormat::from_output_path(output_path)?,
    };
    if let Some(parent) = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }

    let store = FindingStore::open(workspace.findings_db_path())?;
    let findings = store.list_findings(FindingListFilter::MAX_LIMIT)?;
    let body = match format {
        WorkspaceExportFormat::Json => serde_json::to_string_pretty(&json!({
            "format": "kuzushi.workspace.findings.v1",
            "workspaceRoot": workspace.root().display().to_string(),
            "findingsDb": workspace.findings_db_path().display().to_string(),
            "count": findings.len(),
            "findings": &findings,
        }))?,
        WorkspaceExportFormat::Jsonl => findings_to_jsonl(&findings)?,
    };
    fs::write(output_path, body)
        .with_context(|| format!("Could not write {}", output_path.display()))?;

    Ok(WorkspaceFindingsExport {
        output_path: output_path.to_path_buf(),
        format,
        count: findings.len(),
    })
}

fn findings_to_jsonl(findings: &[Finding]) -> Result<String> {
    let mut lines = String::new();
    for finding in findings {
        lines.push_str(&serde_json::to_string(finding)?);
        lines.push('\n');
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::Severity;

    #[test]
    fn resolves_v2_state_paths_under_project() {
        let tmp = tempfile::tempdir().unwrap();
        let target = WorkspaceTarget::new(tmp.path()).unwrap();

        assert_eq!(target.state_dir(), target.root().join(".kuzushi/v2"));
        assert_eq!(
            target.findings_db_path(),
            target.root().join(".kuzushi/v2/findings.sqlite3")
        );
    }

    #[test]
    fn exports_workspace_findings_to_json() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let store = FindingStore::open(workspace.findings_db_path()).unwrap();
        store
            .insert_scan_run("run-1", workspace.root(), "completed")
            .unwrap();
        store
            .insert_finding(
                "run-1",
                &Finding::new_tool(
                    "fixture",
                    "fixture/sql",
                    "src/app.ts",
                    10,
                    None,
                    Severity::High,
                    "request data reaches SQL",
                ),
            )
            .unwrap();

        let output = tmp.path().join("exports/findings.json");
        let report = export_workspace_findings(&workspace, &output, None).unwrap();

        assert_eq!(report.count, 1);
        assert_eq!(report.format, WorkspaceExportFormat::Json);
        let exported: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(output).unwrap()).unwrap();
        assert_eq!(exported["count"], serde_json::json!(1));
        assert_eq!(exported["findings"][0]["rule_id"], "fixture/sql");
    }

    #[test]
    fn rejects_unsupported_findings_export_extensions() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let error = export_workspace_findings(&workspace, tmp.path().join("findings.sarif"), None)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsupported workspace findings export extension"));
        assert!(error.contains(".json"));
    }
}
