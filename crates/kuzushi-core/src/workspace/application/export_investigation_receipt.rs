//! Add study receipts without changing CSV or external scanner file contracts.
use super::investigation_report::InvestigationReportReceipt;
use super::*;

pub(super) fn attach_receipt(
    body: String,
    format: WorkspaceExportFormat,
    receipt: Option<&InvestigationReportReceipt>,
) -> Result<String> {
    let Some(receipt) = receipt else {
        return Ok(body);
    };
    match format {
        WorkspaceExportFormat::Json => attach_json(body, receipt, false),
        WorkspaceExportFormat::Sarif => attach_json(body, receipt, true),
        WorkspaceExportFormat::Jsonl => attach_jsonl(body, receipt),
        _ => Ok(body),
    }
}

fn attach_json(body: String, receipt: &InvestigationReportReceipt, sarif: bool) -> Result<String> {
    let mut document: serde_json::Value = serde_json::from_str(&body)?;
    let value = serde_json::to_value(receipt)?;
    if sarif {
        document["properties"]["kuzushiExport"]["investigation"] = value.clone();
        for run in document["runs"]
            .as_array_mut()
            .context("SARIF runs missing")?
        {
            run["properties"]["kuzushiExport"]["investigation"] = value.clone();
        }
    } else {
        document["metadata"]["investigation"] = value;
    }
    Ok(serde_json::to_string_pretty(&document)?)
}

fn attach_jsonl(body: String, receipt: &InvestigationReportReceipt) -> Result<String> {
    let (metadata, rows) = body.split_once('\n').context("JSONL metadata missing")?;
    let mut metadata: serde_json::Value = serde_json::from_str(metadata)?;
    metadata["metadata"]["investigation"] = serde_json::to_value(receipt)?;
    Ok(format!("{}\n{rows}", serde_json::to_string(&metadata)?))
}

pub(super) fn receipt_output_path(
    workspace: &WorkspaceTarget,
    output: &Path,
    format: WorkspaceExportFormat,
) -> Result<PathBuf> {
    let path = if format == WorkspaceExportFormat::MarkdownBundle {
        output.join("investigation.json")
    } else {
        let name = output.file_name().context("export needs a file name")?;
        let mut receipt_name = name.to_os_string();
        receipt_name.push(".investigation.json");
        output.with_file_name(receipt_name)
    };
    crate::workspace::resolve_contained_output_path(workspace.root(), &path)
        .context("investigation receipt must resolve inside the workspace")
}

pub(super) fn write_receipt(path: &Path, receipt: &InvestigationReportReceipt) -> Result<()> {
    crate::fs_atomic::write_atomic(path, &serde_json::to_string_pretty(receipt)?)
        .with_context(|| format!("could not write investigation receipt {}", path.display()))
}

pub(super) fn attach_bundle_receipt(
    output: &Path,
    receipt: &InvestigationReportReceipt,
) -> Result<()> {
    let path = output.join("manifest.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    manifest["metadata"]["investigation"] = serde_json::to_value(receipt)?;
    let readme_path = output.join("README.md");
    let mut readme = fs::read_to_string(&readme_path)?;
    readme.push_str(&bundle_receipt_summary(receipt));
    fs::write(&readme_path, &readme)?;
    let files = manifest["files"]
        .as_array_mut()
        .context("bundle file manifest missing")?;
    update_readme_digest(files, &readme)?;
    let body = fs::read(output.join("investigation.json"))?;
    files.push(json!({"path": "investigation.json", "sha256": text_digest(&body)}));
    fs::write(path, serde_json::to_string_pretty(&manifest)?)?;
    Ok(())
}

fn update_readme_digest(files: &mut [serde_json::Value], readme: &str) -> Result<()> {
    let entry = files
        .iter_mut()
        .find(|entry| entry["path"] == "README.md")
        .context("bundle README manifest entry missing")?;
    entry["sha256"] = json!(text_digest(readme.as_bytes()));
    Ok(())
}

fn text_digest(body: &[u8]) -> String {
    format!(
        "sha256:{}",
        kuzushi_mcp_common::cache::sha256_hex_bytes(body)
    )
}

fn bundle_receipt_summary(receipt: &InvestigationReportReceipt) -> String {
    let work = &receipt.occurrence;
    format!("\n## Investigation receipt\n\n{} of {} planned jobs completed; {} failed; {} pending.\n\nCompleted jobs do not establish complete repository coverage. A missing observation does not establish a fix.\n\n[Read the source, context, recurrence and shared allowance receipts](investigation.json).\n", work.completed, work.planned, work.failed, work.pending)
}

#[cfg(test)]
mod tests;
