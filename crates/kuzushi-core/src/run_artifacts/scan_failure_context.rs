//! Keep already-written Scan receipts in failed and canceled terminal results.
use super::*;
use serde_json::{json, Value};

pub(super) fn attach(record: ToolRunRecord<'_>, mut output: Value) -> Result<Value> {
    if record.tool != "sast:scan" {
        return Ok(output);
    }
    let stages = phase_stages(record)?;
    if stages.is_empty() {
        return Ok(output);
    }
    let findings = retained_findings(record)?;
    let data = scan_data(&mut output)?;
    data.insert("phaseStages".into(), json!(stages));
    data.insert("runId".into(), json!(record.run_id));
    if let Some(findings) = findings {
        data.insert("findingsCount".into(), json!(findings.len()));
        output["summary"] = json!(format!(
            "{} · {} observation(s) retained",
            output["summary"].as_str().unwrap_or("Scan stopped"),
            findings.len()
        ));
    }
    attach_native_coverage(record, &mut output)?;
    Ok(output)
}

fn scan_data(output: &mut Value) -> Result<&mut serde_json::Map<String, Value>> {
    if !output["data"].is_object() {
        output["data"] = json!({});
    }
    output
        .get_mut("data")
        .and_then(Value::as_object_mut)
        .context("Scan failure result lacks structured data")
}

fn attach_native_coverage(record: ToolRunRecord<'_>, output: &mut Value) -> Result<()> {
    if let Some(body) = artifact_text(record, "native-coverage.json")? {
        let coverage: Value =
            serde_json::from_str(&body).context("invalid retained native coverage")?;
        anyhow::ensure!(
            coverage.is_object(),
            "invalid retained native coverage object"
        );
        output["data"]["nativeCoverage"] = coverage;
    }
    Ok(())
}

fn phase_stages(record: ToolRunRecord<'_>) -> Result<Vec<PhaseStageReceipt>> {
    let Some(body) = artifact_text(record, SAST_PHASE_STAGES_JSONL_FILE)? else {
        return Ok(Vec::new());
    };
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("invalid retained Scan phase receipt"))
        .collect()
}

fn retained_findings(record: ToolRunRecord<'_>) -> Result<Option<Vec<crate::findings::Finding>>> {
    artifact_text(record, "findings.json")?
        .map(|body| serde_json::from_str(&body).context("invalid retained Scan observations"))
        .transpose()
}

fn artifact_text(record: ToolRunRecord<'_>, leaf: &str) -> Result<Option<String>> {
    match read_run_artifact_text(record.target, record.run_id, leaf) {
        RunArtifactRead::Missing { .. } => Ok(None),
        read => read
            .require("Retained Scan evidence")
            .map(|(_, body)| Some(body)),
    }
}

#[cfg(test)]
mod tests;
