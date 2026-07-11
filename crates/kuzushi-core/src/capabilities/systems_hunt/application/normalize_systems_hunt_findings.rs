use super::*;
use super::normalize_systems_hunt_candidate::*;

pub(crate) fn normalize_systems_hunt_findings(
    raw: Value,
    target: &Path,
    context: &SystemsContextOutput,
    artifact_root: &Path,
    max_findings: usize,
) -> Result<(Vec<Finding>, Vec<String>)> {
    let mut findings = Vec::new();
    let mut artifacts = Vec::new();
    let Some(items) = raw.get("findings").and_then(Value::as_array) else {
        return Ok((findings, artifacts));
    };

    for item in items.iter().take(max_findings) {
        let Some(candidate) = parse_systems_hunt_candidate(item) else {
            continue;
        };
        if candidate.is_under_evidenced() {
            artifacts.push(write_rejected_candidate(target, artifact_root, candidate.object)?);
            continue;
        }

        let mut finding = build_systems_hunt_finding(&candidate);
        let artifact = build_systems_hunt_artifact(&candidate, context, &finding);
        let relative_artifact = write_finding_artifact(target, artifact_root, &finding, &artifact)?;
        attach_artifact_path(&mut finding, &relative_artifact);
        artifacts.push(relative_artifact);
        findings.push(finding);
    }
    Ok((findings, artifacts))
}

fn write_finding_artifact(
    target: &Path,
    artifact_root: &Path,
    finding: &Finding,
    artifact: &Value,
) -> Result<String> {
    let artifact_path = write_artifact(target, artifact_root, &finding.fingerprint, artifact)?;
    Ok(path_relative_to(target, &artifact_path))
}

fn write_rejected_candidate(
    target: &Path,
    artifact_root: &Path,
    object: &serde_json::Map<String, Value>,
) -> Result<String> {
    let artifact_path = write_rejected_systems_candidate_artifact(target, artifact_root, object)?;
    Ok(path_relative_to(target, &artifact_path))
}

fn write_rejected_systems_candidate_artifact(
    target: &Path,
    artifact_root: &Path,
    object: &serde_json::Map<String, Value>,
) -> Result<PathBuf> {
    let fingerprint = rejected_candidate_fingerprint(object);
    let artifact = json!({
        "fingerprint": fingerprint,
        "rejected": true,
        "rejectionReason": "under-evidenced systems-hunt candidate: no evidence, invariant link, trigger link, cheap verification flag, or corroboration status",
        "candidate": object,
    });
    write_artifact(target, artifact_root, &fingerprint, &artifact)
}

fn rejected_candidate_fingerprint(object: &serde_json::Map<String, Value>) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    "systems-hunt-rejected-candidate".hash(&mut hasher);
    object
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .hash(&mut hasher);
    object
        .get("filePath")
        .or_else(|| object.get("file_path"))
        .or_else(|| object.get("path"))
        .or_else(|| object.get("file"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .hash(&mut hasher);
    object
        .get("startLine")
        .or_else(|| object.get("line"))
        .map(Value::to_string)
        .unwrap_or_default()
        .hash(&mut hasher);
    format!("systems-hunt-rejected-{:016x}", hasher.finish())
}
