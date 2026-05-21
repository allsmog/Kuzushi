use super::*;

pub(crate) fn read_threat_model(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: ReadFlavor,
) -> Result<Value> {
    let Some(output_dir) = read_string(&input, &["outputDir", "output_dir"]) else {
        return Ok(missing_output_dir_response(flavor));
    };
    let target = resolve_target(&input, ctx)?;
    let repo_name = repo_name(&target);
    let methodology = read_methodology(&input, "pasta");
    let artifacts = read_randori_artifacts(&target, &output_dir);
    let Some(document) = read_threat_model_document(&target, &output_dir, &methodology, &artifacts)?
    else {
        return Ok(missing_threat_model_artifacts_response(&target, &output_dir));
    };
    let document = apply_methodology(document, &methodology)?;
    Ok(read_threat_model_response(ReadThreatModelResponse {
        flavor,
        target,
        repo_name,
        output_dir,
        methodology,
        document,
        artifacts,
    }))
}

fn missing_output_dir_response(flavor: ReadFlavor) -> Value {
    crate::module_result::failed_output_result(
        format!("{} rejected input", flavor.tool_name()),
        format!("{} requires an outputDir.", flavor.tool_name()),
        json!({ "reason": "missing-output-dir" }),
    )
}

fn read_threat_model_document(
    target: &Path,
    output_dir: &str,
    methodology: &str,
    artifacts: &RandoriArtifacts,
) -> Result<Option<Value>> {
    let normalized_path =
        resolve_output_dir(target, output_dir).join("normalized-threat-model.json");
    if normalized_path.exists() {
        return read_normalized_threat_model(&normalized_path, methodology).map(Some);
    }
    if artifacts.has_any_artifact() {
        return convert_randori_artifacts_to_document(artifacts, methodology);
    }
    Ok(None)
}

fn read_normalized_threat_model(path: &Path, methodology: &str) -> Result<Value> {
    let raw = fs::read_to_string(path).with_context(|| format!("Could not read {}", path.display()))?;
    let parsed = serde_json::from_str::<Value>(&raw)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    normalize_document(parsed, methodology)
}

fn missing_threat_model_artifacts_response(target: &Path, output_dir: &str) -> Value {
    let output = format!(
            "No threat-model artifacts found under {} (resolved against {}).",
            output_dir,
            target.display()
        );
    crate::module_result::failed_output_result(
        "threat-model artifacts not found",
        output,
        json!({
            "reason": "artifacts-not-found",
            "target": target.display().to_string(),
            "outputDir": output_dir,
        }),
    )
}

struct ReadThreatModelResponse {
    flavor: ReadFlavor,
    target: PathBuf,
    repo_name: String,
    output_dir: String,
    methodology: String,
    document: Value,
    artifacts: RandoriArtifacts,
}

fn read_threat_model_response(response: ReadThreatModelResponse) -> Value {
    let threat_count = array_len(response.document.pointer("/threats"));
    let node_count = array_len(response.document.pointer("/dfd/nodes"));
    let flow_count = array_len(response.document.pointer("/dfd/flows"));
    let output = read_threat_model_output(
        response.flavor,
        &response.methodology,
        &response.repo_name,
        &response.output_dir,
        threat_count,
        node_count,
        flow_count,
    );
    let data = json!({
        "target": response.target.display().to_string(),
        "repoName": response.repo_name,
        "outputDir": response.output_dir,
        "methodology": response.methodology,
        "document": response.document,
        "artifacts": response.artifacts.to_json(),
    });
    crate::module_result::completed_output_result(output.clone(), output, data)
}

fn read_threat_model_output(
    flavor: ReadFlavor,
    methodology: &str,
    repo_name: &str,
    output_dir: &str,
    threat_count: usize,
    node_count: usize,
    flow_count: usize,
) -> String {
    match flavor {
        ReadFlavor::ThreatModel => format!(
            "Loaded {} threat model for {} from {}\n  Threats: {}\n  DFD:     {} nodes · {} flows",
            methodology_label(methodology),
            repo_name,
            output_dir,
            threat_count,
            node_count,
            flow_count
        ),
        ReadFlavor::Randori => format!(
            "Loaded threat model for {} from {}\n  Threats: {}\n  DFD:     {} nodes · {} flows",
            repo_name, output_dir, threat_count, node_count, flow_count
        ),
    }
}

pub(crate) fn methodologies_output() -> Value {
    let output = [
        "Selectable threat model methodologies:",
        "- pasta: risk-first PASTA flow using Randori stages S1-S4 plus narrative synthesis.",
        "- stride: DFD + bounded STRIDE threat scenarios from the same evidence-grounded provider.",
        "- dread: DREAD risk scoring overlay over generated threat scenarios.",
    ]
    .join("\n");
    let data = json!({
        "methodologies": VALID_METHODOLOGIES,
        "provider": "randori-pasta",
    });
    crate::module_result::completed_output_result(output.clone(), output, data)
}

pub(crate) const THREAT_MODEL_SYSTEM_PROMPT: &str = r#"You are Kuzushi's threat-modeling agent.
Return only JSON. Produce a normalized ThreatModelDocument with:
{"version":"2.0","dfd":{"nodes":[],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{"total":0,"bySeverity":{},"byCategory":{}}}

Use camelCase field names from the schema. Do not include markdown."#;
