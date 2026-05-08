use super::prelude::*;
use super::*;

pub(crate) fn read_threat_model(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: ReadFlavor,
) -> Result<Value> {
    let output_dir = match read_string(&input, &["outputDir", "output_dir"]) {
        Some(value) => value,
        None => {
            return Ok(json!({
                "ok": false,
                "output": format!("{} requires an outputDir.", flavor.tool_name()),
            }));
        }
    };
    let target = resolve_target(&input, ctx)?;
    let repo_name = repo_name(&target);
    let methodology = read_methodology(&input, "pasta");
    let artifacts = read_randori_artifacts(&target, &output_dir);
    let normalized_path =
        resolve_output_dir(&target, &output_dir).join("normalized-threat-model.json");
    let document = if normalized_path.exists() {
        let raw = fs::read_to_string(&normalized_path)
            .with_context(|| format!("Could not read {}", normalized_path.display()))?;
        let parsed = serde_json::from_str::<Value>(&raw)
            .with_context(|| format!("Could not parse {}", normalized_path.display()))?;
        Some(normalize_document(parsed, &methodology)?)
    } else if artifacts.has_any_artifact() {
        convert_randori_artifacts_to_document(&artifacts, &methodology)?
    } else {
        None
    };

    let Some(document) = document else {
        return Ok(json!({
            "ok": false,
            "output": format!(
                "No threat-model artifacts found under {} (resolved against {}).",
                output_dir,
                target.display()
            ),
        }));
    };
    let document = apply_methodology(document, &methodology)?;
    let threat_count = array_len(document.pointer("/threats"));
    let node_count = array_len(document.pointer("/dfd/nodes"));
    let flow_count = array_len(document.pointer("/dfd/flows"));
    let output = match flavor {
        ReadFlavor::ThreatModel => format!(
            "Loaded {} threat model for {} from {}\n  Threats: {}\n  DFD:     {} nodes · {} flows",
            methodology_label(&methodology),
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
    };

    Ok(json!({
        "ok": true,
        "output": output,
        "data": {
            "target": target.display().to_string(),
            "repoName": repo_name,
            "outputDir": output_dir,
            "methodology": methodology,
            "document": document,
            "artifacts": artifacts.to_json(),
        },
    }))
}

pub(crate) fn methodologies_output() -> Value {
    let output = [
        "Selectable threat model methodologies:",
        "- pasta: risk-first PASTA flow using Randori stages S1-S4 plus narrative synthesis.",
        "- stride: DFD + bounded STRIDE threat scenarios from the same evidence-grounded provider.",
        "- dread: DREAD risk scoring overlay over generated threat scenarios.",
    ]
    .join("\n");
    json!({
        "ok": true,
        "output": output,
        "data": {
            "methodologies": VALID_METHODOLOGIES,
            "provider": "randori-pasta",
        },
    })
}

pub(crate) const THREAT_MODEL_SYSTEM_PROMPT: &str = r#"You are Kuzushi's threat-modeling agent.
Return only JSON. Produce a normalized ThreatModelDocument with:
{"version":"2.0","dfd":{"nodes":[],"flows":[],"trustBoundaries":[]},"threats":[],"summary":{"total":0,"bySeverity":{},"byCategory":{}}}

Use camelCase field names from the schema. Do not include markdown."#;
