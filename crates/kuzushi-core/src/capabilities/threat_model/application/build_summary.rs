use super::*;

pub(super) struct ThreatModelSummary {
    pub(super) threat_count: usize,
    pub(super) node_count: usize,
    pub(super) flow_count: usize,
    pub(super) boundary_count: usize,
}

pub(super) fn threat_model_summary(document: &Value) -> ThreatModelSummary {
    ThreatModelSummary {
        threat_count: array_len(document.pointer("/threats")),
        node_count: array_len(document.pointer("/dfd/nodes")),
        flow_count: array_len(document.pointer("/dfd/flows")),
        boundary_count: array_len(document.pointer("/dfd/trustBoundaries")),
    }
}

pub(super) fn threat_model_output_lines(
    flavor: BuildFlavor,
    input: &BuildInput,
    summary: &ThreatModelSummary,
    finding_count: usize,
    persisted: bool,
) -> Vec<String> {
    let mut lines = threat_model_header_lines(flavor, input, persisted);
    lines.extend(threat_model_metric_lines(input, summary, finding_count));
    lines
}

pub(super) fn emit_threat_model_done(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    flavor: BuildFlavor,
    summary: &ThreatModelSummary,
) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                verb,
                format!(
                    "{} complete · {threats} threats · {nodes} nodes",
                    flavor.tool_name(),
                    threats = summary.threat_count,
                    nodes = summary.node_count
                ),
            )
            .emit();
    }
}

pub(super) fn threat_model_artifacts(
    normalized_artifact: &Path,
    persistent_artifact: &Path,
    persisted: bool,
) -> Vec<Value> {
    let mut artifacts = vec![json!({
        "label": "normalized threat model",
        "path": normalized_artifact.display().to_string(),
        "kind": "json",
    })];
    if persisted {
        artifacts.push(json!({
            "label": "persistent threat model",
            "path": persistent_artifact.display().to_string(),
            "kind": "json",
        }));
    }
    artifacts
}

fn threat_model_header_lines(
    flavor: BuildFlavor,
    input: &BuildInput,
    persisted: bool,
) -> Vec<String> {
    match flavor {
        BuildFlavor::ThreatModel => threat_model_build_header_lines(input, persisted),
        BuildFlavor::RandoriPasta => randori_pasta_header_lines(input),
    }
}

fn threat_model_build_header_lines(input: &BuildInput, persisted: bool) -> Vec<String> {
    vec![
        format!(
            "threat-model:build complete for {} ({})",
            input.repo_name,
            input.target.display()
        ),
        format!("  Method:   {}", methodology_label(&input.methodology)),
        format!("  Slice:    {}", input.slice),
        format!("  Provider: {}", BuildFlavor::ThreatModel.provider()),
        format!("  Stages:   {}", input.stages.join(", ")),
        format!("  Artifact: {}", input.output_dir),
        format!("  Saved:    {}", saved_threat_model_status(persisted)),
    ]
}

fn randori_pasta_header_lines(input: &BuildInput) -> Vec<String> {
    vec![
        format!(
            "randori:pasta complete for {} ({})",
            input.repo_name,
            input.target.display()
        ),
        format!("  Stages:   {}", input.stages.join(", ")),
        format!("  Artifact: {}", input.output_dir),
    ]
}

fn saved_threat_model_status(persisted: bool) -> &'static str {
    if persisted {
        ".kuzushi/threat-model.json"
    } else {
        "skipped (operator-edited model preserved)"
    }
}

fn threat_model_metric_lines(
    input: &BuildInput,
    summary: &ThreatModelSummary,
    finding_count: usize,
) -> [String; 4] {
    [
        format!("  Threats:  {}", summary.threat_count),
        format!(
            "  DFD:      {} nodes · {} flows · {} boundaries",
            summary.node_count, summary.flow_count, summary.boundary_count
        ),
        format!(
            "  Findings: {}{}",
            finding_count,
            findings_suppressed_suffix(input.emit_findings)
        ),
        "  Cost:     $0.0000".to_string(),
    ]
}

fn findings_suppressed_suffix(emit_findings: bool) -> &'static str {
    if emit_findings {
        ""
    } else {
        " (emitFindings=false)"
    }
}
