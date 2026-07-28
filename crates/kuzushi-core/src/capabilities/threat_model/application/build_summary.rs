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
    has_concrete_content: bool,
    cost: crate::runtime::RuntimeCostReport,
) -> Vec<String> {
    let mut lines = threat_model_header_lines(flavor, input, persisted, has_concrete_content);
    lines.extend(threat_model_metric_lines(
        input,
        summary,
        finding_count,
        cost,
    ));
    lines
}

pub(super) fn emit_threat_model_terminal(
    ctx: &ToolExecutionContext<'_>,
    verb: &str,
    flavor: BuildFlavor,
    summary: &ThreatModelSummary,
    has_concrete_content: bool,
) {
    if let Some(trace) = ctx.trace {
        let mut terminal = trace.step(
            terminal_trace_kind(has_concrete_content),
            verb,
            threat_model_terminal_label(flavor, summary, has_concrete_content),
        );
        if !has_concrete_content {
            terminal = terminal.with_severity("warn");
        }
        let _ = terminal.emit();
    }
}

fn terminal_trace_kind(has_concrete_content: bool) -> &'static str {
    if has_concrete_content {
        "done"
    } else {
        "tool-progress"
    }
}

fn threat_model_terminal_label(
    flavor: BuildFlavor,
    summary: &ThreatModelSummary,
    has_concrete_content: bool,
) -> String {
    let status = evidence_status(has_concrete_content);
    format!(
        "{} {status} · {threats} threats · {nodes} nodes",
        flavor.tool_name(),
        threats = summary.threat_count,
        nodes = summary.node_count
    )
}

pub(super) fn threat_model_artifacts(
    normalized_artifact: &Path,
    markdown_artifact: &Path,
    persistent_artifact: &Path,
    persisted: bool,
) -> Vec<Value> {
    let mut artifacts = vec![
        json!({
            "label": "normalized threat model",
            "path": normalized_artifact.display().to_string(),
            "kind": "json",
        }),
        json!({
            "label": "harness-schema threat model (markdown)",
            "path": markdown_artifact.display().to_string(),
            "kind": "markdown",
        }),
    ];
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
    has_concrete_content: bool,
) -> Vec<String> {
    match flavor {
        BuildFlavor::ThreatModel => {
            threat_model_build_header_lines(input, persisted, has_concrete_content)
        }
        BuildFlavor::RandoriPasta => randori_pasta_header_lines(input, has_concrete_content),
    }
}

fn threat_model_build_header_lines(
    input: &BuildInput,
    persisted: bool,
    has_concrete_content: bool,
) -> Vec<String> {
    let mut lines = vec![
        format!(
            "threat-model:build {} for {} ({})",
            evidence_status(has_concrete_content),
            input.repo_name,
            input.target.display()
        ),
        format!("  Method:   {}", methodology_label(&input.methodology)),
        format!("  Slice:    {}", input.slice),
    ];
    append_pasta_stages(&mut lines, input);
    lines.extend([
        format!("  Artifact: {}", input.output_dir),
        format!(
            "  Saved:    {}",
            saved_threat_model_status(persisted, has_concrete_content, &input.target)
        ),
    ]);
    lines
}

fn randori_pasta_header_lines(input: &BuildInput, has_concrete_content: bool) -> Vec<String> {
    let mut lines = vec![format!(
        "randori:pasta {} for {} ({})",
        evidence_status(has_concrete_content),
        input.repo_name,
        input.target.display()
    )];
    append_pasta_stages(&mut lines, input);
    lines.push(format!("  Artifact: {}", input.output_dir));
    lines
}

fn append_pasta_stages(lines: &mut Vec<String>, input: &BuildInput) {
    if input.methodology == "pasta" {
        lines.push(format!("  PASTA stages: {}", input.stages.join(", ")));
    }
}

fn evidence_status(has_concrete_content: bool) -> &'static str {
    if has_concrete_content {
        "complete"
    } else {
        "partial — inadequate evidence"
    }
}

fn saved_threat_model_status(persisted: bool, has_concrete_content: bool, target: &Path) -> String {
    let path = persistent_threat_model_path(target);
    if persisted {
        path.strip_prefix(target)
            .unwrap_or(path.as_path())
            .display()
            .to_string()
    } else if has_concrete_content {
        "skipped (operator-edited model preserved)".to_string()
    } else if path.exists() {
        "skipped (inadequate candidate; previous model preserved)".to_string()
    } else {
        "skipped (inadequate candidate; no durable model written)".to_string()
    }
}

fn threat_model_metric_lines(
    input: &BuildInput,
    summary: &ThreatModelSummary,
    finding_count: usize,
    cost: crate::runtime::RuntimeCostReport,
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
        format!("  Cost:     {}", threat_model_cost_label(cost)),
    ]
}

fn threat_model_cost_label(cost: crate::runtime::RuntimeCostReport) -> String {
    if cost.is_unavailable() {
        return "unavailable".to_string();
    }
    match cost.exact_usd() {
        Some(exact) => format!("${exact:.4}"),
        None => format!(">=${:.4} (incomplete)", cost.observed_usd()),
    }
}

fn findings_suppressed_suffix(emit_findings: bool) -> &'static str {
    if emit_findings {
        ""
    } else {
        " (emitFindings=false)"
    }
}
