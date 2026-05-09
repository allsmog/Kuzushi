use super::*;

pub(crate) fn build_threat_model(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
    flavor: BuildFlavor,
) -> Result<Value> {
    let runtime = runtime.with_context(|| {
        format!(
            "{} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
            flavor.tool_name()
        )
    })?;
    let input = parse_build_input(&input, ctx, flavor)?;
    let verb = match flavor {
        BuildFlavor::ThreatModel => "build",
        BuildFlavor::RandoriPasta => "pasta",
    };
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool",
                verb,
                format!(
                    "{} start · methodology={}",
                    flavor.tool_name(),
                    input.methodology
                ),
            )
            .emit();
    }
    let previous_model = load_persistent_threat_model(&input.target);
    let prompt = build_agent_prompt(&input, previous_model.as_ref())?;
    // Phase scope so the threat-model agent's LLM round-trip surfaces under
    // dfd-collect / stride-classify / actor-stories rather than as a loose
    // top-level event.
    let _llm_scope = ctx.trace.map(|trace| {
        let phase = trace
            .step(
                "reasoning",
                verb,
                "dfd-collect · stride-classify · actor-stories",
            )
            .emit();
        trace.parent_scope(phase)
    });
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            input.model.clone(),
            input.target.clone(),
            THREAT_MODEL_SYSTEM_PROMPT.to_string(),
            prompt,
        ),
        StructuredJsonContract::new(
            flavor.tool_name(),
            "ThreatModelDocument",
            threat_model_document_schema(),
        ),
        |raw| {
            let (document_candidate, _) = extract_document_and_findings(raw.clone())?;
            normalize_document(document_candidate, &input.methodology)?;
            Ok(raw)
        },
    )?;
    drop(_llm_scope);
    let (document_candidate, bridge_findings) = extract_document_and_findings(raw)?;
    let document = normalize_document(document_candidate, &input.methodology)?;
    let document = apply_methodology(document, &input.methodology)?;
    let normalized_artifact =
        write_normalized_artifact(&input.target, &input.output_dir, &document)?;
    let persisted = if flavor.persists_document() {
        save_persistent_threat_model(&input.target, &document, !input.preserve_user_edits)?
    } else {
        false
    };
    let findings = if input.emit_findings {
        build_findings_from_document(&document)
    } else {
        bridge_findings.unwrap_or_else(Vec::new)
    };

    let threat_count = array_len(document.pointer("/threats"));
    let node_count = array_len(document.pointer("/dfd/nodes"));
    let flow_count = array_len(document.pointer("/dfd/flows"));
    let boundary_count = array_len(document.pointer("/dfd/trustBoundaries"));
    let mut lines = match flavor {
        BuildFlavor::ThreatModel => vec![
            format!(
                "threat-model:build complete for {} ({})",
                input.repo_name,
                input.target.display()
            ),
            format!("  Method:   {}", methodology_label(&input.methodology)),
            format!("  Slice:    {}", input.slice),
            format!("  Provider: {}", flavor.provider()),
            format!("  Stages:   {}", input.stages.join(", ")),
            format!("  Artifact: {}", input.output_dir),
            format!(
                "  Saved:    {}",
                if persisted {
                    ".kuzushi/threat-model.json"
                } else {
                    "skipped (operator-edited model preserved)"
                }
            ),
        ],
        BuildFlavor::RandoriPasta => vec![
            format!(
                "randori:pasta complete for {} ({})",
                input.repo_name,
                input.target.display()
            ),
            format!("  Stages:   {}", input.stages.join(", ")),
            format!("  Artifact: {}", input.output_dir),
        ],
    };
    lines.extend([
        format!("  Threats:  {threat_count}"),
        format!(
            "  DFD:      {node_count} nodes · {flow_count} flows · {boundary_count} boundaries"
        ),
        format!(
            "  Findings: {}{}",
            findings.len(),
            if input.emit_findings {
                ""
            } else {
                " (emitFindings=false)"
            }
        ),
        "  Cost:     $0.0000".to_string(),
    ]);
    append_top_threats(&mut lines, &document);
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "done",
                verb,
                format!(
                    "{} complete · {threats} threats · {nodes} nodes",
                    flavor.tool_name(),
                    threats = threat_count,
                    nodes = node_count
                ),
            )
            .emit();
    }

    Ok(json!({
        "ok": threat_count > 0 || node_count > 0 || flow_count > 0,
        "output": lines.join("\n"),
        "data": {
            "target": input.target.display().to_string(),
            "repoName": input.repo_name,
            "artifactDir": input.output_dir,
            "normalizedArtifact": normalized_artifact.display().to_string(),
            "threatModelPath": input.target.join(".kuzushi").join("threat-model.json").display().to_string(),
            "provider": flavor.provider(),
            "methodology": input.methodology,
            "slice": input.slice,
            "stages": input.stages,
            "document": document,
            "findings": findings,
            "persisted": persisted,
        },
        "costUsd": 0.0,
    }))
}
