use super::items_3::require_json_object;
use super::prelude::*;
use super::*;

pub(in crate::modules) fn run_shinsa_assessment(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let spec = PluginAdapterSpec {
        tool_name,
        tool_slug: "shinsa",
        package_name: "shinsa-plugin",
        env_var: "KUZUSHI_SHINSA_PLUGIN",
        install_hint: "install shinsa-plugin and set KUZUSHI_SHINSA_PLUGIN",
        prompt_title: "",
        allow_skill_filter: false,
    };
    let plugin_root = resolve_required_plugin_root(&input, spec)?;
    let runtime = runtime.context(format!(
        "{tool_name} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies."
    ))?;
    let model = resolve_tool_model(tool_name, &input, ctx)?;
    let mode = match tool_name {
        "shinsa:scan" => "compliance-scan",
        "shinsa:quick-check" => "quick-check",
        "shinsa:nist-scan" => "nist-scan",
        "shinsa:nist-quick-check" => "nist-quick-check",
        _ => "compliance-scan",
    };
    let output_dir = string_input_any(&input, &["outputDir", "output_dir"])
        .unwrap_or_else(|| "shinsa-output".to_string());
    let inventory = collect_agentic_repo_inventory(&target, 100, 4096)?;
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            target.clone(),
            "You are Kuzushi's Shinsa compliance adapter. Return only JSON with summary, findings, controls, and maturity.".to_string(),
            build_shinsa_prompt(mode, &output_dir, &plugin_root, &input, &inventory),
        ),
        StructuredJsonContract::new(tool_name, "ShinsaReport", findings_schema()),
        require_json_object,
    )?;
    let findings = normalize_agent_json_findings(raw.clone(), &target, "shinsa", 100)?;
    let persisted = persist_tool_findings("shinsa", &target, &findings, ctx)?;
    let out_root = target.join(&output_dir);
    fs::create_dir_all(&out_root)
        .with_context(|| format!("Could not create {}", out_root.display()))?;
    let state_path = out_root.join("shinsa-state.json");
    let report_path = out_root.join("compliance-report.md");
    fs::write(
        &state_path,
        format!("{}\n", serde_json::to_string_pretty(&raw)?),
    )?;
    fs::write(
        &report_path,
        format!(
            "# Shinsa Compliance Report\n\nMode: {mode}\nFindings: {}\n",
            findings.len()
        ),
    )?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "{tool_name} complete\n  Mode:     {mode}\n  Output:   {}/\n  Artifacts: shinsa-state.json compliance-report.md\n  Findings: {}",
            output_dir,
            findings.len()
        ),
        "data": {
            "target": target.display().to_string(),
            "mode": mode,
            "pluginRoot": plugin_root.display().to_string(),
            "outputDir": output_dir,
            "statePath": state_path.display().to_string(),
            "reportPath": report_path.display().to_string(),
            "findings": findings,
            "persisted": persisted,
        },
        "costUsd": 0.0,
    }))
}

pub(in crate::modules) fn build_shinsa_prompt(
    mode: &str,
    output_dir: &str,
    plugin_root: &Path,
    input: &Value,
    inventory: &[(String, String)],
) -> String {
    let mut lines = vec![
        format!("Run a {mode} compliance assessment over the provided repository snippets."),
        format!("Resolved plugin root: {}", plugin_root.display()),
        format!("Artifact output directory: {output_dir}"),
        "Ground every finding in file and line evidence. Do not speculate about unread code."
            .to_string(),
    ];
    if let Some(controls) = string_array_or_csv_input(input, &["controls"]) {
        lines.push(format!("Controls filter: {}", controls.join(", ")));
    }
    if let Some(family) = string_input_any(input, &["family"]) {
        lines.push(format!("Family filter: {family}"));
    }
    if let Some(severity) = string_array_or_csv_input(input, &["severity"]) {
        lines.push(format!("Severity filter: {}", severity.join(", ")));
    }
    lines.push(String::new());
    lines.push("Repository inventory and snippets:".to_string());
    for (path, snippet) in inventory {
        lines.push(format!("\n--- {path} ---\n{snippet}"));
    }
    lines.join("\n")
}
