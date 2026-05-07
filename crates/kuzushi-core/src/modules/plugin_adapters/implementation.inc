use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};

use super::agentic_sast::collect_agentic_repo_inventory;
use super::generic_findings::{
    normalize_agent_json_findings, persist_tool_findings, render_generic_findings_output,
};
use super::input::{positive_usize_input, string_array_or_csv_input, string_input_any};
use super::plugin_resolution::{resolve_required_plugin_root, PluginAdapterSpec};
use super::{
    builtin_module, dag, model_option, resolve_tool_model, resolve_tool_target, target_option,
    tool, tool_with_options, BuiltinModule, ModuleKind, ModuleRegistry, ToolExecutionContext,
};

pub(super) fn register_modules(registry: &mut ModuleRegistry) {
    registry.register(vuln_scout_module());
    registry.register(tob_module());
    registry.register(shinsa_module());
}

pub(super) fn execute_tool(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match tool_name {
        "vuln-scout:audit" => run_vuln_scout_audit(input, ctx, runtime),
        "tob:audit" => run_tob_audit(input, ctx, runtime),
        "tob:skills" => list_tob_skills(input),
        "shinsa:scan" | "shinsa:quick-check" | "shinsa:nist-scan" | "shinsa:nist-quick-check" => {
            run_shinsa_assessment(tool_name, input, ctx, runtime)
        }
        "shinsa:frameworks" => list_shinsa_frameworks(input),
        _ => anyhow::bail!("unknown plugin adapter tool {tool_name:?}"),
    }
}

fn vuln_scout_module() -> BuiltinModule {
    builtin_module(
        "vuln-scout",
        "Vuln Scout",
        ModuleKind::Offense,
        "Whitebox pentest wrapper around the @kuzushi/vuln-scout Claude Code plugin.",
        vec![tool_with_options(
            "vuln-scout:audit",
            "Run the Vuln Scout audit plugin.",
            vec![target_option(), model_option()],
        )],
        vec![dag("vuln-scout:audit", "findings", &["context:build"])],
    )
}

fn tob_module() -> BuiltinModule {
    builtin_module(
        "tob",
        "Trail of Bits Skills",
        ModuleKind::Offense,
        "Audit wrapper around the @kuzushi/tob-skills Claude Code plugin collection.",
        vec![
            tool_with_options(
                "tob:audit",
                "Run a Trail of Bits skills audit.",
                vec![target_option(), model_option()],
            ),
            tool("tob:skills", "List available Trail of Bits skill modules."),
        ],
        vec![dag("tob:audit", "findings", &["context:build"])],
    )
}

fn shinsa_module() -> BuiltinModule {
    builtin_module(
        "shinsa",
        "Shinsa Compliance",
        ModuleKind::Governance,
        "Compliance assessment wrapper around the shinsa-plugin Claude Code plugin.",
        vec![
            tool_with_options(
                "shinsa:scan",
                "Run a full ISO 27001 Annex A compliance assessment.",
                vec![target_option(), model_option()],
            ),
            tool_with_options(
                "shinsa:quick-check",
                "Run a fast ISO 27001 Annex A check.",
                vec![target_option(), model_option()],
            ),
            tool_with_options(
                "shinsa:nist-scan",
                "Run a full NIST SP 800-53 Rev 5 compliance assessment.",
                vec![target_option(), model_option()],
            ),
            tool_with_options(
                "shinsa:nist-quick-check",
                "Run a fast NIST SP 800-53 Rev 5 check.",
                vec![target_option(), model_option()],
            ),
            tool("shinsa:frameworks", "List supported compliance frameworks."),
        ],
        vec![
            dag("shinsa:scan", "assessment", &["context:build"]),
            dag("shinsa:nist-scan", "assessment", &["context:build"]),
        ],
    )
}

fn run_vuln_scout_audit(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    run_plugin_finding_adapter(
        PluginAdapterSpec {
            tool_name: "vuln-scout:audit",
            tool_slug: "vuln-scout",
            package_name: "@kuzushi/vuln-scout",
            env_var: "KUZUSHI_VULN_SCOUT_PLUGIN",
            install_hint: "pnpm add @kuzushi/vuln-scout",
            prompt_title:
                "Run a whitebox pentest audit using Vuln Scout-style read-only repository analysis.",
            allow_skill_filter: false,
        },
        input,
        ctx,
        runtime,
    )
}

fn run_tob_audit(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    validate_requested_tob_skills(&input)?;
    run_plugin_finding_adapter(
        PluginAdapterSpec {
            tool_name: "tob:audit",
            tool_slug: "tob-audit",
            package_name: "@kuzushi/tob-skills",
            env_var: "KUZUSHI_TOB_SKILLS_DIR",
            install_hint: "pnpm add @kuzushi/tob-skills",
            prompt_title:
                "Run a Trail of Bits skills-style audit using read-only repository analysis.",
            allow_skill_filter: true,
        },
        input,
        ctx,
        runtime,
    )
}

fn run_plugin_finding_adapter(
    spec: PluginAdapterSpec<'_>,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    if !target.is_dir() {
        anyhow::bail!(
            "{} target is not a directory: {}",
            spec.tool_name,
            target.display()
        );
    }
    let plugin_root = resolve_required_plugin_root(&input, spec)?;
    let runtime = runtime.context(format!(
        "{} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
        spec.tool_name
    ))?;
    let model = resolve_tool_model(spec.tool_name, &input, ctx)?;
    let max_findings =
        positive_usize_input(&input, &["maxFindings", "max_findings"], "maxFindings")?
            .unwrap_or(50)
            .min(200);
    let inventory = collect_agentic_repo_inventory(&target, 100, 4096)?;
    let raw = query_required_structured_json(
        runtime,
        AgentQueryRequest::new(
            model,
            target.clone(),
            format!(
                "You are Kuzushi's {} pi-agent-core adapter. Return only JSON matching {{\"findings\":[{{\"ruleId\":\"...\",\"filePath\":\"relative/path\",\"startLine\":1,\"severity\":\"critical|high|medium|low|info\",\"message\":\"evidence-backed finding\",\"evidence\":\"source-grounded proof\"}}]}}.",
                spec.tool_name
            ),
            build_plugin_adapter_prompt(spec, &target, &plugin_root, &input, &inventory),
        ),
        StructuredJsonContract::new(spec.tool_name, "PluginAdapterFindings", findings_schema()),
        require_json_object,
    )?;
    let findings = normalize_agent_json_findings(raw, &target, spec.tool_slug, max_findings)?;
    let persisted = persist_tool_findings(spec.tool_slug, &target, &findings, ctx)?;
    Ok(json!({
        "ok": true,
        "output": render_generic_findings_output(spec.tool_name, &target, &findings, &persisted),
        "data": {
            "target": target.display().to_string(),
            "pluginRoot": plugin_root.display().to_string(),
            "count": findings.len(),
            "findings": findings,
            "persisted": persisted,
        },
        "costUsd": 0.0,
    }))
}

fn require_json_object(value: Value) -> Result<Value> {
    if value.is_object() {
        Ok(value)
    } else {
        anyhow::bail!("plugin adapter structured output must be a JSON object")
    }
}

fn findings_schema() -> Value {
    json!({
        "type": "object",
        "required": ["findings"],
        "additionalProperties": true,
        "properties": {
            "summary": {"type": "string"},
            "findings": {"type": "array", "items": {"type": "object"}}
        }
    })
}

fn build_plugin_adapter_prompt(
    spec: PluginAdapterSpec<'_>,
    target: &Path,
    plugin_root: &Path,
    input: &Value,
    inventory: &[(String, String)],
) -> String {
    let mut lines = vec![
        spec.prompt_title.to_string(),
        format!("Target: {}", target.display()),
        format!("Resolved plugin root: {}", plugin_root.display()),
        "Use only the provided repository snippets; do not claim runtime exploitability."
            .to_string(),
    ];
    if spec.allow_skill_filter {
        if let Some(skills) = string_array_or_csv_input(input, &["skills"]) {
            lines.push(format!("Requested skills: {}", skills.join(", ")));
        }
    }
    lines.push(String::new());
    lines.push("Repository inventory and snippets:".to_string());
    for (path, snippet) in inventory {
        lines.push(format!("\n--- {path} ---\n{snippet}"));
    }
    lines.join("\n")
}

fn list_tob_skills(input: Value) -> Result<Value> {
    let declared = [
        "fp-check",
        "variant-analysis",
        "sharp-edges",
        "insecure-defaults",
        "static-analysis",
        "differential-review",
    ];
    let spec = PluginAdapterSpec {
        tool_name: "tob:skills",
        tool_slug: "tob-audit",
        package_name: "@kuzushi/tob-skills",
        env_var: "KUZUSHI_TOB_SKILLS_DIR",
        install_hint: "pnpm add @kuzushi/tob-skills",
        prompt_title: "",
        allow_skill_filter: false,
    };
    let root = match resolve_required_plugin_root(&input, spec) {
        Ok(root) => root,
        Err(error) => {
            return Ok(json!({
                "ok": false,
                "output": error.to_string(),
                "data": {
                    "declared": declared,
                    "resolvable": [],
                    "unresolved": declared,
                },
            }));
        }
    };
    let mut resolvable = Vec::new();
    for name in declared {
        let path = root.join(name);
        if path.exists() {
            resolvable.push(json!({"id": name, "path": path.display().to_string()}));
        }
    }
    let unresolved = declared
        .iter()
        .filter(|name| {
            !resolvable
                .iter()
                .any(|row| row.get("id").and_then(Value::as_str) == Some(*name))
        })
        .copied()
        .collect::<Vec<_>>();
    Ok(json!({
        "ok": true,
        "output": format!("Resolvable ToB skill plugins: {}\nDeclared but not resolvable: {}", resolvable.len(), unresolved.join(", ")),
        "data": {
            "pluginRoot": root.display().to_string(),
            "declared": declared,
            "resolvable": resolvable,
            "unresolved": unresolved,
        },
    }))
}

fn validate_requested_tob_skills(input: &Value) -> Result<()> {
    let Some(skills) = string_array_or_csv_input(input, &["skills"]) else {
        return Ok(());
    };
    let declared = [
        "fp-check",
        "variant-analysis",
        "sharp-edges",
        "insecure-defaults",
        "static-analysis",
        "differential-review",
    ];
    let unknown = skills
        .iter()
        .filter(|skill| !declared.contains(&skill.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        anyhow::bail!(
            "tob:audit unknown skill(s): {}. Valid names: {}.",
            unknown.join(", "),
            declared.join(", ")
        );
    }
    Ok(())
}

fn run_shinsa_assessment(
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

fn build_shinsa_prompt(
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

fn list_shinsa_frameworks(input: Value) -> Result<Value> {
    let spec = PluginAdapterSpec {
        tool_name: "shinsa:frameworks",
        tool_slug: "shinsa",
        package_name: "shinsa-plugin",
        env_var: "KUZUSHI_SHINSA_PLUGIN",
        install_hint: "install shinsa-plugin and set KUZUSHI_SHINSA_PLUGIN",
        prompt_title: "",
        allow_skill_filter: false,
    };
    let root = match resolve_required_plugin_root(&input, spec) {
        Ok(root) => root,
        Err(error) => {
            return Ok(json!({
                "ok": false,
                "output": error.to_string(),
                "data": {
                    "skills": [],
                    "frameworks": ["iso27001-annex-a", "nist-sp-800-53-rev5"],
                },
            }));
        }
    };
    let skills_root = root.join("skills");
    let mut skills = Vec::new();
    if let Ok(read_dir) = fs::read_dir(&skills_root) {
        for entry in read_dir.filter_map(|entry| entry.ok()) {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                skills.push(entry.file_name().to_string_lossy().to_string());
            }
        }
    }
    skills.sort();
    Ok(json!({
        "ok": true,
        "output": format!("shinsa-plugin path: {}\nSkill modules: {}", root.display(), skills.len()),
        "data": {
            "pluginRoot": root.display().to_string(),
            "skills": skills,
            "frameworks": ["iso27001-annex-a", "nist-sp-800-53-rev5"],
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_tob_skills_reports_resolvable_and_unresolved_declared_skills() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("fp-check")).unwrap();
        fs::create_dir_all(temp.path().join("static-analysis")).unwrap();

        let report =
            list_tob_skills(json!({"pluginRoot": temp.path().display().to_string()})).unwrap();

        assert_eq!(report["ok"], json!(true));
        assert_eq!(report["data"]["resolvable"].as_array().unwrap().len(), 2);
        assert!(report["data"]["unresolved"]
            .as_array()
            .unwrap()
            .contains(&json!("variant-analysis")));
    }

    #[test]
    fn list_shinsa_frameworks_lists_skill_directories_and_frameworks() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("skills").join("annex-a")).unwrap();
        fs::write(temp.path().join("skills").join("README.md"), "not a skill").unwrap();

        let report =
            list_shinsa_frameworks(json!({"pluginRoot": temp.path().display().to_string()}))
                .unwrap();

        assert_eq!(report["ok"], json!(true));
        assert_eq!(report["data"]["skills"], json!(["annex-a"]));
        assert_eq!(
            report["data"]["frameworks"],
            json!(["iso27001-annex-a", "nist-sp-800-53-rev5"])
        );
    }

    #[test]
    fn plugin_list_commands_return_actionable_json_when_root_is_missing() {
        let tob = list_tob_skills(json!({})).unwrap();
        assert_eq!(tob["ok"], json!(false));
        assert!(tob["output"]
            .as_str()
            .unwrap()
            .contains("tob:skills requires"));

        let shinsa = list_shinsa_frameworks(json!({})).unwrap();
        assert_eq!(shinsa["ok"], json!(false));
        assert!(shinsa["output"]
            .as_str()
            .unwrap()
            .contains("shinsa:frameworks requires"));
    }
}
