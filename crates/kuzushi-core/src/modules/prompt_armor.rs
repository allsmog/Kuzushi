use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::runtime::{AgentQueryRequest, AgentRuntime};

use super::generic_findings::{normalize_agent_json_findings, persist_tool_findings};
use super::plugin_resolution::{resolve_required_plugin_root, PluginAdapterSpec};
use super::{
    builtin_module, collect_agentic_repo_inventory, dag, json_summary, model_option, opt,
    parse_json_object_from_agent_text, read_bool_any, resolve_input_path, resolve_tool_model,
    resolve_tool_target, string_input_any, target_option, tool_with_options, BuiltinModule,
    ModuleKind, OptionType, ToolExecutionContext,
};

pub(super) fn module() -> BuiltinModule {
    builtin_module(
        "prompt-armor",
        "PromptArmor",
        ModuleKind::Offense,
        "LLM red-team wrapper around promptarmor-plugin attack suites and mutations.",
        vec![
            tool_with_options(
                "prompt-armor:scan",
                "Run a full LLM red-team scan.",
                vec![
                    target_option(),
                    opt(
                        "authorized",
                        OptionType::Bool,
                        "Confirm authorization to test.",
                    )
                    .default(json!(false)),
                    opt(
                        "payload",
                        OptionType::String,
                        "Single attack payload to test.",
                    )
                    .evasion(),
                    model_option(),
                ],
            ),
            tool_with_options(
                "prompt-armor:analyze",
                "Statically analyze prompt-injection surface.",
                vec![target_option(), model_option()],
            ),
            tool_with_options(
                "prompt-armor:attack",
                "Send a single authorized attack payload and judge the response.",
                vec![
                    target_option(),
                    opt(
                        "authorized",
                        OptionType::Bool,
                        "Confirm authorization to test.",
                    )
                    .default(json!(false)),
                    opt(
                        "payload",
                        OptionType::String,
                        "Single attack payload to test.",
                    )
                    .evasion(),
                    model_option(),
                ],
            ),
            tool_with_options(
                "prompt-armor:diff",
                "Diff two prior red-team runs.",
                vec![
                    opt("runA", OptionType::Path, "Baseline prompt-armor run path.").required(),
                    opt(
                        "runB",
                        OptionType::Path,
                        "Comparison prompt-armor run path.",
                    )
                    .required(),
                ],
            ),
            tool_with_options(
                "prompt-armor:report",
                "Generate a consolidated red-team report.",
                vec![target_option()],
            ),
            tool_with_options(
                "prompt-armor:config",
                "Inspect or scaffold promptarmor.yaml.",
                vec![target_option()],
            ),
        ],
        vec![dag("prompt-armor:scan", "findings", &["context:build"])],
    )
}

pub(super) fn execute_tool(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match tool_name {
        "prompt-armor:config" => config(input, ctx),
        "prompt-armor:diff" => diff(input, ctx),
        "prompt-armor:report" => report(input, ctx),
        "prompt-armor:scan" | "prompt-armor:attack" | "prompt-armor:analyze" => {
            runtime_tool(tool_name, input, ctx, runtime)
        }
        _ => anyhow::bail!("unknown prompt-armor tool {tool_name:?}"),
    }
}

fn runtime_tool(
    tool_name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let command = tool_name.trim_start_matches("prompt-armor:");
    if matches!(command, "scan" | "attack")
        && !read_bool_any(&input, &["authorized"])?.unwrap_or(false)
    {
        return Ok(json!({
            "ok": false,
            "output": format!("{tool_name} refuses to run: pass authorized=true to confirm you have authorization to test the target endpoint. This command can generate real traffic."),
        }));
    }
    let target = resolve_tool_target(&input, ctx)?;
    let spec = PluginAdapterSpec {
        tool_name,
        tool_slug: "prompt-armor",
        package_name: "promptarmor-plugin",
        env_var: "KUZUSHI_PROMPT_ARMOR_PLUGIN",
        install_hint: "install promptarmor-plugin and set KUZUSHI_PROMPT_ARMOR_PLUGIN",
        prompt_title: "",
        allow_skill_filter: false,
    };
    let plugin_root = resolve_required_plugin_root(&input, spec)?;
    let runtime = runtime.context(format!(
        "{tool_name} requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies."
    ))?;
    let model = resolve_tool_model(tool_name, &input, ctx)?;
    let inventory = collect_agentic_repo_inventory(&target, 100, 4096)?;
    let response = runtime.query_blocking(AgentQueryRequest::new(
        model,
        target.clone(),
        "You are Kuzushi's PromptArmor adapter. Return only JSON with findings and summary. Ground findings in source snippets when doing static analyze.".to_string(),
        build_prompt(command, &plugin_root, &input, &inventory),
    ))?;
    let raw = response.structured.unwrap_or_else(|| {
        parse_json_object_from_agent_text(&response.text).unwrap_or(json!({"findings": []}))
    });
    let findings = normalize_agent_json_findings(raw, &target, "prompt-armor", 100)?;
    let persisted = persist_tool_findings("prompt-armor", &target, &findings, ctx)?;
    let output_dir = target.join(".prompt-armor");
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("Could not create {}", output_dir.display()))?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "{tool_name} complete\n  Command: /{command}\n  Output: .prompt-armor/\n  Findings: {}",
            findings.len()
        ),
        "data": {
            "target": target.display().to_string(),
            "pluginRoot": plugin_root.display().to_string(),
            "command": command,
            "outputDir": output_dir.display().to_string(),
            "findings": findings,
            "persisted": persisted,
        },
        "costUsd": 0.0,
    }))
}

fn build_prompt(
    command: &str,
    plugin_root: &Path,
    input: &Value,
    inventory: &[(String, String)],
) -> String {
    let mut lines = vec![
        format!("Run PromptArmor /{command} using the provided inputs."),
        format!("Resolved plugin root: {}", plugin_root.display()),
        "For scan and attack, the caller has supplied the required authorization gate.".to_string(),
    ];
    for key in [
        "endpoint",
        "suites",
        "mutations",
        "config",
        "paths",
        "focus",
        "attack",
        "mutation",
        "payload",
    ] {
        if let Some(value) = input.get(key) {
            lines.push(format!("{key}: {}", json_summary(value)));
        }
    }
    lines.push(String::new());
    lines.push("Repository inventory and snippets:".to_string());
    for (path, snippet) in inventory {
        lines.push(format!("\n--- {path} ---\n{snippet}"));
    }
    lines.join("\n")
}

fn config(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let path = target.join("promptarmor.yaml");
    let action = string_input_any(&input, &["action"]).unwrap_or_else(|| "show".to_string());
    if action == "init" && !path.exists() {
        fs::write(
            &path,
            "version: 1\nsuites:\n  - injection\n  - tool-abuse\nmutations: []\n",
        )
        .with_context(|| format!("Could not write {}", path.display()))?;
    }
    let exists = path.exists();
    let body = if exists {
        fs::read_to_string(&path).unwrap_or_default()
    } else {
        String::new()
    };
    Ok(json!({
        "ok": true,
        "output": if exists {
            format!("prompt-armor:config {action}\nConfig: {}", path.display())
        } else {
            format!("prompt-armor:config found no promptarmor.yaml at {}. Run with {{\"action\":\"init\"}} to scaffold one.", path.display())
        },
        "data": {
            "path": path.display().to_string(),
            "exists": exists,
            "content": body,
        },
    }))
}

fn diff(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let run_a =
        string_input_any(&input, &["runA", "run_a"]).context("prompt-armor:diff requires runA")?;
    let run_b =
        string_input_any(&input, &["runB", "run_b"]).context("prompt-armor:diff requires runB")?;
    let path_a = resolve_input_path(&target, &run_a);
    let path_b = resolve_input_path(&target, &run_b);
    let text_a = fs::read_to_string(&path_a).with_context(|| {
        format!(
            "Could not read prompt-armor diff input {}",
            path_a.display()
        )
    })?;
    let text_b = fs::read_to_string(&path_b).with_context(|| {
        format!(
            "Could not read prompt-armor diff input {}",
            path_b.display()
        )
    })?;
    let delta = text_b.lines().count() as isize - text_a.lines().count() as isize;
    Ok(json!({
        "ok": true,
        "output": format!("prompt-armor:diff complete\n  runA: {}\n  runB: {}\n  lineDelta: {}", path_a.display(), path_b.display(), delta),
        "data": {
            "runA": path_a.display().to_string(),
            "runB": path_b.display().to_string(),
            "lineDelta": delta,
        },
    }))
}

fn report(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let target = resolve_tool_target(&input, ctx)?;
    let out_dir = target.join(".prompt-armor");
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("Could not create {}", out_dir.display()))?;
    let output = string_input_any(&input, &["output"])
        .map(|path| resolve_input_path(&target, &path))
        .unwrap_or_else(|| out_dir.join("report.md"));
    let mut entries = Vec::new();
    if let Ok(read_dir) = fs::read_dir(&out_dir) {
        for entry in read_dir.filter_map(|entry| entry.ok()) {
            entries.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    entries.sort();
    let body = format!(
        "# PromptArmor Report\n\nArtifacts in `.prompt-armor`: {}\n",
        if entries.is_empty() {
            "none".to_string()
        } else {
            entries.join(", ")
        }
    );
    fs::write(&output, &body).with_context(|| format!("Could not write {}", output.display()))?;
    Ok(json!({
        "ok": true,
        "output": format!("prompt-armor:report complete\nReport: {}", output.display()),
        "data": {
            "reportPath": output.display().to_string(),
            "artifacts": entries,
        },
    }))
}
