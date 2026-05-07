use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Map, Value};

use crate::runtime::{AgentQueryRequest, AgentRuntime};

use super::{
    builtin_module, json_summary, model_option, opt, parse_json_object_from_agent_text,
    read_bool_any, resolve_input_path, resolve_tool_model, resolve_tool_target,
    string_array_or_csv_input, string_input_any, tool, tool_with_options, unix_millis,
    BuiltinModule, ModuleKind, OptionType, ToolExecutionContext,
};

pub(super) fn module() -> BuiltinModule {
    builtin_module(
        "vendor-assessment",
        "Vendor Assessment",
        ModuleKind::Governance,
        "Vendor security assessment workspace: attach docs, set scope, generate prompts, assess.",
        vec![
            tool_with_options(
                "vendor-assessment:attach",
                "Attach vendor evidence documents.",
                vec![
                    opt("source", OptionType::String, "Evidence source path or URL."),
                    opt("path", OptionType::Path, "Evidence document path."),
                    opt("url", OptionType::String, "Evidence document URL."),
                ],
            ),
            tool_with_options(
                "vendor-assessment:scope",
                "Set or inspect assessment scope.",
                vec![
                    opt("vendorName", OptionType::String, "Vendor name."),
                    opt("productName", OptionType::String, "Product name."),
                    opt("profile", OptionType::String, "Assessment profile.")
                        .default(json!("enterprise-ai")),
                ],
            ),
            tool(
                "vendor-assessment:prompts",
                "Generate assessment prompt packets.",
            ),
            tool_with_options(
                "vendor-assessment:assess",
                "Run vendor assessment.",
                vec![model_option()],
            ),
        ],
        vec![],
    )
}

pub(super) fn execute_tool(
    name: &str,
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    match name {
        "vendor-assessment:attach" => attach(input, ctx),
        "vendor-assessment:scope" => scope(input, ctx),
        "vendor-assessment:prompts" => prompts(input, ctx),
        "vendor-assessment:assess" => assess(input, ctx, runtime),
        _ => anyhow::bail!("unknown vendor-assessment tool {name:?}"),
    }
}

fn root(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<PathBuf> {
    if let Some(workspace) = ctx.workspace {
        return Ok(workspace.root().to_path_buf());
    }
    resolve_tool_target(input, ctx)
}

fn scope_path(root: &Path) -> PathBuf {
    root.join(".kuzushi")
        .join("vendor-assessment")
        .join("scope.json")
}

fn runs_dir(root: &Path) -> PathBuf {
    root.join(".kuzushi").join("vendor-assessment").join("runs")
}

fn load_scope(root: &Path) -> Result<Value> {
    let path = scope_path(root);
    if !path.exists() {
        return Ok(empty_scope());
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("Could not read vendor assessment scope {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("Could not parse vendor assessment scope {}", path.display()))
}

fn save_scope(root: &Path, scope: &Value) -> Result<PathBuf> {
    let path = scope_path(root);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    fs::write(&path, format!("{}\n", serde_json::to_string_pretty(scope)?))
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

fn empty_scope() -> Value {
    json!({
        "version": "1",
        "vendorName": "",
        "productName": "",
        "primaryDomain": "",
        "useCase": "",
        "profile": "enterprise-ai",
        "dataClasses": [],
        "integrations": [],
        "documents": [],
        "updatedAt": unix_millis(),
    })
}

fn merge_scope_inputs(mut scope: Value, input: &Value) -> Value {
    let Value::Object(ref mut object) = scope else {
        return empty_scope();
    };
    for (input_keys, output_key) in [
        (&["vendorName", "vendor"][..], "vendorName"),
        (&["productName"][..], "productName"),
        (&["primaryDomain", "domain"][..], "primaryDomain"),
        (&["useCase"][..], "useCase"),
        (&["profile"][..], "profile"),
    ] {
        if let Some(value) = string_input_any(input, input_keys) {
            object.insert(output_key.to_string(), json!(value));
        }
    }
    for key in ["dataClasses", "integrations"] {
        if let Some(values) = string_array_or_csv_input(input, &[key]) {
            object.insert(key.to_string(), json!(values));
        }
    }
    object.insert("updatedAt".to_string(), json!(unix_millis()));
    scope
}

fn attach(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = root(&input, ctx)?;
    let source = string_input_any(&input, &["source", "path", "url", "target"])
        .context("vendor-assessment:attach requires source, path, url, or target")?;
    let mut scope = merge_scope_inputs(load_scope(&root)?, &input);
    let kind = string_input_any(&input, &["kind"]).unwrap_or_else(|| "other".to_string());
    let title = string_input_any(&input, &["title"]).unwrap_or_else(|| {
        Path::new(&source)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&source)
            .to_string()
    });
    let (status, text, warnings) = if source.starts_with("http://")
        || source.starts_with("https://")
    {
        (
            "referenced".to_string(),
            String::new(),
            vec![
                "Rust vendor-assessment records URL evidence but does not fetch remote documents; download the document locally and pass source/path to parse text.".to_string(),
            ],
        )
    } else {
        let path = resolve_input_path(&root, &source);
        let raw = fs::read(&path).with_context(|| {
            format!(
                "Could not read vendor assessment attachment {}",
                path.display()
            )
        })?;
        if raw.iter().take(4096).any(|byte| *byte == 0) {
            (
                "attached".to_string(),
                String::new(),
                vec!["Attachment looks binary; stored metadata without parsed text.".to_string()],
            )
        } else {
            let text = String::from_utf8_lossy(&raw[..raw.len().min(256_000)]).to_string();
            ("attached".to_string(), text, Vec::new())
        }
    };
    let doc = json!({
        "id": format!("doc-{}", unix_millis()),
        "source": source,
        "kind": kind,
        "title": title,
        "status": status,
        "text": text,
        "parseWarnings": warnings,
    });
    let documents = scope
        .as_object_mut()
        .expect("vendor scope is an object")
        .entry("documents")
        .or_insert_with(|| json!([]));
    if let Some(items) = documents.as_array_mut() {
        items.push(doc.clone());
    }
    let scope_path = save_scope(&root, &scope)?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "Attached {} ({})\nScope: {}",
            doc.get("title").and_then(Value::as_str).unwrap_or("document"),
            doc.get("status").and_then(Value::as_str).unwrap_or("attached"),
            scope_path.display()
        ),
        "data": {
            "scope": scope,
            "document": doc,
            "scopePath": scope_path.display().to_string(),
        },
    }))
}

fn scope(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = root(&input, ctx)?;
    if read_bool_any(&input, &["clear"])?.unwrap_or(false) {
        let scope = empty_scope();
        let scope_path = save_scope(&root, &scope)?;
        return Ok(json!({
            "ok": true,
            "output": "Vendor assessment draft scope cleared.",
            "data": {
                "cleared": true,
                "scope": scope,
                "scopePath": scope_path.display().to_string(),
            },
        }));
    }
    let scope = merge_scope_inputs(load_scope(&root)?, &input);
    let scope_path = save_scope(&root, &scope)?;
    let docs = scope
        .get("documents")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    Ok(json!({
        "ok": true,
        "output": format!(
            "Vendor assessment scope\n  Vendor: {}\n  Product: {}\n  Documents: {}\n  Scope: {}",
            scope.get("vendorName").and_then(Value::as_str).filter(|v| !v.is_empty()).unwrap_or("(unset)"),
            scope.get("productName").and_then(Value::as_str).filter(|v| !v.is_empty()).unwrap_or("(unset)"),
            docs,
            scope_path.display(),
        ),
        "data": {
            "scope": scope,
            "scopePath": scope_path.display().to_string(),
        },
    }))
}

fn prompts(input: Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let root = root(&input, ctx)?;
    let scope = merge_scope_inputs(load_scope(&root)?, &input);
    save_scope(&root, &scope)?;
    let run_id = string_input_any(&input, &["runId", "run_id"])
        .unwrap_or_else(|| format!("prompts-{}", unix_millis()));
    let prompts_dir = runs_dir(&root).join(&run_id).join("prompts");
    fs::create_dir_all(&prompts_dir)
        .with_context(|| format!("Could not create {}", prompts_dir.display()))?;
    let prompts = build_prompt_bundle(&scope);
    for (filename, content) in &prompts {
        fs::write(prompts_dir.join(filename), format!("{content}\n"))
            .with_context(|| format!("Could not write {}", prompts_dir.join(filename).display()))?;
    }
    Ok(json!({
        "ok": true,
        "output": format!(
            "Prompt bundle written to {}\nProfile: {}\nPrompts: {}",
            prompts_dir.display(),
            scope.get("profile").and_then(Value::as_str).unwrap_or("enterprise-ai"),
            prompts.len()
        ),
        "data": {
            "runId": run_id,
            "promptsDir": prompts_dir.display().to_string(),
            "prompts": prompts.iter().map(|(file, content)| json!({"fileName": file, "content": content})).collect::<Vec<_>>(),
        },
    }))
}

fn assess(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
    runtime: Option<&dyn AgentRuntime>,
) -> Result<Value> {
    let root = root(&input, ctx)?;
    let scope = merge_scope_inputs(load_scope(&root)?, &input);
    save_scope(&root, &scope)?;
    let run_id = format!("va-{}", unix_millis());
    let run_root = runs_dir(&root).join(&run_id);
    let prompts_dir = run_root.join("prompts");
    fs::create_dir_all(&prompts_dir)
        .with_context(|| format!("Could not create {}", prompts_dir.display()))?;
    let prompts = build_prompt_bundle(&scope);
    for (filename, content) in &prompts {
        fs::write(prompts_dir.join(filename), format!("{content}\n"))?;
    }
    let has_text = scope_has_text(&scope);
    let mut report = build_fallback_report(&run_id, &scope, &run_root, has_text);
    let mut cost_usd = 0.0;
    if has_text {
        let runtime = runtime.context(
            "vendor-assessment:assess with parsed documents requires the pi-agent-core runtime. Configure runtime.agent_bridge_command or install the bundled Node bridge dependencies.",
        )?;
        let model = resolve_tool_model("vendor-assessment:assess", &input, ctx)?;
        let response = runtime.query_blocking(AgentQueryRequest::new(
            model,
            root.clone(),
            "You are Kuzushi's vendor security assessment agent. Return only JSON with overallRisk, confidence, summary, domains, mitigations, and documents.".to_string(),
            prompts
                .iter()
                .map(|(_, content)| content.as_str())
                .collect::<Vec<_>>()
                .join("\n\n"),
        ))?;
        let raw = response
            .structured
            .or_else(|| parse_json_object_from_agent_text(&response.text).ok());
        if let Some(Value::Object(object)) = raw {
            merge_report_object(&mut report, object);
        }
        cost_usd = 0.0;
    }
    let report_md = render_report_markdown(&report);
    let scope_path = run_root.join("scope.json");
    let report_path = run_root.join("report.md");
    let report_json_path = run_root.join("report.json");
    fs::write(
        &scope_path,
        format!("{}\n", serde_json::to_string_pretty(&scope)?),
    )?;
    fs::write(&report_path, format!("{report_md}\n"))?;
    fs::write(
        &report_json_path,
        format!("{}\n", serde_json::to_string_pretty(&report)?),
    )?;
    Ok(json!({
        "ok": true,
        "output": format!(
            "Vendor assessment complete ({}, {}).\nReport: {}\nJSON:   {}\nScope:  {}\nPrompts: {}",
            report.get("overallRisk").and_then(Value::as_str).unwrap_or("needs-review"),
            report.get("confidence").and_then(Value::as_str).unwrap_or("low"),
            report_path.display(),
            report_json_path.display(),
            scope_path.display(),
            prompts_dir.display(),
        ),
        "data": {
            "runId": run_id,
            "report": report,
            "scope": scope,
            "artifacts": {
                "scopePath": scope_path.display().to_string(),
                "reportPath": report_path.display().to_string(),
                "reportJsonPath": report_json_path.display().to_string(),
                "promptsDir": prompts_dir.display().to_string(),
            },
        },
        "costUsd": cost_usd,
    }))
}

fn build_prompt_bundle(scope: &Value) -> Vec<(String, String)> {
    let pretty_scope = serde_json::to_string_pretty(scope).unwrap_or_else(|_| "{}".to_string());
    vec![
        (
            "overview.md".to_string(),
            format!(
                "Assess this vendor scope for enterprise security risk. Ground all conclusions in attached document text when present.\n\nScope:\n{pretty_scope}"
            ),
        ),
        (
            "evidence-review.md".to_string(),
            "Extract concrete controls, gaps, integrations, data classes, and contractual commitments from the attached evidence.".to_string(),
        ),
        (
            "follow-up-questions.md".to_string(),
            "List high-signal follow-up questions for missing security evidence.".to_string(),
        ),
    ]
}

fn scope_has_text(scope: &Value) -> bool {
    scope
        .get("documents")
        .and_then(Value::as_array)
        .is_some_and(|documents| {
            documents.iter().any(|doc| {
                doc.get("text")
                    .and_then(Value::as_str)
                    .is_some_and(|text| !text.trim().is_empty())
            })
        })
}

fn build_fallback_report(
    run_id: &str,
    scope: &Value,
    run_root: &Path,
    document_backed: bool,
) -> Value {
    let docs = scope
        .get("documents")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    json!({
        "runId": run_id,
        "overallRisk": if document_backed { "needs-review" } else { "intake" },
        "confidence": if document_backed { "medium" } else { "low" },
        "summary": if document_backed {
            "Assessment synthesized from attached vendor evidence."
        } else {
            "No parsed evidence was attached; collect documents before making a risk decision."
        },
        "documents": docs,
        "domains": [],
        "mitigations": [],
        "artifacts": {
            "scopePath": run_root.join("scope.json").display().to_string(),
            "reportPath": run_root.join("report.md").display().to_string(),
            "reportJsonPath": run_root.join("report.json").display().to_string(),
            "promptsDir": run_root.join("prompts").display().to_string(),
        },
    })
}

fn merge_report_object(report: &mut Value, object: Map<String, Value>) {
    if let Value::Object(report_object) = report {
        for key in [
            "overallRisk",
            "confidence",
            "summary",
            "domains",
            "mitigations",
            "documents",
        ] {
            if let Some(value) = object.get(key).cloned() {
                report_object.insert(key.to_string(), value);
            }
        }
    }
}

fn render_report_markdown(report: &Value) -> String {
    let mut lines = vec![
        "# Vendor AI Security Assessment Report".to_string(),
        String::new(),
        format!(
            "Overall risk: {}",
            report
                .get("overallRisk")
                .and_then(Value::as_str)
                .unwrap_or("needs-review")
        ),
        format!(
            "Confidence: {}",
            report
                .get("confidence")
                .and_then(Value::as_str)
                .unwrap_or("low")
        ),
        String::new(),
        report
            .get("summary")
            .and_then(Value::as_str)
            .unwrap_or("No summary supplied.")
            .to_string(),
        String::new(),
        "## Appendix".to_string(),
        format!(
            "Documents: {}",
            report
                .get("documents")
                .and_then(Value::as_array)
                .map_or(0, Vec::len)
        ),
    ];
    if let Some(items) = report.get("mitigations").and_then(Value::as_array) {
        lines.push(String::new());
        lines.push("## Mitigations".to_string());
        for item in items {
            lines.push(format!("- {}", json_summary(item)));
        }
    }
    lines.join("\n")
}
