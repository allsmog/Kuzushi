use super::prompt_bundle::{
    build_fallback_report, build_prompt_bundle, merge_report_object, scope_has_text,
};
use super::storage::{load_updated_scope, runs_dir};
use crate::capabilities::vendor_assessment::adapters::render_report_markdown;
use crate::capabilities::vendor_assessment::domain::{unix_millis, ScopeUpdate};
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::{query_required_structured_json, StructuredJsonContract};
use anyhow::{Context, Result};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn assess(
    root: &Path,
    update: ScopeUpdate,
    runtime: Option<&dyn AgentRuntime>,
    resolve_model: impl FnOnce() -> Result<String>,
) -> Result<Value> {
    load_updated_scope(root, &update).and_then(|scope| {
        let run_id = format!("va-{}", unix_millis());
        let run_root = runs_dir(root).join(&run_id);
        let prompts_dir = run_root.join("prompts");
        write_assessment_prompts(&prompts_dir, &scope).and_then(|prompts| {
            build_assessment_report(
                root,
                &run_id,
                &scope,
                &run_root,
                &prompts,
                runtime,
                resolve_model,
            )
            .and_then(|report| {
                write_assessment_artifacts(&run_root, &scope, &report).map(|artifacts| {
                    assessment_response(run_id, report, scope, artifacts, prompts_dir)
                })
            })
        })
    })
}

fn write_assessment_prompts(prompts_dir: &Path, scope: &Value) -> Result<Vec<(String, String)>> {
    ensure_assessment_prompt_dir(prompts_dir).and_then(|_| {
        let prompts = build_prompt_bundle(&scope);
        write_assessment_prompt_files(prompts_dir, &prompts).map(|_| prompts)
    })
}

fn ensure_assessment_prompt_dir(prompts_dir: &Path) -> Result<()> {
    fs::create_dir_all(prompts_dir)
        .with_context(|| format!("Could not create {}", prompts_dir.display()))
}

fn write_assessment_prompt_files(prompts_dir: &Path, prompts: &[(String, String)]) -> Result<()> {
    prompts.iter().try_for_each(|(filename, content)| {
        fs::write(prompts_dir.join(filename), format!("{content}\n")).map_err(Into::into)
    })
}

fn build_assessment_report(
    root: &Path,
    run_id: &str,
    scope: &Value,
    run_root: &Path,
    prompts: &[(String, String)],
    runtime: Option<&dyn AgentRuntime>,
    resolve_model: impl FnOnce() -> Result<String>,
) -> Result<Value> {
    let has_text = scope_has_text(&scope);
    let mut report = build_fallback_report(&run_id, &scope, &run_root, has_text);
    if !has_text {
        return Ok(report);
    }
    query_assessment_object(root, prompts, runtime, resolve_model).map(|object| {
        merge_report_object(&mut report, object);
        report
    })
}

fn query_assessment_object(
    root: &Path,
    prompts: &[(String, String)],
    runtime: Option<&dyn AgentRuntime>,
    resolve_model: impl FnOnce() -> Result<String>,
) -> Result<Map<String, Value>> {
    required_runtime(runtime).and_then(|runtime| {
        resolve_model().and_then(|model| {
            query_required_structured_json(
                runtime,
                AgentQueryRequest::new(
                    model,
                    root.to_path_buf(),
                    "You are Kuzushi's vendor security assessment agent. Return only JSON with overallRisk, confidence, summary, domains, mitigations, and documents.".to_string(),
                    joined_prompt_text(prompts),
                ),
                StructuredJsonContract::new(
                    "vendor-assessment:assess",
                    "VendorAssessmentReport",
                    vendor_assessment_schema(),
                ),
                require_json_object,
            )
            .map(required_object)
        })
    })
}

fn required_runtime(runtime: Option<&dyn AgentRuntime>) -> Result<&dyn AgentRuntime> {
    runtime.context(
        "vendor-assessment:assess with parsed documents requires the LangGraph runtime. Configure runtime.langgraph_bridge_command or install the bundled Node bridge dependencies.",
    )
}

fn joined_prompt_text(prompts: &[(String, String)]) -> String {
    prompts
        .iter()
        .map(|(_, content)| content.as_str())
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn required_object(raw: Value) -> Map<String, Value> {
    let Value::Object(object) = raw else {
        unreachable!("require_json_object returned non-object");
    };
    object
}

struct AssessmentArtifacts {
    scope_path: PathBuf,
    report_path: PathBuf,
    report_json_path: PathBuf,
}

fn write_assessment_artifacts(
    run_root: &Path,
    scope: &Value,
    report: &Value,
) -> Result<AssessmentArtifacts> {
    let scope_path = run_root.join("scope.json");
    let report_path = run_root.join("report.md");
    let report_json_path = run_root.join("report.json");
    write_scope_artifact(&scope_path, scope).and_then(|_| {
        write_report_markdown_artifact(&report_path, report).and_then(|_| {
            write_report_json_artifact(&report_json_path, report).map(|_| AssessmentArtifacts {
                scope_path,
                report_path,
                report_json_path,
            })
        })
    })
}

fn write_scope_artifact(path: &Path, scope: &Value) -> Result<()> {
    write_pretty_json_artifact(path, scope)
}

fn write_report_json_artifact(path: &Path, report: &Value) -> Result<()> {
    write_pretty_json_artifact(path, report)
}

fn write_pretty_json_artifact(path: &Path, value: &Value) -> Result<()> {
    serde_json::to_string_pretty(value)
        .map(|body| format!("{body}\n"))
        .map_err(Into::into)
        .and_then(|body| fs::write(path, body).map_err(Into::into))
}

fn write_report_markdown_artifact(path: &Path, report: &Value) -> Result<()> {
    fs::write(path, format!("{}\n", render_report_markdown(report))).map_err(Into::into)
}

fn assessment_response(
    run_id: String,
    report: Value,
    scope: Value,
    artifacts: AssessmentArtifacts,
    prompts_dir: PathBuf,
) -> Value {
    let output = format!(
        "Vendor assessment complete ({}, {}).\nReport: {}\nJSON:   {}\nScope:  {}\nPrompts: {}",
        report.get("overallRisk").and_then(Value::as_str).unwrap_or("needs-review"),
        report.get("confidence").and_then(Value::as_str).unwrap_or("low"),
        artifacts.report_path.display(),
        artifacts.report_json_path.display(),
        artifacts.scope_path.display(),
        prompts_dir.display(),
    );
    let mut result = crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "runId": run_id,
            "report": report,
            "scope": scope,
            "artifacts": {
                "scopePath": artifacts.scope_path.display().to_string(),
                "reportPath": artifacts.report_path.display().to_string(),
                "reportJsonPath": artifacts.report_json_path.display().to_string(),
                "promptsDir": prompts_dir.display().to_string(),
            },
        }),
    );
    result["artifacts"] = json!([
        { "label": "report", "path": artifacts.report_path.display().to_string() },
        { "label": "report json", "path": artifacts.report_json_path.display().to_string() },
        { "label": "scope", "path": artifacts.scope_path.display().to_string() },
        { "label": "prompts", "path": prompts_dir.display().to_string() },
    ]);
    result["costUsd"] = json!(0.0);
    result
}

pub(crate) fn require_json_object(value: Value) -> Result<Value> {
    if value.is_object() {
        Ok(value)
    } else {
        anyhow::bail!("vendor-assessment structured output must be a JSON object")
    }
}

pub(crate) fn vendor_assessment_schema() -> Value {
    json!({
        "type": "object",
        "required": ["overallRisk", "confidence", "summary"],
        "additionalProperties": true,
        "properties": {
            "overallRisk": {"type": "string"},
            "confidence": {"type": "string"},
            "summary": {"type": "string"},
            "domains": {"type": "array", "items": {"type": "object"}},
            "mitigations": {"type": "array", "items": {"type": "object"}},
            "documents": {"type": "array", "items": {"type": "object"}}
        }
    })
}
