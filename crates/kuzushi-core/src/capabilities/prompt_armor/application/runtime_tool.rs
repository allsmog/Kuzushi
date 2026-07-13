use super::build_prompt::{build_prompt, prompt_armor_system_prompt};
use super::structured_output::{findings_schema, require_json_object};
use crate::capabilities::agentic_sast::collect_agentic_repo_inventory;
use crate::capabilities::prompt_armor::domain::output_dir;
use crate::findings::{
    normalize_agent_json_findings, persist_tool_findings, Finding, FindingStore,
};
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::structured_output::{
    query_required_structured_json_with_cost, CostedStructuredJson, StructuredJsonContract,
};
use crate::workspace::WorkspaceTarget;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub(crate) struct PromptArmorRuntimeInput<'a> {
    pub(crate) tool_name: &'a str,
    pub(crate) command: &'a str,
    pub(crate) input: &'a Value,
    pub(crate) target: &'a Path,
    pub(crate) plugin_root: &'a Path,
    pub(crate) model: String,
    pub(crate) runtime: &'a dyn AgentRuntime,
    pub(crate) workspace: Option<&'a WorkspaceTarget>,
    pub(crate) findings_store: Option<&'a FindingStore>,
}

pub(crate) fn run_runtime_tool(request: PromptArmorRuntimeInput<'_>) -> Result<Value> {
    let output_dir = ensure_output_dir(request.target)?;
    query_prompt_armor(&request).and_then(|raw| {
        let cost = raw.cost_report()?;
        runtime_tool_response(request, raw.value, cost, output_dir)
    })
}

fn query_prompt_armor(request: &PromptArmorRuntimeInput<'_>) -> Result<CostedStructuredJson<Value>> {
    let inventory = collect_agentic_repo_inventory(request.target, 100, 4096)?;
    query_required_structured_json_with_cost(
        request.runtime,
        AgentQueryRequest::new(
            request.model.clone(),
            request.target.to_path_buf(),
            prompt_armor_system_prompt(),
            build_prompt(
                request.command,
                request.plugin_root,
                request.input,
                &inventory,
            ),
        ),
        StructuredJsonContract::new(request.tool_name, "PromptArmorFindings", findings_schema()),
        require_json_object,
    )
}

fn runtime_tool_response(
    request: PromptArmorRuntimeInput<'_>,
    raw: Value,
    cost: crate::runtime::RuntimeCostReport,
    output_dir: PathBuf,
) -> Result<Value> {
    let findings = normalize_agent_json_findings(raw, request.target, "prompt-armor", 100)?;
    let persisted = persist_tool_findings(
        "prompt-armor",
        request.target,
        &findings,
        request.workspace,
        request.findings_store,
    )?;
    Ok(runtime_success_response(RuntimeSuccess {
        request,
        output_dir,
        findings,
        persisted,
        cost,
    }))
}

fn ensure_output_dir(target: &Path) -> Result<PathBuf> {
    crate::workspace::ensure_workspace_output_dir(target, ".prompt-armor")
        .with_context(|| format!("Could not create {}", output_dir(target).display()))
}

struct RuntimeSuccess<'a, Persisted> {
    request: PromptArmorRuntimeInput<'a>,
    output_dir: PathBuf,
    findings: Vec<Finding>,
    persisted: Persisted,
    cost: crate::runtime::RuntimeCostReport,
}

fn runtime_success_response<Persisted: serde::Serialize>(
    success: RuntimeSuccess<'_, Persisted>,
) -> Value {
    let request = success.request;
    let output = format!(
        "{tool_name} complete\n  Command: /{command}\n  Output: .prompt-armor/\n  Findings: {}",
        success.findings.len(),
        tool_name = request.tool_name,
        command = request.command,
    );
    let mut result = crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": request.target.display().to_string(),
            "pluginRoot": request.plugin_root.display().to_string(),
            "command": request.command,
            "outputDir": success.output_dir.display().to_string(),
            "findings": success.findings,
            "persisted": success.persisted,
        }),
    );
    crate::module_result::apply_runtime_cost_report(&mut result, success.cost);
    result
}
