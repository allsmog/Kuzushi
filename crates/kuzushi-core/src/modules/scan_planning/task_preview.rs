//! Read-only facts about the actual SAST task route. No availability probes.
use super::super::{ExecutableRequirement, ModuleMaturity, ModuleRegistry};
use crate::modules::application::sast_scan::{
    requested_scope_contracts, semgrep_settings, SastTaskSelection,
};
use anyhow::{Context, Result};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTaskPreview {
    pub tool: String,
    pub maturity: ModuleMaturity,
    pub native: bool,
    pub runtime_required: bool,
    pub executables: Vec<ExecutableRequirement>,
    pub deferred_checks: &'static str,
}

impl ModuleRegistry {
    /// Describes one requested task without running it or preparing a new job.
    /// Native routes share scanner implementations with the named catalog tool;
    /// their options, source receipts and completion contracts remain distinct.
    pub fn scan_task_preview(&self, task: &str, input: &Value) -> Result<ScanTaskPreview> {
        let selected = requested_scope_contracts(&json!({"taskMode":"manual","tasks":[task]}))?;
        selected.ensure_non_empty()?;
        let (tool, native) = task_route(&selected)?;
        let maturity = self.task_catalog_maturity(&tool)?;
        Ok(ScanTaskPreview {
            executables: self.task_executables(&tool, input)?,
            deferred_checks: deferred_checks(&tool),
            runtime_required: !native,
            tool,
            maturity,
            native,
        })
    }

    fn task_catalog_maturity(&self, name: &str) -> Result<ModuleMaturity> {
        self.all_modules()
            .flat_map(|module| module.tools().iter().map(move |tool| (module, tool)))
            .find(|(_, tool)| tool.name == name)
            .map(|(module, tool)| tool.effective_maturity(module.maturity()))
            .with_context(|| format!("No catalog contract for scan task route {name}"))
    }

    fn task_executables(&self, tool: &str, input: &Value) -> Result<Vec<ExecutableRequirement>> {
        let settings = match tool {
            "semgrep:scan" => semgrep_settings(input),
            "cargo-audit:scan" => crate::modules::native_scanners::cargo_audit_settings(input),
            "govulncheck:scan" => {
                return Ok(vec![ExecutableRequirement {
                    option: "govulncheck".into(),
                    command: "govulncheck".into(),
                }])
            }
            _ => return Ok(Vec::new()),
        };
        let prepared = self.prepare_tool_input(tool, binary_setting(settings), None)?;
        Ok(self
            .executable_requirements(tool, &prepared)
            .into_iter()
            .map(|requirement| study_executable(tool, requirement))
            .collect())
    }
}

fn binary_setting(settings: Value) -> Value {
    let values = settings
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(key, _)| key.as_str() == "binary")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    Value::Object(values)
}

fn study_executable(tool: &str, mut requirement: ExecutableRequirement) -> ExecutableRequirement {
    let option = if tool == "semgrep:scan" {
        "semgrepBinary"
    } else {
        "cargoAuditBinary"
    };
    requirement.option = option.into();
    requirement
}

fn task_route(selected: &SastTaskSelection) -> Result<(String, bool)> {
    let model_route = [
        (selected.run_agentic, "agentic-sast:scan"),
        (selected.run_carlini, "offense-review:threat-hunt"),
        (selected.run_taint_iris_next, "taint-iris-next:hunt"),
        (selected.run_systems_hunt, "systems-hunt:systems-hunt"),
    ]
    .into_iter()
    .find(|(enabled, _)| *enabled);
    if let Some((_, tool)) = model_route {
        return Ok((tool.into(), false));
    }
    let scanner = selected.scanners.first().context("No scan task route")?;
    let action = if scanner.id() == "dep-hygiene" {
        "check"
    } else {
        "scan"
    };
    Ok((format!("{}:{action}", scanner.id()), true))
}

fn deferred_checks(tool: &str) -> &'static str {
    match tool {
        "codeql:scan" => "Managed CodeQL executable and authenticated source-bound database are checked during preparation. No database is created here.",
        "cargo-audit:scan" => "Lockfile membership, advisory database and executable compatibility are checked during preparation. Presence alone does not certify the scanner.",
        _ => "Source, context, dependency compatibility and allowance are checked before execution. This preview grants no permission and starts no work.",
    }
}

#[cfg(test)]
mod tests;
