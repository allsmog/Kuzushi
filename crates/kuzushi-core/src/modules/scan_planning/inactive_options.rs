//! Declared task ownership for canonical scan-option previews. No IO or probes.
use crate::modules::application::sast_scan::{requested_scope_contracts, SastTaskSelection};
use crate::modules::{native_scanners, workspace_module, OptionSpec};
use anyhow::Result;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InactiveScanTaskOptions {
    pub task: String,
    pub options: Vec<String>,
}

/// Explain canonical options belonging to engines outside the requested set.
/// This does not authenticate source or certify dependencies or execution.
pub fn inactive_scan_task_options(input: &Value) -> Result<Vec<InactiveScanTaskOptions>> {
    let selected = requested_scope_contracts(input)?;
    Ok(option_groups()
        .into_iter()
        .filter_map(|(task, options)| inactive_group(input, &selected, task, options))
        .collect())
}

fn option_groups() -> [(&'static str, Vec<OptionSpec>); 5] {
    [
        ("semgrep", workspace_module::sast_semgrep_options()),
        ("cargo-audit", native_scanners::cargo_audit_study_options()),
        ("secret-scan", workspace_module::sast_secret_scan_options()),
        ("iac-scan", workspace_module::sast_iac_scan_options()),
        (
            "agentic",
            vec![workspace_module::sast_agentic_turn_limit_option()],
        ),
    ]
}

fn inactive_group(
    input: &Value,
    selected: &SastTaskSelection,
    task: &str,
    specifications: Vec<OptionSpec>,
) -> Option<InactiveScanTaskOptions> {
    if task_requested(selected, task) {
        return None;
    }
    let options = specifications
        .into_iter()
        .filter(|option| is_configured(input, task, &option.name))
        .map(|option| option.name)
        .collect::<Vec<_>>();
    (!options.is_empty()).then(|| InactiveScanTaskOptions {
        task: task.into(),
        options,
    })
}

fn task_requested(selected: &SastTaskSelection, task: &str) -> bool {
    if task == "agentic" {
        return selected.run_agentic;
    }
    selected.scanners.iter().any(|scanner| scanner.id() == task)
}

fn is_configured(input: &Value, task: &str, key: &str) -> bool {
    match input.get(key) {
        Some(Value::Null) => !matches!(task, "semgrep" | "cargo-audit"),
        Some(_) => true,
        None => false,
    }
}

#[cfg(test)]
mod tests;
