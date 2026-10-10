use super::*;
use crate::workspace::{
    resolve_accepted_scan_scope_selection, AcceptedScanScopeSelection, ScanScopeRef,
};

pub(in crate::modules) fn bind_accepted_sast_scope_input(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let Some(scope) = resolve_selection(&input, ctx)? else {
        return Ok(input);
    };
    validate_exact_scope_request(&input)?;
    anyhow::ensure!(
        !scope.discovery_files.is_empty(),
        "accepted scope has no discovery files"
    );
    Ok(input)
}

pub(in crate::modules) fn validate_exact_scope_request(input: &Value) -> Result<()> {
    anyhow::ensure!(
        super::scope_guard::scope_paths(input)?.is_empty(),
        "scanScopeRef cannot be combined with paths; its immutable membership is authoritative"
    );
    let _: ScanScopeRef = serde_json::from_value(input["scanScopeRef"].clone())
        .context("scanScopeRef must identify an exact accepted revision and scope")?;
    let selected = requested_scope_contracts(input)?;
    selected.ensure_non_empty()?;
    if selected.run_agentic {
        crate::capabilities::agentic_sast::validate_agentic_scope_options(input)?;
    }
    ensure_exact_membership_supported(&selected)
}

pub(in crate::modules) fn scope_scan_options(
    input: &Value,
    whitebox: bool,
    ctx: &ToolExecutionContext<'_>,
) -> Result<SastScanOptions> {
    Ok(SastScanOptions {
        run: sast_scan_options(input, whitebox)?,
        selection: resolve_selection(input, ctx)?,
    })
}

pub(in crate::modules) struct SastScanOptions {
    pub run: ScanRunOptions,
    pub selection: Option<AcceptedScanScopeSelection>,
}

impl SastScanOptions {
    pub fn discovery_files(&self) -> Option<&[String]> {
        self.selection
            .as_ref()
            .map(|scope| scope.discovery_files.as_slice())
    }
}

fn resolve_selection(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Option<AcceptedScanScopeSelection>> {
    input
        .get("scanScopeRef")
        .map(|value| {
            let reference: ScanScopeRef = serde_json::from_value(value.clone())
                .context("scanScopeRef must identify an exact accepted revision and scope")?;
            resolve_accepted_scan_scope_selection(ctx, &reference)
        })
        .transpose()
}

fn ensure_exact_membership_supported(selected: &SastTaskSelection) -> Result<()> {
    anyhow::ensure!(!selected.run_carlini && !selected.run_systems_hunt && !selected.run_taint_iris_next,
        "selected model-backed engine has no exact-file discovery contract yet. Choose an exact-file engine or review a separately approved whole-repository job. No scan started.");
    for scanner in &selected.scanners {
        anyhow::ensure!(scanner.supports_exact_files(), "{} cannot honor accepted file membership. Choose a supported engine or review a separately approved whole-repository job. No scan started.", scanner.id());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
