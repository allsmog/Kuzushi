use super::*;
use crate::scan::{require_directory_scope, resolve_scan_scopes, ScanScope};
use std::path::Path;

#[cfg(test)]
mod tests;

/// Scope validation runs before publishing a study or admitting scan work.
pub(in crate::modules) fn bind_sast_scope_input(mut input: Value, root: &Path) -> Result<Value> {
    let paths = scope_paths(&input)?;
    if paths.is_empty() {
        return Ok(input);
    }
    let scopes = resolve_scan_scopes(root, &paths)?;
    let selected = requested_scope_contracts(&input)?;
    selected.validate_scopes(&input, &scopes)?;
    input["paths"] = json!(scopes
        .iter()
        .map(|scope| &scope.relative)
        .collect::<Vec<_>>());
    Ok(input)
}

/// Assess declared scope contracts without availability probes or subprocesses.
pub(in crate::modules) fn requested_scope_contracts(input: &Value) -> Result<SastTaskSelection> {
    let mut request = parse_sast_tasks(input)?;
    if request.source == super::input::SastTaskSelectionSource::Automatic {
        request.tasks = super::input::default_native_sast_tasks();
    }
    SastTaskSelection::from_tasks(
        request.tasks,
        super::input::SastTaskSelectionSource::Explicit,
    )
}

impl SastTaskSelection {
    pub(in crate::modules) fn ensure_scoped_input(&self, input: &Value, root: &Path) -> Result<()> {
        let scopes = resolve_scan_scopes(root, &scope_paths(input)?)?;
        if scopes.is_empty() {
            return Ok(());
        }
        self.validate_scopes(input, &scopes)
    }

    fn validate_scopes(&self, input: &Value, scopes: &[ScanScope]) -> Result<()> {
        reject_repository_only_engines(self)?;
        validate_native_scopes(self, scopes)?;
        if self.run_agentic {
            validate_agentic_patterns(input)?;
        }
        if self.run_taint_iris_next {
            validate_taint_scope(input, scopes)?;
        }
        Ok(())
    }
}

fn reject_repository_only_engines(selected: &SastTaskSelection) -> Result<()> {
    for (enabled, engine) in [
        (selected.run_carlini, "offense-review"),
        (selected.run_systems_hunt, "systems-hunt"),
    ] {
        anyhow::ensure!(!enabled,
            "{engine} currently discovers across the whole repository. Choose a scoped engine, or clear paths and review a new whole-repository plan. No scan started.");
    }
    Ok(())
}

/// File scopes are scanned exactly by engines that read exact files. Any
/// selected engine that cannot do so refuses the file rather than widening
/// to its parent directory.
fn validate_native_scopes(selected: &SastTaskSelection, scopes: &[ScanScope]) -> Result<()> {
    let directory_only = directory_only_engines(selected);
    if directory_only.is_empty() {
        return Ok(());
    }
    for scope in scopes {
        require_directory_scope(scope, &directory_only)?;
    }
    Ok(())
}

fn directory_only_engines(selected: &SastTaskSelection) -> String {
    selected
        .scanners
        .iter()
        .filter(|scanner| !scanner.supports_exact_files())
        .map(|scanner| scanner.id())
        .collect::<Vec<_>>()
        .join(", ")
}

fn validate_agentic_patterns(input: &Value) -> Result<()> {
    let patterns =
        super::input::string_list_input(input, &["includePatterns", "include_patterns"])?
            .unwrap_or_default();
    anyhow::ensure!(patterns.is_empty(),
        "Scoped agentic discovery uses paths to select source. Clear includePatterns before reviewing this plan; explicit patterns cannot override an approved scope. No scan started.");
    Ok(())
}

fn validate_taint_scope(input: &Value, scopes: &[ScanScope]) -> Result<()> {
    let [scope] = scopes else {
        anyhow::bail!("taint-iris-next supports one directory scope per job. Choose one directory or a different scoped engine. No scan started.");
    };
    require_directory_scope(scope, "taint-iris-next")?;
    if let Some(subdir) =
        super::input::optional_string_input(input, &["targetSubdir", "target_subdir"])?
    {
        anyhow::ensure!(crate::scan::normalized_scan_path(&subdir)? == scope.relative,
            "taint-iris-next targetSubdir must match its approved paths scope. Clear targetSubdir or align it before reviewing the plan. No scan started.");
    }
    Ok(())
}

pub(super) fn scope_paths(input: &Value) -> Result<Vec<String>> {
    Ok(
        super::input::path_list_input(input, &["paths", "includePaths", "include_paths"])?
            .unwrap_or_default(),
    )
}
