//! Readers for stored engine results. No engine launch or model work.
use super::*;

mod status;

pub(in crate::modules) fn run_fuzz_import(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    ctx.ensure_active()?;
    let target = resolve_tool_target(input, ctx)?;
    let workspace = ctx
        .workspace
        .context("fuzz:import requires an active workspace")?;
    let data_root = match optional_string_input(input, &["dataRoot", "data_root"])? {
        Some(value) => PathBuf::from(value),
        None => FuzzPaths::data_root_for(&derived_workspace_root(&home_dir()?, &target)),
    };
    let filter = optional_string_input(input, &["afeTarget", "afe_target", "shard"])?;
    let request = import::FuzzImportRequest {
        data_root: &data_root,
        source_dir: &target,
        target_filter: filter.as_deref(),
        include_unverified: bool_input(input, &["includeUnverified", "include_unverified"]),
    };
    let summary = import::import_afe_findings(workspace, &request)?;
    let output = format!(
        "fuzz:import · {} imported · {} unverified skipped · {} malformed rows",
        summary.imported, summary.skipped_unverified, summary.skipped_rows
    );
    Ok(import_result(&target, summary, output))
}

fn import_result(target: &Path, summary: import::FuzzImportSummary, output: String) -> Value {
    let skipped = summary.skipped_rows;
    let output = format!("{output}\nVerification flags are external engine claims. This import does not establish local reproduction or current-revision coverage.");
    let data = json!({ "target": target.display().to_string(), "summary": summary,
        "verificationAuthority": "external-engine", "localReproductionPerformed": false });
    if skipped > 0 {
        let warning =
            format!("{skipped} malformed index rows were skipped; imported history is partial.");
        return crate::module_result::partial_output_result(
            output.clone(),
            output,
            vec![json!(warning)],
            data,
        );
    }
    crate::module_result::completed_output_result(output.clone(), output, data)
}

pub(in crate::modules) fn run_fuzz_status(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    ctx.ensure_active()?;
    let target = resolve_tool_target(input, ctx)?;
    let workspace_root = match optional_string_input(input, &["workspaceRoot", "workspace_root"])? {
        Some(value) => PathBuf::from(value),
        None => derived_workspace_root(&home_dir()?, &target),
    };
    let data_root = match optional_string_input(input, &["dataRoot", "data_root"])? {
        Some(value) => PathBuf::from(value),
        None => FuzzPaths::data_root_for(&workspace_root),
    };
    let active = || ctx.ensure_active();
    let probe = status::workspace(&workspace_root, &active)?;
    let counts = status::index(&data_root, &active)?;
    Ok(status_result(
        &target,
        &workspace_root,
        &data_root,
        probe,
        counts,
    ))
}

fn status_result(
    target: &Path,
    workspace: &Path,
    data_root: &Path,
    probe: status::StoredWorkspace,
    counts: Option<status::StoredCounts>,
) -> Value {
    let skipped = counts.as_ref().map_or(0, |counts| counts.malformed_rows);
    let output = status_output(&probe, counts.as_ref());
    let data = json!({ "target": target.display().to_string(),
        "workspaceRoot": workspace.display().to_string(), "dataRoot": data_root.display().to_string(),
        "initialized": probe.initialized, "sinksPresent": probe.sinks_present,
        "targets": probe.targets, "builtTargets": probe.built, "parkedWorkorders": probe.workorders,
        "findings": counts, "verificationAuthority": "external-engine", "localReproductionPerformed": false,
        "inspectionLimits": { "directoryEntries": status::MAX_ENTRIES,
            "indexRows": status::MAX_ENTRIES, "indexBytes": status::MAX_INDEX_BYTES } });
    if skipped > 0 {
        return crate::module_result::partial_output_result(
            output.clone(),
            output,
            vec![json!(format!(
                "{skipped} malformed index rows were skipped; displayed counts are partial."
            ))],
            data,
        );
    }
    crate::module_result::completed_output_result(output.clone(), output, data)
}

fn status_output(probe: &status::StoredWorkspace, counts: Option<&status::StoredCounts>) -> String {
    let state = if probe.initialized {
        "workspace marker present"
    } else {
        "workspace uninitialized; no marker recorded"
    };
    let counts = counts
        .map(|counts| {
            format!(
                "{}/{} records marked verified by the external engine; {} malformed rows",
                counts.verified, counts.total, counts.malformed_rows
            )
        })
        .unwrap_or_else(|| "findings index missing".into());
    format!("fuzz:status · {state}\n{} target markers, {} build markers, {} parked workorders\n{counts}\nStored markers do not establish build validity, local reproduction or current-revision coverage.",
        probe.targets.len(), probe.built.len(), probe.workorders.len())
}
