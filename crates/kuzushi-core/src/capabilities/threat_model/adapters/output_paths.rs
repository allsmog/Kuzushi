use super::*;

/// Keep generated artifacts with their producing run. Untraced library callers
/// retain the historical generated directory; explicit output paths take priority.
pub(crate) fn resolve_build_output_dir(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    target: &Path,
) -> String {
    read_string(input, &["outputDir", "output_dir"]).unwrap_or_else(|| {
        let run_id = ctx.run_id().unwrap_or_else(|| Uuid::new_v4().to_string());
        flavor.default_output_dir(target, &run_id)
    })
}

#[cfg(test)]
mod tests;
