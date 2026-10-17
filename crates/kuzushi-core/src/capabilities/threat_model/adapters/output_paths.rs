use super::*;

/// Keep generated artifacts with their producing run. Untraced library callers
/// retain the historical generated directory; explicit output paths take priority.
pub(crate) fn resolve_build_output_dir(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
    flavor: BuildFlavor,
    target: &Path,
) -> String {
    read_output_dir(input).unwrap_or_else(|| {
        let run_id = ctx.run_id().unwrap_or_else(|| Uuid::new_v4().to_string());
        flavor.default_output_dir(target, &run_id)
    })
}

pub(crate) fn read_output_dir(input: &Value) -> Option<String> {
    ["outputDir", "output_dir"].iter().find_map(|key| {
        input
            .get(*key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

#[cfg(test)]
mod tests;
