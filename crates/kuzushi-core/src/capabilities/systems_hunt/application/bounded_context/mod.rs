use super::*;
use crate::workspace::inventory::{collect_source_prefixes, SourcePrefix, SourcePrefixLimits};

mod limits;
mod packs;
mod ranking;
mod render;
#[cfg(test)]
mod tests;

pub(crate) fn selected_systems_path(path: &str, include_non_production: bool) -> bool {
    limits::selected_path(path, include_non_production)
}

pub(crate) fn append_systems_source_coverage(lines: &mut Vec<String>, receipt: &Value) {
    render::append_coverage(lines, receipt);
}

pub(crate) fn gather_bounded_context(
    root: &Path,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let limits = limits::ContextLimits::parse(input)?;
    let mut heartbeat = crate::progress::HeartbeatGate::new(std::time::Duration::from_secs(1));
    let mut progress = |entries| {
        if heartbeat.ready() {
            emit_progress(ctx, entries);
        }
    };
    let canceled = || ctx.is_cancelled();
    let prefixes = collect_source_prefixes(
        root,
        limits.source,
        &|path| selected_systems_path(path, limits.include_non_production),
        &mut progress,
        &canceled,
    )?;
    let output = ranking::context_output(prefixes, limits.max_surfaces, &canceled)?;
    render::result(output)
}

fn emit_progress(ctx: &ToolExecutionContext<'_>, entries: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace
            .step(
                "tool-progress",
                "systems-hunt:systems-context-gatherer",
                format!("repository inventory · {entries} entries examined"),
            )
            .emit();
    }
}
