use super::*;

pub(in crate::modules) fn entry_points_module() -> BuiltinModule {
    builtin_module(
        "entry-points",
        "Entry Points",
        ModuleKind::Intel,
        "Deterministic extractor that normalizes attack-surface routes from \
         the context snapshot into a stable .kuzushi/entry-points.json.",
        tools_with_policy(
            workspace_policy(
                ToolPhase::Map,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Optional,
            ),
            vec![tool_with_options(
                "entry-points:extract",
                "Extract entry points (routes, handlers, outbound clients) from the latest \
                 context snapshot. Writes .kuzushi/entry-points.json. Deterministic; no model cost.",
                vec![target_option()],
            )],
        ),
        vec![dag(
            "entry-points:extract",
            "entry-points",
            &["context:build"],
        )],
    )
}

pub(in crate::modules) fn run_entry_points_extract(
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let target = resolve_tool_target(input, ctx)?;
    emit_step(ctx, "tool", "extract", "entry-points start");
    let (catalog, output_path) =
        crate::capabilities::entry_points::refresh_entry_point_catalog(&target)?;
    emit_step(
        ctx,
        "done",
        "extract",
        format!("entry-points wrote {} routes", catalog.total),
    );
    Ok(entry_points_response(&target, &output_path, &catalog))
}

fn entry_points_response(
    target: &std::path::Path,
    path: &std::path::Path,
    catalog: &crate::capabilities::entry_points::EntryPointCatalog,
) -> Value {
    let output = format!(
        "entry-points:extract wrote {} entry point{} under {}\n  Output: {}",
        catalog.total,
        if catalog.total == 1 { "" } else { "s" },
        target.display(),
        path.display()
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "target": target.display().to_string(),
            "outputPath": path.display().to_string(),
            "total": catalog.total,
            "entryPoints": catalog.entry_points,
            "provenance": catalog.provenance,
        }),
    )
}

fn emit_step(ctx: &ToolExecutionContext<'_>, kind: &str, verb: &str, label: impl Into<String>) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step(kind, verb, label.into()).emit();
    }
}
