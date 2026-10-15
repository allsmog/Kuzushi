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
            )
            .without_phase_result()],
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
    let snapshot = crate::workspace::source_snapshot::SourceSnapshot::capture(
        ctx,
        "entry-points:extract",
        &target,
    )?;
    let (catalog, output_path) =
        crate::capabilities::entry_points::refresh_entry_point_catalog_cancellable(
            &target,
            &|| ctx.is_cancelled(),
            || snapshot.ensure_current(ctx, "entry-points:extract", &target),
        )?;
    emit_step(
        ctx,
        "done",
        "extract",
        match catalog.snapshot_coverage.disclosure() {
            Some(disclosure) => format!(
                "entry-points wrote {} routes with partial coverage: {disclosure}",
                catalog.total
            ),
            None => format!("entry-points wrote {} routes", catalog.total),
        },
    );
    Ok(snapshot.finish(
        ctx,
        "entry-points:extract",
        &target,
        entry_points_response(&target, &output_path, &catalog),
    ))
}

fn entry_points_response(
    target: &std::path::Path,
    path: &std::path::Path,
    catalog: &crate::capabilities::entry_points::EntryPointCatalog,
) -> Value {
    let mut output = format!(
        "entry-points:extract wrote {} entry point{} under {}\n  Output: {}",
        catalog.total,
        if catalog.total == 1 { "" } else { "s" },
        target.display(),
        path.display()
    );
    let data = json!({
        "target": target.display().to_string(),
        "outputPath": path.display().to_string(),
        "total": catalog.total,
        "entryPoints": catalog.entry_points,
        "provenance": catalog.provenance,
        "snapshotCoverage": catalog.snapshot_coverage,
    });
    // A catalog the snapshot could only partly supply is reported partial, so
    // its gaps never read as an absence of entry points.
    let Some(disclosure) = catalog.snapshot_coverage.disclosure() else {
        return crate::module_result::completed_output_result(output.clone(), output, data);
    };
    let summary = format!("entry-points:extract wrote a partial catalog: {disclosure}");
    output.push_str(&format!("\n  Partial coverage: {disclosure}"));
    crate::module_result::partial_output_result(summary, output, vec![json!(disclosure)], data)
}

fn emit_step(ctx: &ToolExecutionContext<'_>, kind: &str, verb: &str, label: impl Into<String>) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step(kind, verb, label.into()).emit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::entry_points::{
        EntryPointCatalog, EntryPointCatalogProvenance, EntryPointSnapshotCoverage,
    };

    fn catalog(snapshot_coverage: EntryPointSnapshotCoverage) -> EntryPointCatalog {
        EntryPointCatalog {
            target: "/tmp/target".to_string(),
            timestamp: 7,
            snapshot_timestamp: 3,
            total: 0,
            entry_points: vec![],
            provenance: EntryPointCatalogProvenance {
                built_at_ms: 7,
                sha256: "sha256:payload".to_string(),
                revision: None,
                revision_dirty: None,
                context_snapshot_timestamp: 3,
                context_snapshot_sha256: "sha256:context".to_string(),
                context_snapshot_tree_hash: None,
            },
            snapshot_coverage,
        }
    }

    fn response(snapshot_coverage: EntryPointSnapshotCoverage) -> Value {
        entry_points_response(
            std::path::Path::new("/tmp/target"),
            std::path::Path::new("/tmp/target/.kuzushi/entry-points.json"),
            &catalog(snapshot_coverage),
        )
    }

    #[test]
    fn complete_coverage_reports_a_completed_extraction() {
        let result = response(EntryPointSnapshotCoverage::Complete);

        assert_eq!(result["status"], "completed");
        assert_eq!(result["warnings"], json!([]));
        assert_eq!(result["data"]["snapshotCoverage"]["state"], "complete");
    }

    /// The operator-visible envelope must not call a catalog the snapshot
    /// could only partly supply a completed extraction.
    #[test]
    fn partial_coverage_reports_a_partial_extraction_with_the_disclosure() {
        let result = response(EntryPointSnapshotCoverage::Partial {
            reason: "snapshot byte budget".to_string(),
            array_cap: Some(2000),
            omitted_entries: Some(1186),
        });

        assert_eq!(result["status"], "partial");
        assert_eq!(result["data"]["snapshotCoverage"]["omittedEntries"], 1186);
        let warnings = result["warnings"].as_array().unwrap();
        assert_eq!(warnings.len(), 1);
        for text in [
            warnings[0].as_str().unwrap(),
            result["summary"].as_str().unwrap(),
            result["output"].as_str().unwrap(),
        ] {
            assert!(text.contains("snapshot byte budget"), "{text}");
        }
    }
}
