pub(crate) fn partial_summary(
    plan: &crate::capabilities::full_mode_multi::FullModePlan,
) -> Option<String> {
    let coverage = plan.coverage.as_ref()?;
    if coverage.canceled {
        return Some("Source planning canceled; no scan ran.".into());
    }
    if coverage.enumeration_incomplete {
        return Some(
            "Partial source enumeration; execution blocked. Review inventory limits.".into(),
        );
    }
    coverage.omitted_sources.first().map(|source| {
        format!(
            "Partial source plan: {} omitted, including {}. No scan ran.",
            coverage.omitted_sources.len(),
            source.path
        )
    })
}

pub(crate) fn detail(plan: &crate::capabilities::full_mode_multi::FullModePlan) -> String {
    let Some(coverage) = &plan.coverage else {
        return "Source inventory receipt unavailable.".into();
    };
    let mut lines = vec![format!("Source planning: {} · {}. No complete repository coverage claim.", coverage.enumeration,
        if coverage.is_partial() { "partial; execution blocked" } else { "selected sources planned" }),
        format!("Source limits: {} files / {} bytes. Planned source bytes: {}. Window-planning reads: {} bytes.", coverage.max_source_files, coverage.max_source_bytes, coverage.selected_source_bytes, coverage.planning_read_bytes),
        format!("Excluded paths: {}. Omitted sources: {}. Canceled: {}.", coverage.excluded_paths.len(), coverage.omitted_sources.len(), coverage.canceled)];
    if let Some(limit) = &coverage.inventory_limitation {
        lines.push(format!("Inventory limitation: {limit}"));
    }
    if coverage.enumeration == "git-index" {
        lines.push("Git-tracked files only; untracked files are outside this plan. An explicit scope can name them.".into());
    }
    lines.extend(
        coverage
            .omitted_sources
            .iter()
            .take(3)
            .map(|source| format!("Omitted {}: {}", source.path, source.reason)),
    );
    lines.push("Full path exclusions and inventory limits are in the plan coverage receipt. A partial plan grants no model work; select and review a smaller explicit scope.".into());
    lines.join("\n")
}
