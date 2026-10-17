use kuzushi_core::{RunSummary, WorkflowPhase};

/// Legacy summary kinds stay readable, but declared auxiliary tools never
/// establish a Scan result, even when an older receipt labels them as scans.
pub(super) fn has_scan_phase_result(summary: &RunSummary) -> bool {
    let policy = summary.tool.as_deref().map(|tool| {
        (
            kuzushi_core::modules::autonomy::tool_has_phase_result(tool),
            kuzushi_core::modules::tool_phase(tool),
        )
    });
    match policy {
        Some((Some(false), _)) => false,
        Some((_, Some(WorkflowPhase::Scan))) => true,
        _ => summary.kind.eq_ignore_ascii_case("scan"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_auxiliary_work_never_inherits_legacy_scan_ownership() {
        for tool in ["full-mode:hunt", "codeql:scan", "findings:goals"] {
            assert!(
                !has_scan_phase_result(&summary("scan", Some(tool))),
                "{tool}"
            );
        }
    }

    #[test]
    fn declared_scan_and_unknown_legacy_scan_remain_readable() {
        for (kind, tool) in [
            ("tool", Some("agentic-sast:scan")),
            ("scan", Some("legacy-engine:scan")),
            ("scan", None),
        ] {
            assert!(has_scan_phase_result(&summary(kind, tool)));
        }
        assert!(!has_scan_phase_result(&summary(
            "tool",
            Some("legacy:read")
        )));
    }

    fn summary(kind: &str, tool: Option<&str>) -> RunSummary {
        RunSummary::running("recorded-run", kind, tool.map(String::from), ".").complete()
    }
}
