use super::*;
use kuzushi_core::{WorkspaceExportCompleteness, WorkspaceExportFormat};

#[test]
fn report_formats_follow_the_locked_order_and_paths() {
    let mut route = ReportRouteState::default();
    let expected = [
        (
            WorkspaceExportFormat::Sarif,
            ".kuzushi/reports/report.sarif",
        ),
        (
            WorkspaceExportFormat::MarkdownBundle,
            ".kuzushi/reports/report/",
        ),
        (
            WorkspaceExportFormat::Jsonl,
            ".kuzushi/reports/findings.jsonl",
        ),
        (
            WorkspaceExportFormat::Json,
            ".kuzushi/reports/findings.json",
        ),
        (WorkspaceExportFormat::Csv, ".kuzushi/reports/findings.csv"),
        (
            WorkspaceExportFormat::VulnFindings,
            ".kuzushi/reports/VULN-FINDINGS.json",
        ),
    ];

    for (index, (format, path)) in expected.into_iter().enumerate() {
        assert_eq!(route.format(), format);
        assert_eq!(route.path_draft(), path);
        if index + 1 < ReportRouteState::FORMATS.len() {
            route.move_format(1);
        }
    }
}

#[test]
fn report_completeness_cycles_all_open_complete() {
    let mut route = ReportRouteState::default();
    assert_eq!(route.completeness(), WorkspaceExportCompleteness::All);
    route.cycle_completeness();
    assert_eq!(route.completeness(), WorkspaceExportCompleteness::Open);
    route.cycle_completeness();
    assert_eq!(route.completeness(), WorkspaceExportCompleteness::Complete);
    route.cycle_completeness();
    assert_eq!(route.completeness(), WorkspaceExportCompleteness::All);
}
