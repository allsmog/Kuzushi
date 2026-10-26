pub(super) fn default_report_path(format: kuzushi_core::WorkspaceExportFormat) -> &'static str {
    match format {
        kuzushi_core::WorkspaceExportFormat::Sarif => ".kuzushi/reports/report.sarif",
        kuzushi_core::WorkspaceExportFormat::MarkdownBundle => ".kuzushi/reports/report/",
        kuzushi_core::WorkspaceExportFormat::Jsonl => ".kuzushi/reports/findings.jsonl",
        kuzushi_core::WorkspaceExportFormat::Json => ".kuzushi/reports/findings.json",
        kuzushi_core::WorkspaceExportFormat::Csv => ".kuzushi/reports/findings.csv",
        kuzushi_core::WorkspaceExportFormat::VulnFindings => ".kuzushi/reports/VULN-FINDINGS.json",
    }
}

pub(super) fn path_validation_error(text: &str) -> Option<&'static str> {
    if text.trim().is_empty() {
        return Some("Enter a destination path.");
    }
    text.chars()
        .any(char::is_control)
        .then_some("Use one path without line breaks or control characters.")
}
