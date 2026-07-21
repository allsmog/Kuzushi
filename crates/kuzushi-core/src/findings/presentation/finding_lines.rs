use super::*;

/// One operator-facing line per finding, shared by every scan-report output.
pub(crate) fn finding_line(finding: &Finding) -> String {
    format!(
        "  - {} - {} - {}:{}",
        finding.severity.as_str(),
        finding.rule_id,
        finding.file_path,
        finding.start_line
    )
}

/// The first `limit` findings as lines, with a trailing "... and N more"
/// disclosure when the list was clamped.
pub(crate) fn top_finding_lines(findings: &[Finding], limit: usize) -> Vec<String> {
    let mut lines: Vec<String> = findings.iter().take(limit).map(finding_line).collect();
    if findings.len() > limit {
        lines.push(format!("  ... and {} more", findings.len() - limit));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_finding_lines_clamps_with_remaining_count() {
        let findings: Vec<Finding> = (0..12)
            .map(|index| test_finding(&format!("rule-{index}")))
            .collect();

        let lines = top_finding_lines(&findings, 10);

        assert_eq!(lines.len(), 11);
        assert_eq!(lines[0], "  - high - rule-0 - src/a.c:42");
        assert_eq!(lines[10], "  ... and 2 more");
    }

    #[test]
    fn top_finding_lines_at_limit_has_no_remaining_line() {
        let findings: Vec<Finding> = (0..10)
            .map(|index| test_finding(&format!("rule-{index}")))
            .collect();

        let lines = top_finding_lines(&findings, 10);

        assert_eq!(lines.len(), 10);
        assert!(lines.iter().all(|line| !line.contains("more")));
    }

    fn test_finding(rule_id: &str) -> Finding {
        Finding::new_tool(
            "test-tool",
            rule_id,
            "src/a.c",
            42,
            None,
            Severity::High,
            "test finding",
        )
    }
}
