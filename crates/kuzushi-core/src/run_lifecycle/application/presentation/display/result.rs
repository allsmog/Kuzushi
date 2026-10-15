use super::super::{ResultArtifactPresentationV1, ResultSummaryPresentationV1};

pub(super) fn result_lines(value: &ResultSummaryPresentationV1) -> Vec<String> {
    let mut lines = vec![format!(
        "Result · {} ({}) · {} · {}",
        crate::modules::tool_display_name(value.tool.as_str()),
        value.tool,
        value.status,
        value.summary
    )];
    append_preview(&mut lines, value);
    append_distinct_issues(&mut lines, value);
    append_artifacts(&mut lines, &value.artifacts);
    lines
}

fn append_preview(lines: &mut Vec<String>, value: &ResultSummaryPresentationV1) {
    let summary = value.summary.as_str().trim();
    lines.extend(
        value
            .output_lines
            .iter()
            .filter(|line| line.as_str().trim() != summary)
            .map(|line| format!("  | {line}")),
    );
}

fn append_distinct_issues(lines: &mut Vec<String>, value: &ResultSummaryPresentationV1) {
    // Only exact trimmed text already displayed can fold. Similar messages
    // may contain different evidence or recovery instructions.
    let displayed = value
        .output_lines
        .iter()
        .map(|line| line.as_str().trim())
        .chain(std::iter::once(value.summary.as_str().trim()))
        .collect::<std::collections::BTreeSet<_>>();
    for (marker, messages) in [("⚠", &value.warnings), ("✗", &value.errors)] {
        lines.extend(
            messages
                .iter()
                .filter(|message| !displayed.contains(message.as_str().trim()))
                .map(|message| format!("  {marker} {message}")),
        );
    }
}

fn append_artifacts(lines: &mut Vec<String>, artifacts: &[ResultArtifactPresentationV1]) {
    if artifacts.is_empty() {
        return;
    }
    let labels = artifacts
        .iter()
        .map(|artifact| format!("{}={}", artifact.label, artifact.path))
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(format!("  artifacts: {labels}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_lifecycle::SafeText;

    fn summary() -> ResultSummaryPresentationV1 {
        ResultSummaryPresentationV1 {
            tool: SafeText::operator_visible("triage:run"),
            status: SafeText::operator_visible("blocked"),
            summary: SafeText::operator_visible("Approve an allowance; no model request started."),
            output_lines: Vec::new(),
            output_line_count: 0,
            warnings: Vec::new(),
            warning_count: 0,
            errors: Vec::new(),
            error_count: 0,
            artifacts: Vec::new(),
            artifact_count: 0,
        }
    }

    #[test]
    fn summary_diagnostics_render_once_without_mutating_receipt() {
        let mut value = summary();
        value.warnings.push(value.summary.clone());
        value
            .errors
            .push(SafeText::operator_visible(format!(" {} ", value.summary)));
        value.warning_count = 1;
        value.error_count = 1;
        let original = value.clone();
        let lines = result_lines(&value);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("blocked"));
        assert!(lines[0].contains("no model request started"));
        assert_eq!(value, original);
    }

    #[test]
    fn similar_diagnostics_and_unpreviewed_evidence_remain_visible() {
        let mut value = summary();
        value
            .output_lines
            .push(SafeText::operator_visible("Source changed"));
        value
            .warnings
            .push(SafeText::operator_visible("Source changed"));
        value
            .errors
            .push(SafeText::operator_visible("Source changed after approval"));
        value
            .errors
            .push(SafeText::operator_visible("no model request started"));
        let lines = result_lines(&value);
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert_eq!(lines[1], "  | Source changed");
        assert_eq!(lines[2], "  ✗ Source changed after approval");
        assert_eq!(lines[3], "  ✗ no model request started");
    }
}
