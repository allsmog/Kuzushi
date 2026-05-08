use super::prelude::*;
use super::*;

pub(crate) fn analyze_github_actions(target: &Path, path: &Path, raw: &str) -> Vec<IacScanFinding> {
    let mut findings = Vec::new();

    for (index, line) in raw.lines().enumerate() {
        let line_no = line_no(index);
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();

        if lower.contains("pull_request_target") {
            findings.push(IacScanFinding::new(
                target,
                path,
                line_no,
                IacScanKind::GithubActions,
                "iac-scan/actions-pull-request-target",
                Severity::High,
                "GitHub Actions workflow runs on pull_request_target",
                trimmed,
            ));
        }

        if lower.contains("permissions: write-all") {
            findings.push(IacScanFinding::new(
                target,
                path,
                line_no,
                IacScanKind::GithubActions,
                "iac-scan/actions-write-all-permissions",
                Severity::High,
                "GitHub Actions workflow grants write-all token permissions",
                trimmed,
            ));
        }

        if lower.contains("github.event.pull_request.head")
            || lower.contains("github.head_ref")
            || lower.contains("github.event.pull_request.title")
            || lower.contains("github.event.pull_request.body")
        {
            findings.push(IacScanFinding::new(
                target,
                path,
                line_no,
                IacScanKind::GithubActions,
                "iac-scan/actions-untrusted-pr-context",
                Severity::Medium,
                "GitHub Actions workflow interpolates untrusted pull request context",
                trimmed,
            ));
        }
    }

    findings
}
