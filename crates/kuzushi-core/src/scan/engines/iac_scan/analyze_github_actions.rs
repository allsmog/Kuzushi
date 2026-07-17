use super::*;

pub(crate) fn analyze_github_actions(target: &Path, path: &Path, raw: &str) -> Vec<IacScanFinding> {
    raw.lines()
        .enumerate()
        .flat_map(|(index, line)| github_actions_line_findings(target, path, line_no(index), line))
        .collect()
}

fn github_actions_line_findings(
    target: &Path,
    path: &Path,
    line_no: u32,
    line: &str,
) -> Vec<IacScanFinding> {
    let trimmed = line.trim();
    let lower = trimmed.to_ascii_lowercase();
    [
        pull_request_target_finding(target, path, line_no, trimmed, &lower),
        write_all_permissions_finding(target, path, line_no, trimmed, &lower),
        write_permission_scope_finding(target, path, line_no, trimmed, &lower),
        untrusted_pr_context_finding(target, path, line_no, trimmed, &lower),
        mutable_action_reference_finding(target, path, line_no, trimmed),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn pull_request_target_finding(
    target: &Path,
    path: &Path,
    line_no: u32,
    trimmed: &str,
    lower: &str,
) -> Option<IacScanFinding> {
    lower.contains("pull_request_target").then(|| {
        github_actions_finding(
            target,
            path,
            line_no,
            "iac-scan/actions-pull-request-target",
            Severity::High,
            "GitHub Actions workflow runs on pull_request_target",
            trimmed,
        )
    })
}

fn write_all_permissions_finding(
    target: &Path,
    path: &Path,
    line_no: u32,
    trimmed: &str,
    lower: &str,
) -> Option<IacScanFinding> {
    lower.contains("permissions: write-all").then(|| {
        github_actions_finding(
            target,
            path,
            line_no,
            "iac-scan/actions-write-all-permissions",
            Severity::High,
            "GitHub Actions workflow grants write-all token permissions",
            trimmed,
        )
    })
}

fn untrusted_pr_context_finding(
    target: &Path,
    path: &Path,
    line_no: u32,
    trimmed: &str,
    lower: &str,
) -> Option<IacScanFinding> {
    contains_untrusted_pr_context(lower).then(|| {
        github_actions_finding(
            target,
            path,
            line_no,
            "iac-scan/actions-untrusted-pr-context",
            Severity::Medium,
            "GitHub Actions workflow interpolates untrusted pull request context",
            trimmed,
        )
    })
}

fn write_permission_scope_finding(
    target: &Path,
    path: &Path,
    line_no: u32,
    trimmed: &str,
    lower: &str,
) -> Option<IacScanFinding> {
    github_write_permission_scope(lower).then(|| {
        github_actions_finding(
            target,
            path,
            line_no,
            "iac-scan/actions-write-permission-scope",
            Severity::Medium,
            "GitHub Actions workflow grants a sensitive token permission write scope",
            trimmed,
        )
    })
}

fn mutable_action_reference_finding(
    target: &Path,
    path: &Path,
    line_no: u32,
    trimmed: &str,
) -> Option<IacScanFinding> {
    mutable_action_reference(trimmed).map(|action_ref| {
        github_actions_finding(
            target,
            path,
            line_no,
            "iac-scan/actions-mutable-action-reference",
            Severity::Medium,
            "GitHub Actions workflow uses a mutable action reference",
            action_ref,
        )
    })
}

fn github_actions_finding(
    target: &Path,
    path: &Path,
    line_no: u32,
    rule_id: &'static str,
    severity: Severity,
    message: &'static str,
    evidence: &str,
) -> IacScanFinding {
    IacScanFinding::new(
        target,
        path,
        line_no,
        IacScanKind::GithubActions,
        rule_id,
        severity,
        message,
        evidence,
    )
}

fn contains_untrusted_pr_context(line: &str) -> bool {
    [
        "github.event.pull_request.head",
        "github.head_ref",
        "github.event.pull_request.title",
        "github.event.pull_request.body",
    ]
    .iter()
    .any(|needle| line.contains(needle))
}

fn github_write_permission_scope(line: &str) -> bool {
    const SENSITIVE_WRITE_SCOPES: &[&str] = &["actions", "contents", "id-token", "packages"];
    let Some((scope, value)) = line.split_once(':') else {
        return false;
    };
    let scope = scope.trim();
    let value = value.trim();
    SENSITIVE_WRITE_SCOPES
        .iter()
        .any(|sensitive_scope| scope == *sensitive_scope && value.starts_with("write"))
}

fn mutable_action_reference(line: &str) -> Option<&str> {
    let value = line
        .strip_prefix("uses:")
        .or_else(|| line.strip_prefix("- uses:"))?
        .trim();
    let value = trim_yaml_string(value);
    if value.starts_with("./") || value.starts_with("../") {
        return None;
    }
    if value.starts_with("docker://") {
        return docker_image_uses_mutable_tag(value).then_some(value);
    }
    let (_, reference) = value.rsplit_once('@')?;
    is_mutable_action_ref(reference).then_some(value)
}

fn trim_yaml_string(value: &str) -> &str {
    let value = value.trim_end_matches(',');
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|inner| inner.strip_suffix('\''))
        })
        .unwrap_or(value)
}

fn is_mutable_action_ref(reference: &str) -> bool {
    matches!(
        reference.to_ascii_lowercase().as_str(),
        "main" | "master" | "latest" | "dev" | "develop" | "head" | "trunk"
    )
}

fn docker_image_uses_mutable_tag(value: &str) -> bool {
    value
        .rsplit_once(':')
        .is_some_and(|(_, tag)| tag.eq_ignore_ascii_case("latest"))
}
