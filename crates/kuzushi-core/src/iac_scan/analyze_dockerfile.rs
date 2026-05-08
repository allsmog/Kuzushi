use super::prelude::*;
use super::*;

pub(crate) fn analyze_dockerfile(target: &Path, path: &Path, raw: &str) -> Vec<IacScanFinding> {
    let mut findings = Vec::new();
    let mut saw_non_root_user = false;
    let mut saw_user = false;

    for (index, line) in raw.lines().enumerate() {
        let line_no = line_no(index);
        let trimmed = strip_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();

        if lower.starts_with("from ") {
            let image = trimmed[5..].split_whitespace().next().unwrap_or("");
            if image.ends_with(":latest") {
                findings.push(IacScanFinding::new(
                    target,
                    path,
                    line_no,
                    IacScanKind::Dockerfile,
                    "iac-scan/dockerfile-floating-image",
                    Severity::Medium,
                    "Dockerfile pins a base image to the mutable latest tag",
                    trimmed,
                ));
            }
        }

        if lower.starts_with("user ") {
            saw_user = true;
            let user = trimmed[5..].trim();
            if user == "0" || user.eq_ignore_ascii_case("root") {
                findings.push(IacScanFinding::new(
                    target,
                    path,
                    line_no,
                    IacScanKind::Dockerfile,
                    "iac-scan/dockerfile-root-user",
                    Severity::High,
                    "Dockerfile explicitly runs the container as root",
                    trimmed,
                ));
            } else {
                saw_non_root_user = true;
            }
        }

        if lower.starts_with("add http://") || lower.starts_with("add https://") {
            findings.push(IacScanFinding::new(
                target,
                path,
                line_no,
                IacScanKind::Dockerfile,
                "iac-scan/dockerfile-remote-add",
                Severity::Medium,
                "Dockerfile downloads remote content with ADD during image build",
                trimmed,
            ));
        }

        if lower.starts_with("copy . ") || lower == "copy ." {
            findings.push(IacScanFinding::new(
                target,
                path,
                line_no,
                IacScanKind::Dockerfile,
                "iac-scan/dockerfile-broad-copy",
                Severity::Low,
                "Dockerfile copies the full build context into the image",
                trimmed,
            ));
        }
    }

    if !saw_user || !saw_non_root_user {
        findings.push(IacScanFinding::new(
            target,
            path,
            1,
            IacScanKind::Dockerfile,
            "iac-scan/dockerfile-missing-non-root-user",
            Severity::Medium,
            "Dockerfile does not set a non-root runtime USER",
            "no non-root USER instruction found",
        ));
    }

    findings
}
