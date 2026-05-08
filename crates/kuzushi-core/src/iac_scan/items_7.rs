use super::prelude::*;
use super::*;

pub(crate) fn analyze_terraform(target: &Path, path: &Path, raw: &str) -> Vec<IacScanFinding> {
    let mut findings = Vec::new();

    for (index, line) in raw.lines().enumerate() {
        let line_no = line_no(index);
        let trimmed = strip_hash_comment(line).trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();

        if lower.contains("0.0.0.0/0") || lower.contains("::/0") {
            findings.push(IacScanFinding::new(
                target,
                path,
                line_no,
                IacScanKind::Terraform,
                "iac-scan/terraform-public-ingress",
                Severity::High,
                "Terraform allows public network access from a world-routable CIDR",
                trimmed,
            ));
        }

        if lower.contains("acl") && lower.contains("public-read") {
            findings.push(IacScanFinding::new(
                target,
                path,
                line_no,
                IacScanKind::Terraform,
                "iac-scan/terraform-public-s3-acl",
                Severity::High,
                "Terraform configures an S3 bucket ACL as public-read",
                trimmed,
            ));
        }

        if lower.contains("publicly_accessible") && lower.contains("true") {
            findings.push(IacScanFinding::new(
                target,
                path,
                line_no,
                IacScanKind::Terraform,
                "iac-scan/terraform-public-database",
                Severity::High,
                "Terraform marks a managed database as publicly accessible",
                trimmed,
            ));
        }

        if lower.contains("access_key") || lower.contains("secret_key") {
            findings.push(IacScanFinding::new(
                target,
                path,
                line_no,
                IacScanKind::Terraform,
                "iac-scan/terraform-hardcoded-cloud-credential",
                Severity::High,
                "Terraform contains an inline cloud credential setting",
                trimmed,
            ));
        }
    }

    findings
}

pub(crate) fn canonical_directory(target: &Path) -> Result<PathBuf> {
    if !target.exists() {
        anyhow::bail!("iac-scan: target does not exist: {}", target.display());
    }
    if !target.is_dir() {
        anyhow::bail!("iac-scan: target is not a directory: {}", target.display());
    }
    target
        .canonicalize()
        .with_context(|| format!("iac-scan: could not canonicalize {}", target.display()))
}

pub(crate) fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

pub(crate) fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
            | ".kuzushi"
            | "node_modules"
            | "vendor"
            | "third_party"
            | "dist"
            | "build"
            | ".next"
            | ".terraform"
            | "target"
    )
}

pub(crate) fn strip_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(head, _)| head)
}

pub(crate) fn strip_hash_comment(line: &str) -> &str {
    strip_comment(line)
}

pub(crate) fn line_no(index: usize) -> u32 {
    u32::try_from(index + 1).unwrap_or(u32::MAX)
}
