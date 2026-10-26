use super::*;

pub(crate) fn analyze_terraform(target: &Path, path: &Path, raw: &str) -> Vec<IacScanFinding> {
    let mut findings = Vec::new();
    let mut blocks = TerraformBlockPath::default();

    for (index, line) in raw.lines().enumerate() {
        let trimmed = strip_hash_comment(line).trim();
        let locator = blocks.locator_for(trimmed);
        blocks.advance(trimmed);
        let statement = TerraformStatement {
            line_no: line_no(index),
            text: trimmed,
            locator,
        };
        findings.extend(statement_findings(target, path, &statement));
    }

    findings
}

struct TerraformStatement<'a> {
    line_no: u32,
    text: &'a str,
    locator: Option<String>,
}

fn statement_findings(
    target: &Path,
    path: &Path,
    statement: &TerraformStatement<'_>,
) -> Vec<IacScanFinding> {
    let lower = statement.text.to_ascii_lowercase();
    TERRAFORM_LINE_DETECTORS
        .iter()
        .filter(|detector| !lower.is_empty() && detector.matches(&lower))
        .map(|detector| detector.finding(target, path, statement))
        .collect()
}

struct TerraformLineDetector {
    rule_id: &'static str,
    title: &'static str,
    any: &'static [&'static str],
    all: &'static [&'static str],
}

impl TerraformLineDetector {
    fn matches(&self, line: &str) -> bool {
        matches_any(line, self.any) && matches_all(line, self.all)
    }

    fn finding(
        &self,
        target: &Path,
        path: &Path,
        statement: &TerraformStatement<'_>,
    ) -> IacScanFinding {
        let finding = IacScanFinding::new(
            target,
            path,
            statement.line_no,
            IacScanKind::Terraform,
            self.rule_id,
            Severity::High,
            self.title,
            statement.text,
        );
        match &statement.locator {
            Some(locator) => finding.with_structural_locator(locator.clone()),
            None => finding,
        }
    }
}

fn matches_any(line: &str, needles: &[&str]) -> bool {
    needles.is_empty() || needles.iter().any(|needle| line.contains(needle))
}

fn matches_all(line: &str, needles: &[&str]) -> bool {
    needles.iter().all(|needle| line.contains(needle))
}

const TERRAFORM_LINE_DETECTORS: &[TerraformLineDetector] = &[
    TerraformLineDetector {
        rule_id: "iac-scan/terraform-public-ingress",
        title: "Terraform allows public network access from a world-routable CIDR",
        any: &["0.0.0.0/0", "::/0"],
        all: &[],
    },
    TerraformLineDetector {
        rule_id: "iac-scan/terraform-public-s3-acl",
        title: "Terraform configures an S3 bucket ACL as public-read",
        any: &[],
        all: &["acl", "public-read"],
    },
    TerraformLineDetector {
        rule_id: "iac-scan/terraform-public-database",
        title: "Terraform marks a managed database as publicly accessible",
        any: &[],
        all: &["publicly_accessible", "true"],
    },
    TerraformLineDetector {
        rule_id: "iac-scan/terraform-hardcoded-cloud-credential",
        title: "Terraform contains an inline cloud credential setting",
        any: &["access_key", "secret_key"],
        all: &[],
    },
];

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
    crate::workspace::inventory::repo_relative(root, path)
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
