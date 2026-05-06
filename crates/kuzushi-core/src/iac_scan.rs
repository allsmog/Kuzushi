use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::findings::{Finding, Severity};
use crate::scan::{ScanCancellation, ScanEngine};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IacScanKind {
    Dockerfile,
    GithubActions,
    Terraform,
    All,
}

impl Default for IacScanKind {
    fn default() -> Self {
        Self::All
    }
}

impl IacScanKind {
    fn from_input(value: &str) -> Result<Self> {
        match value.trim() {
            "dockerfile" | "docker" => Ok(Self::Dockerfile),
            "github-actions" | "github_actions" | "actions" => Ok(Self::GithubActions),
            "terraform" | "tf" => Ok(Self::Terraform),
            "all" | "" => Ok(Self::All),
            other => anyhow::bail!(
                "iac-scan: unknown kind {other:?}; expected dockerfile, github-actions, terraform, or all"
            ),
        }
    }

    fn includes(self, other: Self) -> bool {
        self == Self::All || self == other
    }
}

#[derive(Debug, Clone)]
pub struct IacScanOptions {
    pub kind: IacScanKind,
    pub max_file_bytes: u64,
}

impl Default for IacScanOptions {
    fn default() -> Self {
        Self {
            kind: IacScanKind::All,
            max_file_bytes: 512 * 1024,
        }
    }
}

impl IacScanOptions {
    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let mut options = Self::default();
        if let Some(kind) = input.get("kind").and_then(Value::as_str) {
            options.kind = IacScanKind::from_input(kind)?;
        }
        if let Some(max_file_bytes) = input.get("maxFileBytes").and_then(Value::as_u64) {
            options.max_file_bytes = max_file_bytes.max(1024);
        }
        Ok(options)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IacScanReport {
    pub target: String,
    pub kind: IacScanKind,
    pub findings: Vec<IacScanFinding>,
    pub files_scanned: usize,
    pub files_skipped: usize,
}

impl IacScanReport {
    pub fn output(&self) -> String {
        let mut lines = vec![
            format!(
                "iac-scan: {} finding{} under {}",
                self.findings.len(),
                if self.findings.len() == 1 { "" } else { "s" },
                self.target
            ),
            format!("  Files scanned: {}", self.files_scanned),
            format!("  Files skipped: {}", self.files_skipped),
        ];

        if !self.findings.is_empty() {
            lines.push(String::new());
            lines.push("Top findings:".to_string());
            for finding in self.findings.iter().take(10) {
                lines.push(format!(
                    "  - {} - {} - {}:{}",
                    finding.severity.as_str(),
                    finding.rule_id,
                    finding.file_path,
                    finding.start_line
                ));
            }
            if self.findings.len() > 10 {
                lines.push(format!("  ... and {} more", self.findings.len() - 10));
            }
        }

        lines.join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        serde_json::json!({
            "ok": true,
            "output": self.output(),
            "data": {
                "count": self.findings.len(),
                "findings": self.findings,
                "filesScanned": self.files_scanned,
                "filesSkipped": self.files_skipped,
                "target": self.target,
                "kind": self.kind,
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IacScanFinding {
    pub fingerprint: String,
    pub rule_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub severity: Severity,
    pub message: String,
    pub evidence: String,
    pub manifest_kind: IacScanKind,
}

impl IacScanFinding {
    fn new(
        target: &Path,
        absolute_path: &Path,
        start_line: u32,
        manifest_kind: IacScanKind,
        rule_id: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
        evidence: impl Into<String>,
    ) -> Self {
        let rule_id = rule_id.into();
        let file_path = relative_display(target, absolute_path);
        let message = message.into();
        let evidence = evidence.into();
        let core = Finding::new_tool(
            "iac-scan",
            rule_id.clone(),
            file_path.clone(),
            start_line,
            Some(start_line),
            severity,
            format!("{message}\nEvidence: {evidence}"),
        );

        Self {
            fingerprint: core.fingerprint,
            rule_id,
            file_path,
            start_line,
            severity,
            message,
            evidence,
            manifest_kind,
        }
    }

    pub fn to_core_finding(&self) -> Finding {
        let mut finding = Finding::new_tool(
            "iac-scan",
            self.rule_id.clone(),
            self.file_path.clone(),
            self.start_line,
            Some(self.start_line),
            self.severity,
            format!("{}\nEvidence: {}", self.message, self.evidence),
        );
        finding.fingerprint = self.fingerprint.clone();
        finding.title = self.message.clone();
        finding
    }
}

#[derive(Debug, Clone)]
pub struct IacScanScanner {
    pub options: IacScanOptions,
}

impl Default for IacScanScanner {
    fn default() -> Self {
        Self {
            options: IacScanOptions::default(),
        }
    }
}

impl IacScanScanner {
    pub fn from_tool_input(input: &Value) -> Result<Self> {
        Ok(Self {
            options: IacScanOptions::from_tool_input(input)?,
        })
    }
}

impl ScanEngine for IacScanScanner {
    fn id(&self) -> &'static str {
        "iac-scan"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        let report = scan_iac(target, &self.options, cancellation)?;
        Ok(report
            .findings
            .iter()
            .map(IacScanFinding::to_core_finding)
            .collect())
    }
}

pub fn scan_iac(
    target: &Path,
    options: &IacScanOptions,
    cancellation: &ScanCancellation,
) -> Result<IacScanReport> {
    let target = canonical_directory(target)?;
    let mut files = Vec::new();
    collect_iac_files(&target, &target, options, &mut files)?;
    files.sort();

    let mut findings = Vec::new();
    let mut files_scanned = 0usize;
    let mut files_skipped = 0usize;

    for file in files {
        if cancellation.is_cancelled() {
            anyhow::bail!("iac-scan scan cancelled");
        }

        let metadata = match fs::metadata(&file) {
            Ok(metadata) => metadata,
            Err(_) => {
                files_skipped += 1;
                continue;
            }
        };
        if metadata.len() > options.max_file_bytes {
            files_skipped += 1;
            continue;
        }

        let raw = match fs::read_to_string(&file) {
            Ok(raw) => raw,
            Err(_) => {
                files_skipped += 1;
                continue;
            }
        };
        files_scanned += 1;

        match classify_iac_file(&target, &file) {
            Some(IacScanKind::Dockerfile) if options.kind.includes(IacScanKind::Dockerfile) => {
                findings.extend(analyze_dockerfile(&target, &file, &raw));
            }
            Some(IacScanKind::GithubActions)
                if options.kind.includes(IacScanKind::GithubActions) =>
            {
                findings.extend(analyze_github_actions(&target, &file, &raw));
            }
            Some(IacScanKind::Terraform) if options.kind.includes(IacScanKind::Terraform) => {
                findings.extend(analyze_terraform(&target, &file, &raw));
            }
            _ => {}
        }
    }

    Ok(IacScanReport {
        target: target.display().to_string(),
        kind: options.kind,
        findings,
        files_scanned,
        files_skipped,
    })
}

fn collect_iac_files(
    root: &Path,
    dir: &Path,
    options: &IacScanOptions,
    out: &mut Vec<PathBuf>,
) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if should_skip_dir(&name) {
            continue;
        }

        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_iac_files(root, &path, options, out)?;
        } else if file_type.is_file()
            && classify_iac_file(root, &path).is_some_and(|kind| options.kind.includes(kind))
        {
            out.push(path);
        }
    }

    Ok(())
}

fn classify_iac_file(root: &Path, path: &Path) -> Option<IacScanKind> {
    let file_name = path.file_name()?.to_string_lossy();
    if file_name == "Dockerfile" || file_name.starts_with("Dockerfile.") {
        return Some(IacScanKind::Dockerfile);
    }

    let rel = path.strip_prefix(root).unwrap_or(path);
    let mut components = rel.components().filter_map(|part| match part {
        std::path::Component::Normal(name) => Some(name.to_string_lossy().to_string()),
        _ => None,
    });
    if components.next().as_deref() == Some(".github")
        && components.next().as_deref() == Some("workflows")
        && matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("yml" | "yaml")
        )
    {
        return Some(IacScanKind::GithubActions);
    }

    if path.extension().and_then(|ext| ext.to_str()) == Some("tf") {
        return Some(IacScanKind::Terraform);
    }

    None
}

fn analyze_dockerfile(target: &Path, path: &Path, raw: &str) -> Vec<IacScanFinding> {
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

fn analyze_github_actions(target: &Path, path: &Path, raw: &str) -> Vec<IacScanFinding> {
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

fn analyze_terraform(target: &Path, path: &Path, raw: &str) -> Vec<IacScanFinding> {
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

fn canonical_directory(target: &Path) -> Result<PathBuf> {
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

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn should_skip_dir(name: &str) -> bool {
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

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(head, _)| head)
}

fn strip_hash_comment(line: &str) -> &str {
    strip_comment(line)
}

fn line_no(index: usize) -> u32 {
    u32::try_from(index + 1).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn scans_dockerfile_github_actions_and_terraform() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("Dockerfile"),
            "FROM node:latest\nCOPY . /app\nUSER root\n",
        )
        .unwrap();
        fs::create_dir_all(temp.path().join(".github/workflows")).unwrap();
        fs::write(
            temp.path().join(".github/workflows/ci.yml"),
            "on: pull_request_target\npermissions: write-all\nrun: echo ${{ github.event.pull_request.title }}\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("main.tf"),
            "cidr_blocks = [\"0.0.0.0/0\"]\nacl = \"public-read\"\n",
        )
        .unwrap();

        let report = scan_iac(
            temp.path(),
            &IacScanOptions::default(),
            &ScanCancellation::default(),
        )
        .unwrap();
        let rules = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();

        assert!(rules.contains(&"iac-scan/dockerfile-floating-image"));
        assert!(rules.contains(&"iac-scan/dockerfile-root-user"));
        assert!(rules.contains(&"iac-scan/actions-pull-request-target"));
        assert!(rules.contains(&"iac-scan/actions-write-all-permissions"));
        assert!(rules.contains(&"iac-scan/terraform-public-ingress"));
        assert!(rules.contains(&"iac-scan/terraform-public-s3-acl"));
        assert_eq!(report.files_scanned, 3);
    }

    #[test]
    fn kind_filter_limits_scanned_manifest_family() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("Dockerfile"), "FROM node:latest\n").unwrap();
        fs::write(
            temp.path().join("main.tf"),
            "cidr_blocks = [\"0.0.0.0/0\"]\n",
        )
        .unwrap();

        let report = scan_iac(
            temp.path(),
            &IacScanOptions {
                kind: IacScanKind::Terraform,
                ..IacScanOptions::default()
            },
            &ScanCancellation::default(),
        )
        .unwrap();

        assert_eq!(report.files_scanned, 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report.findings[0].rule_id,
            "iac-scan/terraform-public-ingress"
        );
    }

    #[test]
    fn missing_target_failure_is_actionable() {
        let temp = tempdir().unwrap();
        let err = scan_iac(
            &temp.path().join("missing"),
            &IacScanOptions::default(),
            &ScanCancellation::default(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("iac-scan: target does not exist"));
    }

    #[test]
    fn cancellation_is_observed_before_file_analysis() {
        let temp = tempdir().unwrap();
        fs::write(
            temp.path().join("main.tf"),
            "cidr_blocks = [\"0.0.0.0/0\"]\n",
        )
        .unwrap();
        let cancellation = ScanCancellation::default();
        cancellation.cancel();

        let err = scan_iac(temp.path(), &IacScanOptions::default(), &cancellation)
            .unwrap_err()
            .to_string();

        assert!(err.contains("iac-scan scan cancelled"));
    }
}
