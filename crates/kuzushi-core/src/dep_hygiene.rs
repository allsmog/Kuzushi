use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::findings::{Finding, Severity};
use crate::scan::{ScanCancellation, ScanEngine};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DepHygieneReport {
    pub target: String,
    pub count: usize,
    pub findings: Vec<DepHygieneFinding>,
}

impl DepHygieneReport {
    pub fn output(&self) -> String {
        if self.findings.is_empty() {
            return format!(
                "dep-hygiene: no risky specifiers found under {}.",
                self.target
            );
        }

        let mut lines = vec![
            format!(
                "dep-hygiene: {} risky specifier{} under {}",
                self.findings.len(),
                if self.findings.len() == 1 { "" } else { "s" },
                self.target
            ),
            String::new(),
        ];

        for severity in [
            DepHygieneSeverity::High,
            DepHygieneSeverity::Medium,
            DepHygieneSeverity::Low,
        ] {
            let grouped = self
                .findings
                .iter()
                .filter(|finding| finding.severity == severity)
                .collect::<Vec<_>>();
            if grouped.is_empty() {
                continue;
            }

            lines.push(format!("  [{}]", severity.as_str().to_ascii_uppercase()));
            for finding in grouped {
                let rel = relative_display(Path::new(&self.target), Path::new(&finding.file_path));
                let constraint = if finding.raw_constraint.is_empty() {
                    "(empty)"
                } else {
                    &finding.raw_constraint
                };
                lines.push(format!(
                    "    {rel} :: {}@{} - {}",
                    finding.package_name, constraint, finding.reason
                ));
            }
            lines.push(String::new());
        }

        lines.join("\n").trim_end().to_string()
    }

    pub fn to_tool_json(&self) -> Value {
        serde_json::json!({
            "ok": true,
            "output": self.output(),
            "data": {
                "count": self.count,
                "findings": self.findings,
                "target": self.target,
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DepHygieneFinding {
    pub manifest: String,
    pub file_path: String,
    pub package_name: String,
    pub raw_constraint: String,
    pub severity: DepHygieneSeverity,
    pub reason: String,
}

impl DepHygieneFinding {
    fn new(
        manifest: ManifestKind,
        file_path: &Path,
        package_name: impl Into<String>,
        raw_constraint: impl Into<String>,
        severity: DepHygieneSeverity,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            manifest: manifest.file_name().to_string(),
            file_path: file_path.display().to_string(),
            package_name: package_name.into(),
            raw_constraint: raw_constraint.into(),
            severity,
            reason: reason.into(),
        }
    }

    fn to_core_finding(&self, target: &Path) -> Finding {
        let absolute_path = Path::new(&self.file_path);
        let file_path = absolute_path
            .strip_prefix(target)
            .unwrap_or(absolute_path)
            .display()
            .to_string();
        let constraint = if self.raw_constraint.is_empty() {
            "(empty)"
        } else {
            &self.raw_constraint
        };
        let message = format!(
            "{}@{} in {}: {}",
            self.package_name, constraint, self.manifest, self.reason
        );
        Finding::new_tool(
            "dep-hygiene",
            format!("dep-hygiene/{}", self.manifest.replace('.', "-")),
            file_path,
            1,
            None,
            self.severity.to_core_severity(),
            message,
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DepHygieneSeverity {
    Low,
    Medium,
    High,
}

impl DepHygieneSeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    fn to_core_severity(self) -> Severity {
        match self {
            Self::Low => Severity::Low,
            Self::Medium => Severity::Medium,
            Self::High => Severity::High,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DepHygieneScanner;

impl ScanEngine for DepHygieneScanner {
    fn id(&self) -> &'static str {
        "dep-hygiene"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        if cancellation.is_cancelled() {
            anyhow::bail!("dep-hygiene scan cancelled");
        }

        let report = check_dependency_hygiene(target)?;
        Ok(report
            .findings
            .iter()
            .map(|finding| finding.to_core_finding(Path::new(&report.target)))
            .collect())
    }
}

/// Ground-truth Rust supply-chain scanner backed by `cargo audit --json`.
///
/// Mirrors the Xint Code design instinct of preferring deterministic scanner
/// output over LLM-rediscovered manifest patterns. Runs only when the target
/// has a `Cargo.lock` and the `cargo-audit` binary is on PATH; otherwise
/// returns no findings (the legacy text-parse path in `DepHygieneScanner`
/// remains the fallback).
#[derive(Debug, Clone, Default)]
pub struct CargoAuditScanner;

impl CargoAuditScanner {
    /// Probe whether `cargo audit` is callable in the current environment.
    /// Returns `false` on any spawn or non-success exit, including when
    /// `cargo` itself is missing.
    pub fn binary_available() -> bool {
        Command::new("cargo")
            .args(["audit", "--version"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

impl ScanEngine for CargoAuditScanner {
    fn id(&self) -> &'static str {
        "cargo-audit"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        if cancellation.is_cancelled() {
            anyhow::bail!("cargo-audit scan cancelled");
        }

        let lockfile = target.join("Cargo.lock");
        if !lockfile.exists() {
            return Ok(Vec::new());
        }
        if !Self::binary_available() {
            return Ok(Vec::new());
        }

        let output = Command::new("cargo")
            .args(["audit", "--json"])
            .arg("--file")
            .arg(&lockfile)
            .current_dir(target)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| "cargo-audit: failed to invoke `cargo audit`")?;

        // cargo-audit exits non-zero when vulnerabilities are found; that's
        // expected. Any output that fails to parse is treated as no findings.
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_cargo_audit_output(&stdout))
    }
}

/// Parse a `cargo audit --json` document into core `Finding`s.
///
/// Public for testing and for any future direct-pipe callers (e.g. CI feeding
/// pre-captured advisories into the findings store without re-running cargo).
pub fn parse_cargo_audit_output(json: &str) -> Vec<Finding> {
    let value: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut findings = Vec::new();
    let list = value
        .get("vulnerabilities")
        .and_then(|v| v.get("list"))
        .and_then(Value::as_array);
    let Some(list) = list else {
        return findings;
    };

    for entry in list {
        let advisory = match entry.get("advisory") {
            Some(a) => a,
            None => continue,
        };
        let id = advisory
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("RUSTSEC-UNKNOWN")
            .to_string();
        let title = advisory
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("(no title)")
            .to_string();
        let package = entry
            .get("package")
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("?");
        let version = entry
            .get("package")
            .and_then(|p| p.get("version"))
            .and_then(Value::as_str)
            .unwrap_or("?");
        let cvss = advisory.get("cvss").and_then(Value::as_str);
        let severity = severity_from_cvss(cvss);
        let message = format!("{id}: {package}@{version} — {title}");

        findings.push(Finding::new_tool(
            "cargo-audit",
            id,
            "Cargo.lock",
            1,
            None,
            severity,
            message,
        ));
    }

    findings
}

fn severity_from_cvss(cvss: Option<&str>) -> Severity {
    let Some(s) = cvss else {
        return Severity::Medium;
    };
    let trimmed = s.trim();
    if let Ok(score) = trimmed.parse::<f64>() {
        return match score {
            x if x >= 9.0 => Severity::Critical,
            x if x >= 7.0 => Severity::High,
            x if x >= 4.0 => Severity::Medium,
            x if x > 0.0 => Severity::Low,
            _ => Severity::Unknown,
        };
    }
    let upper = trimmed.to_ascii_uppercase();
    if upper.contains("CRITICAL") {
        return Severity::Critical;
    }
    // CVSS v3 vector form encodes impact metrics as /C:H/I:H/A:H. Any
    // high-impact letter on confidentiality, integrity, or availability is
    // a High signal — close enough for triage without a full CVSS parser.
    if upper.contains("HIGH")
        || upper.contains("C:H")
        || upper.contains("I:H")
        || upper.contains("A:H")
    {
        return Severity::High;
    }
    if upper.contains("MEDIUM") {
        return Severity::Medium;
    }
    if upper.contains("LOW")
        || upper.contains("C:L")
        || upper.contains("I:L")
        || upper.contains("A:L")
    {
        return Severity::Low;
    }
    Severity::Medium
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    PackageJson,
    PyprojectToml,
    CargoToml,
    GoMod,
}

impl ManifestKind {
    fn file_name(self) -> &'static str {
        match self {
            Self::PackageJson => "package.json",
            Self::PyprojectToml => "pyproject.toml",
            Self::CargoToml => "Cargo.toml",
            Self::GoMod => "go.mod",
        }
    }
}

const TARGET_MANIFESTS: [ManifestKind; 4] = [
    ManifestKind::PackageJson,
    ManifestKind::PyprojectToml,
    ManifestKind::CargoToml,
    ManifestKind::GoMod,
];

pub fn check_dependency_hygiene(target: &Path) -> Result<DepHygieneReport> {
    let target = canonical_directory(target)?;
    let mut findings = Vec::new();

    for manifest in TARGET_MANIFESTS {
        let manifest_path = target.join(manifest.file_name());
        if !manifest_path.exists() {
            continue;
        }
        let raw = fs::read_to_string(&manifest_path)
            .with_context(|| format!("dep-hygiene: failed to read {}", manifest_path.display()))?;
        findings.extend(analyze_manifest(manifest, &manifest_path, &raw));
    }

    Ok(DepHygieneReport {
        target: target.display().to_string(),
        count: findings.len(),
        findings,
    })
}

pub fn analyze_manifest(
    manifest: ManifestKind,
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    match manifest {
        ManifestKind::PackageJson => analyze_package_json(file_path, raw),
        ManifestKind::PyprojectToml => analyze_pyproject_toml(file_path, raw),
        ManifestKind::CargoToml => analyze_cargo_toml(file_path, raw),
        ManifestKind::GoMod => analyze_go_mod(file_path, raw),
    }
}

fn analyze_package_json(file_path: &Path, raw: &str) -> Vec<DepHygieneFinding> {
    let Ok(parsed) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    for section in ["dependencies", "devDependencies"] {
        let Some(deps) = parsed.get(section).and_then(Value::as_object) else {
            continue;
        };

        for (name, value) in deps {
            let Some(raw_constraint) = value.as_str() else {
                continue;
            };
            let trimmed = raw_constraint.trim();
            if trimmed.is_empty()
                || trimmed == "*"
                || trimmed == "latest"
                || trimmed.ends_with("@latest")
            {
                out.push(DepHygieneFinding::new(
                    ManifestKind::PackageJson,
                    file_path,
                    name,
                    raw_constraint,
                    DepHygieneSeverity::High,
                    format!(
                        "{section}: floating tag - pulls whatever is published next, even a malicious release"
                    ),
                ));
                continue;
            }
            if is_floor_only_number_range(trimmed) {
                out.push(DepHygieneFinding::new(
                    ManifestKind::PackageJson,
                    file_path,
                    name,
                    raw_constraint,
                    DepHygieneSeverity::Medium,
                    format!(
                        "{section}: floor-only range; declare an upper bound to prevent unintended major upgrades"
                    ),
                ));
                continue;
            }
            if trimmed.starts_with("^0.") {
                out.push(DepHygieneFinding::new(
                    ManifestKind::PackageJson,
                    file_path,
                    name,
                    raw_constraint,
                    DepHygieneSeverity::Low,
                    format!(
                        "{section}: caret on 0.x - pre-1.0 packages can break under any release"
                    ),
                ));
            }
        }
    }

    out
}

fn analyze_pyproject_toml(file_path: &Path, raw: &str) -> Vec<DepHygieneFinding> {
    let mut out = Vec::new();
    let mut in_deps = false;
    let mut in_poetry_deps = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed == "[project]" || trimmed == "[project.optional-dependencies]";
            in_poetry_deps = trimmed == "[tool.poetry.dependencies]"
                || trimmed == "[tool.poetry.dev-dependencies]";
            continue;
        }

        if in_deps {
            if let Some(spec) = quoted_list_entry(trimmed) {
                if let Some(finding) = analyze_pep508(file_path, spec) {
                    out.push(finding);
                }
            }
        }

        if in_poetry_deps {
            let Some((name, value)) = split_assignment(trimmed) else {
                continue;
            };
            if value.starts_with('{') {
                continue;
            }
            let constraint = clean_quoted_constraint(value);
            if constraint == "*"
                || constraint.is_empty()
                || constraint.eq_ignore_ascii_case("latest")
            {
                out.push(DepHygieneFinding::new(
                    ManifestKind::PyprojectToml,
                    file_path,
                    name,
                    constraint,
                    DepHygieneSeverity::High,
                    "poetry: wildcard pin - accepts any future release without review",
                ));
            } else if is_floor_only_number_range(&constraint) {
                out.push(DepHygieneFinding::new(
                    ManifestKind::PyprojectToml,
                    file_path,
                    name,
                    constraint,
                    DepHygieneSeverity::Medium,
                    "poetry: floor-only range; add an upper bound to fix the supply-chain surface",
                ));
            }
        }
    }

    out
}

fn analyze_pep508(file_path: &Path, spec: &str) -> Option<DepHygieneFinding> {
    let cleaned = spec.split(';').next().unwrap_or_default().trim();
    let name_len = cleaned
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
        .map(char::len_utf8)
        .sum::<usize>();
    if name_len == 0 {
        return None;
    }
    let name = &cleaned[..name_len];
    let constraint = cleaned[name_len..].trim();

    if constraint.is_empty() {
        return Some(DepHygieneFinding::new(
            ManifestKind::PyprojectToml,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::High,
            "PEP 508: unconstrained - accepts any installed version, including malicious",
        ));
    }

    if is_floor_only_nonempty_range(constraint) {
        return Some(DepHygieneFinding::new(
            ManifestKind::PyprojectToml,
            file_path,
            name,
            constraint,
            DepHygieneSeverity::Medium,
            "PEP 508: floor-only - declare an upper bound for supply-chain hygiene",
        ));
    }

    None
}

fn analyze_cargo_toml(file_path: &Path, raw: &str) -> Vec<DepHygieneFinding> {
    let mut out = Vec::new();
    let mut in_deps = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_deps = trimmed == "[dependencies]" || trimmed == "[dev-dependencies]";
            continue;
        }
        if !in_deps || trimmed.is_empty() {
            continue;
        }

        let Some((name, value)) = split_assignment(trimmed) else {
            continue;
        };
        if value.starts_with('{') {
            continue;
        }
        let constraint = clean_quoted_constraint(value);
        if constraint == "*" || constraint.is_empty() {
            out.push(DepHygieneFinding::new(
                ManifestKind::CargoToml,
                file_path,
                name,
                constraint,
                DepHygieneSeverity::High,
                "Cargo: wildcard pin - accepts any future release without review",
            ));
        } else if is_floor_only_number_range(&constraint) {
            out.push(DepHygieneFinding::new(
                ManifestKind::CargoToml,
                file_path,
                name,
                constraint,
                DepHygieneSeverity::Medium,
                "Cargo: floor-only range; declare an upper bound to fix the supply-chain surface",
            ));
        }
    }

    out
}

fn analyze_go_mod(file_path: &Path, raw: &str) -> Vec<DepHygieneFinding> {
    let mut out = Vec::new();
    let mut in_require_block = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("require") && trimmed.ends_with('(') {
            in_require_block = true;
            continue;
        }
        if in_require_block && trimmed == ")" {
            in_require_block = false;
            continue;
        }

        let candidate = if in_require_block {
            trimmed
        } else {
            trimmed.strip_prefix("require ").unwrap_or_default().trim()
        };
        if candidate.is_empty() {
            continue;
        }

        let without_comment = candidate
            .split("//")
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        if without_comment.is_empty() {
            continue;
        }

        let tokens = without_comment.split_whitespace().collect::<Vec<_>>();
        if tokens.len() < 2 {
            continue;
        }
        let name = tokens[0];
        let version = tokens[1];

        if is_go_pseudo_version(version) {
            out.push(DepHygieneFinding::new(
                ManifestKind::GoMod,
                file_path,
                name,
                version,
                DepHygieneSeverity::Medium,
                "go.mod: pinned to a pseudo-version (commit hash); tag a release for an immutable pin",
            ));
        } else if version == "latest" || version == "v0.0.0" {
            out.push(DepHygieneFinding::new(
                ManifestKind::GoMod,
                file_path,
                name,
                version,
                DepHygieneSeverity::High,
                "go.mod: floating latest / v0.0.0 - supply chain unstable",
            ));
        }
    }

    out
}

fn canonical_directory(target: &Path) -> Result<PathBuf> {
    if !target.exists() {
        anyhow::bail!("dep-hygiene: target does not exist: {}", target.display());
    }
    let canonical = fs::canonicalize(target)
        .with_context(|| format!("dep-hygiene: failed to resolve {}", target.display()))?;
    if !canonical.is_dir() {
        anyhow::bail!(
            "dep-hygiene: target is not a directory: {}",
            canonical.display()
        );
    }
    Ok(canonical)
}

fn split_assignment(line: &str) -> Option<(&str, &str)> {
    let eq = line.find('=')?;
    if eq == 0 {
        return None;
    }
    Some((line[..eq].trim(), line[eq + 1..].trim()))
}

fn quoted_list_entry(line: &str) -> Option<&str> {
    let body = line.strip_prefix('"')?;
    let body = body.strip_suffix(',').unwrap_or(body).trim_end();
    body.strip_suffix('"')
}

fn clean_quoted_constraint(value: &str) -> String {
    let mut value = value.trim();
    value = value.strip_suffix(',').unwrap_or(value).trim_end();
    value = value.strip_prefix('"').unwrap_or(value);
    value = value.strip_suffix('"').unwrap_or(value);
    value.trim().to_string()
}

fn is_floor_only_number_range(value: &str) -> bool {
    if value.contains('<') || value.contains(',') {
        return false;
    }
    let Some(rest) = value.strip_prefix('>') else {
        return false;
    };
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();
    rest.chars().next().is_some_and(|ch| ch.is_ascii_digit())
}

fn is_floor_only_nonempty_range(value: &str) -> bool {
    if value.contains('<') || value.contains(',') || value.split_whitespace().count() != 1 {
        return false;
    }
    is_floor_only_number_range(value)
}

fn is_go_pseudo_version(version: &str) -> bool {
    let Some(rest) = version.strip_prefix("v0.0.0-") else {
        return false;
    };
    let Some((timestamp, hash)) = rest.split_once('-') else {
        return false;
    };
    timestamp.len() == 14
        && timestamp.chars().all(|ch| ch.is_ascii_digit())
        && hash.len() == 12
        && hash.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACKAGE_JSON: &str =
        include_str!("../../../tests/fixtures/dep-hygiene/node/package.json");
    const PYPROJECT_TOML: &str =
        include_str!("../../../tests/fixtures/dep-hygiene/python/pyproject.toml");
    const CARGO_TOML: &str = include_str!("../../../tests/fixtures/dep-hygiene/rust/Cargo.toml");
    const GO_MOD: &str = include_str!("../../../tests/fixtures/dep-hygiene/go/go.mod");

    #[test]
    fn analyzes_package_json_like_typescript_module() {
        let findings = analyze_manifest(
            ManifestKind::PackageJson,
            Path::new("/repo/package.json"),
            PACKAGE_JSON,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["lodash"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["express"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["axios"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["left-pad"].severity, DepHygieneSeverity::Low);
        assert_eq!(by_package["vitest"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("good-lib"));
        assert!(!by_package.contains_key("react"));
    }

    #[test]
    fn ignores_unparseable_package_json() {
        let findings = analyze_manifest(
            ManifestKind::PackageJson,
            Path::new("/repo/package.json"),
            "{ this is not json",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn analyzes_pyproject_toml_like_typescript_module() {
        let findings = analyze_manifest(
            ManifestKind::PyprojectToml,
            Path::new("/repo/pyproject.toml"),
            PYPROJECT_TOML,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["requests"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["flask"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["loguru"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["httpx"].severity, DepHygieneSeverity::Medium);
        assert!(!by_package.contains_key("django"));
        assert!(!by_package.contains_key("pydantic"));
        assert!(!by_package.contains_key("sqlalchemy"));
        assert!(!by_package.contains_key("python"));
    }

    #[test]
    fn analyzes_cargo_toml_like_typescript_module() {
        let findings = analyze_manifest(
            ManifestKind::CargoToml,
            Path::new("/repo/Cargo.toml"),
            CARGO_TOML,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["serde"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["tokio"].severity, DepHygieneSeverity::Medium);
        assert!(!by_package.contains_key("anyhow"));
        assert!(!by_package.contains_key("proptest"));
    }

    #[test]
    fn analyzes_go_mod_like_typescript_module() {
        let findings = analyze_manifest(ManifestKind::GoMod, Path::new("/repo/go.mod"), GO_MOD);
        let by_package = finding_map(&findings);

        assert!(!by_package.contains_key("github.com/example/safe"));
        assert_eq!(
            by_package["github.com/example/commit-pin"].severity,
            DepHygieneSeverity::Medium
        );
        assert_eq!(
            by_package["github.com/example/floating"].severity,
            DepHygieneSeverity::High
        );
        assert_eq!(
            by_package["github.com/example/zero"].severity,
            DepHygieneSeverity::High
        );
    }

    #[test]
    fn check_dependency_hygiene_reads_root_manifests() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("package.json"), PACKAGE_JSON).unwrap();
        fs::write(tmp.path().join("pyproject.toml"), PYPROJECT_TOML).unwrap();
        fs::write(tmp.path().join("Cargo.toml"), CARGO_TOML).unwrap();
        fs::write(tmp.path().join("go.mod"), GO_MOD).unwrap();

        let report = check_dependency_hygiene(tmp.path()).unwrap();

        assert_eq!(report.count, 14);
        assert!(report.output().contains("dep-hygiene: 14 risky specifiers"));
    }

    #[test]
    fn scanner_converts_report_to_core_findings() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();
        let scanner = DepHygieneScanner;
        let findings = scanner
            .scan(tmp.path(), &ScanCancellation::default())
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "dep-hygiene");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].file_path, "package.json");
        assert!(findings[0].message.contains("lodash@latest"));
    }

    #[test]
    fn missing_target_error_is_actionable() {
        let tmp = tempfile::tempdir().unwrap();
        let err = check_dependency_hygiene(&tmp.path().join("missing"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("dep-hygiene: target does not exist"));
    }

    fn finding_map(
        findings: &[DepHygieneFinding],
    ) -> std::collections::BTreeMap<String, DepHygieneFinding> {
        findings
            .iter()
            .map(|finding| (finding.package_name.clone(), finding.clone()))
            .collect()
    }

    /// Captured shape of a real `cargo audit --json` document, narrowed to
    /// the fields the parser reads. Two advisories with different CVSS
    /// inputs to exercise score parsing and the textual fallback.
    const CARGO_AUDIT_FIXTURE: &str = r#"{
      "database": { "advisory_count": 0 },
      "lockfile": { "dependency_count": 1 },
      "settings": {},
      "vulnerabilities": {
        "found": true,
        "count": 2,
        "list": [
          {
            "advisory": {
              "id": "RUSTSEC-2020-0071",
              "package": "time",
              "title": "Potential segfault in localtime_r invocations",
              "cvss": "6.2"
            },
            "versions": { "patched": [">=0.2.23"], "unaffected": [] },
            "affected": null,
            "package": {
              "name": "time",
              "version": "0.1.40",
              "source": "registry+https://github.com/rust-lang/crates.io-index"
            }
          },
          {
            "advisory": {
              "id": "RUSTSEC-2099-0001",
              "package": "fakecrate",
              "title": "Hypothetical critical RCE",
              "cvss": "CRITICAL/AV:N/AC:L/PR:N"
            },
            "package": {
              "name": "fakecrate",
              "version": "1.0.0",
              "source": "registry+https://github.com/rust-lang/crates.io-index"
            }
          }
        ]
      },
      "warnings": {}
    }"#;

    #[test]
    fn parse_cargo_audit_emits_finding_per_advisory() {
        let findings = parse_cargo_audit_output(CARGO_AUDIT_FIXTURE);
        assert_eq!(findings.len(), 2);
        let by_rule: std::collections::BTreeMap<_, _> = findings
            .iter()
            .map(|f| (f.rule_id.clone(), f.clone()))
            .collect();

        let time_finding = &by_rule["RUSTSEC-2020-0071"];
        assert_eq!(time_finding.tool, "cargo-audit");
        assert_eq!(time_finding.severity, Severity::Medium);
        assert_eq!(time_finding.file_path, "Cargo.lock");
        assert!(time_finding.message.contains("time@0.1.40"));
        assert!(time_finding.message.contains("Potential segfault"));

        let fake_finding = &by_rule["RUSTSEC-2099-0001"];
        assert_eq!(fake_finding.severity, Severity::Critical);
        assert!(fake_finding.message.contains("fakecrate@1.0.0"));
    }

    #[test]
    fn parse_cargo_audit_returns_empty_for_invalid_json() {
        assert!(parse_cargo_audit_output("{ this is not json").is_empty());
    }

    #[test]
    fn parse_cargo_audit_returns_empty_when_no_vulnerabilities_key() {
        assert!(parse_cargo_audit_output(r#"{"vulnerabilities":{"found":false}}"#).is_empty());
    }

    #[test]
    fn cargo_audit_severity_buckets_match_cvss_score() {
        assert_eq!(severity_from_cvss(Some("9.8")), Severity::Critical);
        assert_eq!(severity_from_cvss(Some("7.5")), Severity::High);
        assert_eq!(severity_from_cvss(Some("5.0")), Severity::Medium);
        assert_eq!(severity_from_cvss(Some("2.1")), Severity::Low);
        assert_eq!(severity_from_cvss(Some("0.0")), Severity::Unknown);
        assert_eq!(severity_from_cvss(None), Severity::Medium);
        // Vector-style CVSS strings fall back to keyword detection.
        assert_eq!(
            severity_from_cvss(Some("CVSS:3.1/AV:N/AC:L/PR:N/C:H/I:H/A:H")),
            Severity::High
        );
    }

    #[test]
    fn cargo_audit_scanner_no_lockfile_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        // No Cargo.lock written. The scanner must short-circuit cleanly,
        // even when cargo-audit is missing from PATH (binary_available
        // is never reached because the lockfile gate fires first).
        let scanner = CargoAuditScanner;
        let findings = scanner
            .scan(tmp.path(), &ScanCancellation::default())
            .unwrap();
        assert!(findings.is_empty());
    }
}
