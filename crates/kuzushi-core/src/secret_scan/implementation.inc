use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::findings::{Finding, Severity};
use crate::scan::{ScanCancellation, ScanEngine};

const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const DEFAULT_MAX_FINDINGS: usize = 1000;

const DEFAULT_EXCLUDE_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    "third_party",
    "third-party",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".cache",
    ".turbo",
    "coverage",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "target",
];

const DEFAULT_BINARY_EXTS: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svg", ".pdf", ".zip", ".gz",
    ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".exe", ".dll", ".so", ".dylib", ".bin",
    ".class", ".jar", ".war", ".pyc", ".pyo", ".o", ".a", ".node", ".wasm", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".avi", ".webm", ".lock",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretScanReport {
    pub target: String,
    pub findings: Vec<SecretScanFinding>,
    pub files_scanned: usize,
    pub files_skipped: usize,
}

impl SecretScanReport {
    pub fn output(&self) -> String {
        let severity_summary = if self.findings.is_empty() {
            "no secrets detected".to_string()
        } else {
            let mut counts = BTreeMap::<&'static str, usize>::new();
            for finding in &self.findings {
                *counts.entry(finding.severity.as_str()).or_default() += 1;
            }
            counts
                .into_iter()
                .map(|(severity, count)| format!("{count} {}", severity.to_ascii_lowercase()))
                .collect::<Vec<_>>()
                .join(", ")
        };

        let mut lines = vec![
            format!(
                "secret-scan: {} finding{} ({severity_summary})",
                self.findings.len(),
                if self.findings.len() == 1 { "" } else { "s" }
            ),
            format!("  Files scanned: {}", self.files_scanned),
            format!("  Files skipped: {}", self.files_skipped),
            format!("  Target:        {}", self.target),
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
                "findings": self.findings,
                "filesScanned": self.files_scanned,
                "filesSkipped": self.files_skipped,
                "target": self.target,
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretScanFinding {
    pub task_id: String,
    pub fingerprint: String,
    pub rule_id: String,
    pub file_path: String,
    pub start_line: u32,
    pub severity: SecretSeverity,
    pub message: String,
    pub evidence: String,
    pub scanner_confidence: String,
    pub subcategory: Vec<String>,
    pub likelihood: String,
    pub impact: String,
    pub cwe: Vec<String>,
    pub score: u32,
}

impl SecretScanFinding {
    fn to_core_finding(&self) -> Finding {
        let mut finding = Finding::new_tool(
            "secret-scan",
            self.rule_id.clone(),
            self.file_path.clone(),
            self.start_line,
            None,
            self.severity.to_core_severity(),
            format!("{}\n{}", self.message, self.evidence),
        );
        finding.fingerprint = self.fingerprint.clone();
        finding.title = self.message.clone();
        finding
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretSeverity {
    Error,
    Warning,
    Info,
}

impl SecretSeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warning => "WARNING",
            Self::Info => "INFO",
        }
    }

    fn to_core_severity(self) -> Severity {
        match self {
            Self::Error => Severity::High,
            Self::Warning => Severity::Medium,
            Self::Info => Severity::Info,
        }
    }
}

impl TryFrom<&str> for SecretSeverity {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "ERROR" => Ok(Self::Error),
            "WARNING" => Ok(Self::Warning),
            "INFO" => Ok(Self::Info),
            other => anyhow::bail!("unknown secret-scan severity {other:?}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecretScanOptions {
    pub max_file_bytes: u64,
    pub exclude_dirs: BTreeSet<String>,
    pub binary_exts: BTreeSet<String>,
    pub max_findings: usize,
    pub severity: Option<BTreeSet<SecretSeverity>>,
}

impl Default for SecretScanOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            exclude_dirs: DEFAULT_EXCLUDE_DIRS
                .iter()
                .map(|entry| (*entry).to_string())
                .collect(),
            binary_exts: DEFAULT_BINARY_EXTS
                .iter()
                .map(|entry| (*entry).to_string())
                .collect(),
            max_findings: DEFAULT_MAX_FINDINGS,
            severity: None,
        }
    }
}

impl SecretScanOptions {
    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let mut options = Self::default();

        if let Some(value) = input.get("maxFileBytes").and_then(Value::as_u64) {
            options.max_file_bytes = value.max(1024);
        }

        if let Some(value) = input.get("maxFindings").and_then(Value::as_u64) {
            options.max_findings = value.max(1).min(10_000) as usize;
        }

        if let Some(values) = input.get("excludeDirs").and_then(Value::as_array) {
            for value in values.iter().filter_map(Value::as_str) {
                if !value.trim().is_empty() {
                    options.exclude_dirs.insert(value.trim().to_string());
                }
            }
        }

        if let Some(values) = input.get("binaryExts").and_then(Value::as_array) {
            for value in values.iter().filter_map(Value::as_str) {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let ext = if trimmed.starts_with('.') {
                    trimmed.to_ascii_lowercase()
                } else {
                    format!(".{}", trimmed.to_ascii_lowercase())
                };
                options.binary_exts.insert(ext);
            }
        }

        if let Some(values) = input.get("severity").and_then(Value::as_array) {
            let mut severities = BTreeSet::new();
            for value in values.iter().filter_map(Value::as_str) {
                severities.insert(SecretSeverity::try_from(value)?);
            }
            options.severity = Some(severities);
        }

        Ok(options)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SecretScanScanner;

impl ScanEngine for SecretScanScanner {
    fn id(&self) -> &'static str {
        "secret-scan"
    }

    fn scan(&self, target: &Path, cancellation: &ScanCancellation) -> Result<Vec<Finding>> {
        let report = scan_for_secrets(target, &SecretScanOptions::default(), cancellation)?;
        Ok(report
            .findings
            .iter()
            .map(SecretScanFinding::to_core_finding)
            .collect())
    }
}

#[derive(Debug, Clone, Copy)]
struct Detector {
    id: &'static str,
    name: &'static str,
    severity: SecretSeverity,
    entropy_threshold: Option<f64>,
    cwe: &'static str,
    description: &'static str,
}

#[derive(Debug, Clone)]
struct SecretHit {
    detector: Detector,
    matched: String,
    captured_secret: String,
    index: usize,
}

pub fn scan_for_secrets(
    target: &Path,
    options: &SecretScanOptions,
    cancellation: &ScanCancellation,
) -> Result<SecretScanReport> {
    let root = canonical_directory(target)?;
    let mut files = Vec::new();
    collect_files(&root, options, &mut files)?;
    let mut findings = Vec::new();
    let mut files_scanned = 0usize;
    let mut files_skipped = 0usize;

    'outer: for file_path in files {
        if cancellation.is_cancelled() {
            anyhow::bail!("secret-scan scan cancelled");
        }

        if is_binary_extension(&file_path, &options.binary_exts) {
            files_skipped += 1;
            continue;
        }

        let Ok(metadata) = fs::metadata(&file_path) else {
            continue;
        };
        if metadata.len() > options.max_file_bytes {
            files_skipped += 1;
            continue;
        }

        let Ok(bytes) = fs::read(&file_path) else {
            continue;
        };
        if is_likely_binary(&bytes) {
            files_skipped += 1;
            continue;
        }
        files_scanned += 1;

        let text = String::from_utf8_lossy(&bytes);
        let rel_path = file_path
            .strip_prefix(&root)
            .unwrap_or(&file_path)
            .display()
            .to_string();
        for hit in detect_secrets_in_text(&text) {
            let location = locate_match(&text, hit.index);
            let fingerprint = fingerprint_for(
                &root,
                hit.detector.id,
                &rel_path,
                location.line,
                &hit.matched,
            );
            let redacted = redact_secret(&hit.captured_secret);
            let evidence_line = location
                .line_text
                .replacen(&hit.captured_secret, &redacted, 1)
                .trim()
                .to_string();
            let severity = hit.detector.severity;
            findings.push(SecretScanFinding {
                task_id: "secret-scan".to_string(),
                fingerprint,
                rule_id: format!("secret-scan/{}", hit.detector.id),
                file_path: rel_path.clone(),
                start_line: location.line,
                severity,
                message: format!("{}: {}", hit.detector.name, hit.detector.description),
                evidence: format!("{}:{}: {}", rel_path, location.line, evidence_line),
                scanner_confidence: if hit.detector.entropy_threshold.is_some() {
                    "MEDIUM".to_string()
                } else {
                    "HIGH".to_string()
                },
                subcategory: vec!["secret".to_string()],
                likelihood: if severity == SecretSeverity::Error {
                    "HIGH".to_string()
                } else {
                    "MEDIUM".to_string()
                },
                impact: if severity == SecretSeverity::Error {
                    "HIGH".to_string()
                } else {
                    "MEDIUM".to_string()
                },
                cwe: vec![hit.detector.cwe.to_string()],
                score: match severity {
                    SecretSeverity::Error => 30,
                    SecretSeverity::Warning => 20,
                    SecretSeverity::Info => 10,
                },
            });

            if findings.len() >= options.max_findings {
                break 'outer;
            }
        }
    }

    if let Some(filter) = &options.severity {
        findings.retain(|finding| filter.contains(&finding.severity));
    }

    Ok(SecretScanReport {
        target: root.display().to_string(),
        findings,
        files_scanned,
        files_skipped,
    })
}

fn canonical_directory(target: &Path) -> Result<PathBuf> {
    let path = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir()
            .context("Could not resolve current directory")?
            .join(target)
    };
    if !path.exists() {
        anyhow::bail!("secret-scan: target is not a directory: {}", path.display());
    }
    let canonical = fs::canonicalize(&path)
        .with_context(|| format!("secret-scan: failed to resolve {}", path.display()))?;
    if !canonical.is_dir() {
        anyhow::bail!(
            "secret-scan: target is not a directory: {}",
            canonical.display()
        );
    }
    Ok(canonical)
}

fn collect_files(dir: &Path, options: &SecretScanOptions, out: &mut Vec<PathBuf>) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let file_name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            if options.exclude_dirs.contains(file_name.as_str()) {
                continue;
            }
            collect_files(&path, options, out)?;
        } else if file_type.is_file() {
            out.push(path);
        }
    }

    Ok(())
}

fn detect_secrets_in_text(text: &str) -> Vec<SecretHit> {
    let mut hits = Vec::new();
    detect_token_shapes(text, &mut hits);
    detect_assignments(
        text,
        &[
            "aws_secret_access_key",
            "aws-secret-access-key",
            "aws_secret_key",
            "aws-secret-key",
            "aws_secret",
            "aws-secret",
        ],
        aws_secret_key_detector(),
        AssignmentMode::OptionalQuote,
        is_base64_secret_char,
        &mut hits,
    );
    detect_assignments(
        text,
        &[
            "password",
            "passwd",
            "api_key",
            "api-key",
            "secret",
            "secret_key",
            "secret-key",
            "access_token",
            "access-token",
            "auth_token",
            "auth-token",
        ],
        generic_secret_assignment_detector(),
        AssignmentMode::RequiredQuote,
        is_generic_secret_char,
        &mut hits,
    );
    detect_pem_private_keys(text, &mut hits);
    hits.sort_by_key(|hit| hit.index);
    hits
}

fn detect_token_shapes(text: &str, hits: &mut Vec<SecretHit>) {
    let bytes = text.as_bytes();
    let mut start = None;

    for (index, byte) in bytes.iter().copied().enumerate() {
        if is_token_char(byte) {
            if start.is_none() {
                start = Some(index);
            }
            continue;
        }

        if let Some(token_start) = start.take() {
            classify_token(text, token_start, index, hits);
        }
    }

    if let Some(token_start) = start {
        classify_token(text, token_start, text.len(), hits);
    }
}

fn classify_token(text: &str, start: usize, end: usize, hits: &mut Vec<SecretHit>) {
    let token = &text[start..end];
    if token.len() == 20
        && [
            "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "ASCA",
        ]
        .iter()
        .any(|prefix| token.starts_with(prefix))
        && token
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        push_hit(hits, aws_access_key_detector(), token, token, start);
        return;
    }

    if matches_prefixed_token(
        token,
        &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        36,
        is_alnum,
    ) {
        push_hit(hits, github_pat_detector(), token, token, start);
        return;
    }

    if matches_prefixed_token(
        token,
        &["xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-"],
        10,
        is_alnum_hyphen,
    ) {
        push_hit(hits, slack_token_detector(), token, token, start);
        return;
    }

    if matches_prefixed_token(token, &["sk_live_", "pk_live_", "rk_live_"], 24, is_alnum) {
        push_hit(hits, stripe_live_key_detector(), token, token, start);
        return;
    }

    if matches_prefixed_token(token, &["sk_test_", "pk_test_", "rk_test_"], 24, is_alnum) {
        push_hit(hits, stripe_test_key_detector(), token, token, start);
        return;
    }

    if token.len() == 39
        && token.starts_with("AIza")
        && token[4..].bytes().all(is_alnum_underscore_hyphen)
    {
        push_hit(hits, google_api_key_detector(), token, token, start);
        return;
    }

    if matches_prefixed_token(token, &["sk-ant-"], 20, is_alnum_underscore_hyphen) {
        push_hit(hits, anthropic_api_key_detector(), token, token, start);
        return;
    }

    if token.starts_with("sk-") {
        let rest = token
            .strip_prefix("sk-proj-")
            .or_else(|| token.strip_prefix("sk-"));
        if let Some(rest) = rest {
            if rest.len() >= 32
                && rest.bytes().all(is_alnum_underscore_hyphen)
                && shannon_entropy(rest) >= 3.5
            {
                push_hit(hits, openai_api_key_detector(), token, token, start);
                return;
            }
        }
    }

    if looks_like_jwt(token) {
        push_hit(hits, jwt_token_detector(), token, token, start);
    }
}

fn detect_pem_private_keys(text: &str, hits: &mut Vec<SecretHit>) {
    let detector = pem_private_key_detector();
    let mut search_from = 0usize;
    while let Some(relative_index) = text[search_from..].find("-----BEGIN ") {
        let index = search_from + relative_index;
        let Some(end_relative) = text[index..].find("PRIVATE KEY-----") else {
            break;
        };
        let end = index + end_relative + "PRIVATE KEY-----".len();
        let matched = &text[index..end];
        if [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY-----",
        ]
        .contains(&matched)
        {
            push_hit(hits, detector, matched, matched, index);
        }
        search_from = end;
    }
}

#[derive(Debug, Clone, Copy)]
enum AssignmentMode {
    OptionalQuote,
    RequiredQuote,
}

fn detect_assignments(
    text: &str,
    keys: &[&str],
    detector: Detector,
    mode: AssignmentMode,
    value_char: fn(u8) -> bool,
    hits: &mut Vec<SecretHit>,
) {
    let lower = text.to_ascii_lowercase();
    let bytes = text.as_bytes();
    let lower_bytes = lower.as_bytes();
    for index in 0..bytes.len() {
        if index > 0 && is_identifier_byte(bytes[index - 1]) {
            continue;
        }

        for key in keys {
            let key_bytes = key.as_bytes();
            if !lower_bytes[index..].starts_with(key_bytes) {
                continue;
            }
            let mut cursor = index + key_bytes.len();
            if cursor < bytes.len() && is_identifier_byte(bytes[cursor]) {
                continue;
            }
            cursor = skip_ascii_whitespace(bytes, cursor);
            if cursor >= bytes.len() || (bytes[cursor] != b':' && bytes[cursor] != b'=') {
                continue;
            }
            cursor += 1;
            cursor = skip_ascii_whitespace(bytes, cursor);

            let quote = if cursor < bytes.len() && (bytes[cursor] == b'"' || bytes[cursor] == b'\'')
            {
                let quote = bytes[cursor];
                cursor += 1;
                Some(quote)
            } else {
                None
            };
            if matches!(mode, AssignmentMode::RequiredQuote) && quote.is_none() {
                continue;
            }

            let value_start = cursor;
            while cursor < bytes.len() && value_char(bytes[cursor]) {
                cursor += 1;
            }
            if cursor - value_start < 16 {
                continue;
            }
            if let Some(quote) = quote {
                if cursor >= bytes.len() || bytes[cursor] != quote {
                    continue;
                }
            }

            let value = &text[value_start..cursor];
            if let Some(threshold) = detector.entropy_threshold {
                if shannon_entropy(value) < threshold {
                    continue;
                }
            }
            let matched = &text[index..cursor];
            push_hit(hits, detector, matched, value, index);
        }
    }
}

fn push_hit(
    hits: &mut Vec<SecretHit>,
    detector: Detector,
    matched: &str,
    captured_secret: &str,
    index: usize,
) {
    hits.push(SecretHit {
        detector,
        matched: matched.to_string(),
        captured_secret: captured_secret.to_string(),
        index,
    });
}

fn matches_prefixed_token(
    token: &str,
    prefixes: &[&str],
    min_rest: usize,
    rest_char: fn(u8) -> bool,
) -> bool {
    prefixes.iter().any(|prefix| {
        token
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.len() >= min_rest && rest.bytes().all(rest_char))
    })
}

fn looks_like_jwt(token: &str) -> bool {
    let parts = token.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts[0].starts_with("eyJ")
        && parts[0].len() >= 11
        && parts[1].len() >= 8
        && parts[2].len() >= 4
        && parts
            .iter()
            .all(|part| part.bytes().all(is_alnum_underscore_hyphen))
}

fn is_token_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'/' | b'+' | b'.')
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn is_alnum(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

fn is_alnum_hyphen(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

fn is_alnum_underscore_hyphen(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn is_base64_secret_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'+' | b'=')
}

fn is_generic_secret_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!@#$%^&*_+/=-".contains(&byte)
}

fn skip_ascii_whitespace(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    cursor
}

fn is_binary_extension(path: &Path, binary_exts: &BTreeSet<String>) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{}", ext.to_ascii_lowercase()))
        .is_some_and(|ext| binary_exts.contains(ext.as_str()))
}

fn is_likely_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(4096).any(|byte| *byte == 0)
}

fn locate_match(text: &str, index: usize) -> MatchLocation {
    let mut line = 1u32;
    let mut line_start = 0usize;
    for (cursor, byte) in text.as_bytes().iter().copied().enumerate().take(index) {
        if byte == b'\n' {
            line += 1;
            line_start = cursor + 1;
        }
    }
    let line_end = text[line_start..]
        .find('\n')
        .map(|offset| line_start + offset)
        .unwrap_or(text.len());
    MatchLocation {
        line,
        line_text: text[line_start..line_end].to_string(),
    }
}

#[derive(Debug, Clone)]
struct MatchLocation {
    line: u32,
    line_text: String,
}

fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    let mut counts = BTreeMap::<char, usize>::new();
    for ch in input.chars() {
        *counts.entry(ch).or_default() += 1;
    }

    let len = input.chars().count() as f64;
    counts
        .values()
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn redact_secret(secret: &str) -> String {
    let chars = secret.chars().collect::<Vec<_>>();
    if chars.len() <= 4 {
        return "***".to_string();
    }
    let prefix = chars.iter().take(4).collect::<String>();
    format!("{}{}", prefix, "*".repeat((chars.len() - 4).min(8)))
}

fn fingerprint_for(
    repo_root: &Path,
    detector_id: &str,
    file_path: &str,
    line: u32,
    matched: &str,
) -> String {
    let repo_name = repo_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let input = format!("{repo_name}|secret-scan|{detector_id}|{file_path}|{line}|{matched}");
    format!(
        "secret-scan:{detector_id}:{:016x}",
        fnv1a64(input.as_bytes())
    )
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn aws_access_key_detector() -> Detector {
    Detector {
        id: "aws-access-key",
        name: "AWS Access Key ID",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "AWS access key ID committed to source.",
    }
}

fn aws_secret_key_detector() -> Detector {
    Detector {
        id: "aws-secret-key",
        name: "AWS Secret Access Key",
        severity: SecretSeverity::Error,
        entropy_threshold: Some(4.0),
        cwe: "CWE-798",
        description: "AWS secret access key candidate (40-char base64).",
    }
}

fn github_pat_detector() -> Detector {
    Detector {
        id: "github-pat",
        name: "GitHub Personal Access Token",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "GitHub fine-grained or classic personal access token.",
    }
}

fn slack_token_detector() -> Detector {
    Detector {
        id: "slack-token",
        name: "Slack Token",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Slack bot/user/app token.",
    }
}

fn stripe_live_key_detector() -> Detector {
    Detector {
        id: "stripe-live-key",
        name: "Stripe Live Key",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Stripe live API key (production credentials).",
    }
}

fn stripe_test_key_detector() -> Detector {
    Detector {
        id: "stripe-test-key",
        name: "Stripe Test Key",
        severity: SecretSeverity::Warning,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Stripe test API key - still a leak even if low-impact.",
    }
}

fn google_api_key_detector() -> Detector {
    Detector {
        id: "google-api-key",
        name: "Google API Key",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Google Cloud / Maps / Firebase API key.",
    }
}

fn anthropic_api_key_detector() -> Detector {
    Detector {
        id: "anthropic-api-key",
        name: "Anthropic API Key",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "Anthropic API key.",
    }
}

fn openai_api_key_detector() -> Detector {
    Detector {
        id: "openai-api-key",
        name: "OpenAI API Key",
        severity: SecretSeverity::Error,
        entropy_threshold: Some(3.5),
        cwe: "CWE-798",
        description: "OpenAI-style API key (sk-... or sk-proj-...).",
    }
}

fn jwt_token_detector() -> Detector {
    Detector {
        id: "jwt-token",
        name: "JSON Web Token",
        severity: SecretSeverity::Warning,
        entropy_threshold: None,
        cwe: "CWE-522",
        description: "JWT-shaped token; verify it isn't a long-lived credential.",
    }
}

fn pem_private_key_detector() -> Detector {
    Detector {
        id: "pem-private-key",
        name: "PEM Private Key",
        severity: SecretSeverity::Error,
        entropy_threshold: None,
        cwe: "CWE-798",
        description: "PEM-encoded private key block.",
    }
}

fn generic_secret_assignment_detector() -> Detector {
    Detector {
        id: "generic-secret-assignment",
        name: "Generic Secret Assignment",
        severity: SecretSeverity::Warning,
        entropy_threshold: Some(3.5),
        cwe: "CWE-798",
        description: "Likely-credential assignment with a high-entropy value.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_curated_secret_shapes_and_redacts_evidence() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/config.env"),
            [
                "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
                "aws_secret_access_key = \"abcdEFGH1234567890abcdEFGH1234567890ABCD\"",
                "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ",
                "password = \"aB3$eF6!hI9@kL2%mN5^\"",
            ]
            .join("\n"),
        )
        .unwrap();
        fs::create_dir(temp.path().join("node_modules")).unwrap();
        fs::write(
            temp.path().join("node_modules/ignored.env"),
            "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGH",
        )
        .unwrap();

        let report = scan_for_secrets(
            temp.path(),
            &SecretScanOptions::default(),
            &ScanCancellation::default(),
        )
        .unwrap();

        let rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(report.files_scanned, 1);
        assert!(rule_ids.contains("secret-scan/aws-access-key"));
        assert!(rule_ids.contains("secret-scan/aws-secret-key"));
        assert!(rule_ids.contains("secret-scan/github-pat"));
        assert!(rule_ids.contains("secret-scan/generic-secret-assignment"));
        assert!(report
            .findings
            .iter()
            .all(|finding| !finding.evidence.contains("abcdEFGH1234567890")));
    }

    #[test]
    fn applies_size_binary_and_severity_filters() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("keys.txt"),
            [
                "STRIPE_TEST=sk_test_abcdefghijklmnopqrstuvwxyz",
                "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
            ]
            .join("\n"),
        )
        .unwrap();
        fs::write(temp.path().join("image.bin"), b"\0secret").unwrap();

        let mut options = SecretScanOptions::default();
        options.severity = Some(BTreeSet::from([SecretSeverity::Warning]));
        let report = scan_for_secrets(temp.path(), &options, &ScanCancellation::default()).unwrap();

        assert_eq!(report.files_skipped, 1);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "secret-scan/stripe-test-key");
    }

    #[test]
    fn tool_input_options_coerce_limits_sets_and_severities() {
        let options = SecretScanOptions::from_tool_input(&json!({
            "maxFileBytes": 1,
            "maxFindings": 50_000,
            "excludeDirs": ["build", "  ", "vendor"],
            "binaryExts": ["pem", ".sqlite"],
            "severity": ["ERROR", "WARNING"]
        }))
        .unwrap();

        assert_eq!(options.max_file_bytes, 1024);
        assert_eq!(options.max_findings, 10_000);
        assert!(options.exclude_dirs.contains("build"));
        assert!(options.exclude_dirs.contains("vendor"));
        assert!(options.binary_exts.contains(".pem"));
        assert!(options.binary_exts.contains(".sqlite"));
        assert_eq!(
            options.severity,
            Some(BTreeSet::from([
                SecretSeverity::Error,
                SecretSeverity::Warning
            ]))
        );

        let err = SecretScanOptions::from_tool_input(&json!({"severity": ["BAD"]})).unwrap_err();
        assert!(err.to_string().contains("unknown secret-scan severity"));
    }

    #[test]
    fn secret_severity_and_jwt_shape_helpers_cover_edges() {
        assert_eq!(
            SecretSeverity::try_from("ERROR").unwrap(),
            SecretSeverity::Error
        );
        assert_eq!(
            SecretSeverity::try_from("WARNING").unwrap(),
            SecretSeverity::Warning
        );
        assert_eq!(
            SecretSeverity::try_from("INFO").unwrap(),
            SecretSeverity::Info
        );
        assert!(SecretSeverity::try_from("LOW").is_err());

        assert!(looks_like_jwt(
            "eyJhbGciOiJIUzI1.abcdefghijklmnopqrstuvwxyz.abcdef"
        ));
        assert!(!looks_like_jwt("not.a.jwt"));
        assert!(!looks_like_jwt("eyJshort.payload.sig"));
    }

    #[test]
    fn missing_target_failure_is_actionable() {
        let temp = tempfile::tempdir().unwrap();
        let err = scan_for_secrets(
            &temp.path().join("missing"),
            &SecretScanOptions::default(),
            &ScanCancellation::default(),
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("secret-scan: target is not a directory"));
    }

    #[test]
    fn scanner_converts_results_to_core_findings() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("keys.txt"),
            "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGH",
        )
        .unwrap();

        let findings = SecretScanScanner
            .scan(temp.path(), &ScanCancellation::default())
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "secret-scan");
        assert_eq!(findings[0].rule_id, "secret-scan/openai-api-key");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn cancellation_stops_native_scan() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("keys.txt"),
            "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF",
        )
        .unwrap();
        let cancellation = ScanCancellation::default();
        cancellation.cancel();

        let err = SecretScanScanner
            .scan(temp.path(), &cancellation)
            .unwrap_err()
            .to_string();

        assert!(err.contains("cancelled"));
    }
}
