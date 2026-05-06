use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}

impl Severity {
    pub fn from_semgrep(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "ERROR" => Self::High,
            "WARNING" => Self::Medium,
            "INFO" => Self::Low,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
            Self::Unknown => "unknown",
        }
    }
}

impl TryFrom<&str> for Severity {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            "unknown" => Ok(Self::Unknown),
            other => anyhow::bail!("unknown severity {other:?}"),
        }
    }
}

/// Discovery channel a finding came from. Mirrors RoboDuck's `VulnSource`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum VulnSource {
    /// Output from a SARIF-emitting scanner (semgrep, codeql, …).
    Sarif,
    /// LLM-driven per-file analysis (systems-hunt, carlini-threat-hunt).
    Ainalysis,
    /// LLM-driven chunked whole-codebase pass (full-mode-multi).
    AinalysisMulti,
    /// Diff-scoped scan (`--since <ref>`, variant-ndiff).
    DiffAnalyzer,
    /// Reserved — Infer integration not yet wired.
    Infer,
    /// Reserved — fuzzing channel not yet wired.
    Fuzzing,
}

impl VulnSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sarif => "sarif",
            Self::Ainalysis => "ainalysis",
            Self::AinalysisMulti => "ainalysis-multi",
            Self::DiffAnalyzer => "diff-analyzer",
            Self::Infer => "infer",
            Self::Fuzzing => "fuzzing",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sarif" => Some(Self::Sarif),
            "ainalysis" => Some(Self::Ainalysis),
            "ainalysis-multi" | "ainalysis_multi" => Some(Self::AinalysisMulti),
            "diff-analyzer" | "diff_analyzer" => Some(Self::DiffAnalyzer),
            "infer" => Some(Self::Infer),
            "fuzzing" => Some(Self::Fuzzing),
            _ => None,
        }
    }

    /// Heuristic mapping from existing tool ids to a default channel.
    /// Used so existing modules don't have to be retrofitted in this
    /// phase — they keep emitting `tool="systems-hunt"` and we infer
    /// the source.
    pub fn from_tool(tool: &str) -> Self {
        match tool {
            "semgrep" | "codeql" | "secret-scan" | "iac-scan" | "dep-hygiene" => Self::Sarif,
            "systems-hunt" | "carlini-threat-hunt" => Self::Ainalysis,
            "full-mode-multi" => Self::AinalysisMulti,
            "variant-ndiff" => Self::DiffAnalyzer,
            "infer" => Self::Infer,
            _ => Self::Ainalysis,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub id: Option<i64>,
    pub scan_id: Option<String>,
    pub fingerprint: String,
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: Option<u32>,
    pub message: String,
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_fingerprint: Option<String>,
    pub triage: Option<TriageOutcome>,
    pub created_at: String,
    /// Discovery channel — populated automatically from `tool` if not
    /// set explicitly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vuln_source: Option<VulnSource>,
    /// Cross-channel collision key. Two findings with the same
    /// `dedup_key` in the same scan are treated as the same underlying
    /// vulnerability — the higher-severity one wins, the tool list
    /// merges. Computed from `(file, line/16, normalized_cwe)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_key: Option<String>,
}

/// 16-line bucket size — picked so a function-sized vulnerability
/// reported across two channels at lines 42 and 47 collides, but
/// findings 30 lines apart in the same file don't.
const DEDUP_LINE_BUCKET: u32 = 16;

/// Compute a cross-channel dedup key.
///
/// `(normalised_file, line / 16, normalised_cwe)`.
///
/// CWE comparison is normalised via `normalize_cwe` so `CWE-787`,
/// `cwe-787`, `CWE_787`, and `787` collapse to the same string.
pub fn compute_dedup_key(file: &str, line: u32, cwe: Option<&str>) -> String {
    let bucket = line / DEDUP_LINE_BUCKET;
    let normalised_file = file.trim_start_matches("./");
    let cwe_part = cwe.map(normalize_cwe).unwrap_or_else(|| "*".to_string());
    format!("{normalised_file}:{bucket}:{cwe_part}")
}

/// Lower-cased CWE id with the leading `cwe-` prefix removed; non-digit
/// junk is stripped. So `CWE-787`, `cwe-787`, `CWE_787`, ` 787 ` all
/// normalise to `787`.
pub fn normalize_cwe(value: &str) -> String {
    let lower = value.trim().to_ascii_lowercase();
    let stripped = lower
        .trim_start_matches("cwe-")
        .trim_start_matches("cwe_")
        .trim_start_matches("cwe");
    stripped
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect::<String>()
}

/// Best-effort CWE extraction from a finding's message + rule_id +
/// title. Looks for `CWE-\d+`. Returns the first hit only.
pub fn extract_cwe(rule_id: &str, title: &str, message: &str) -> Option<String> {
    for source in [rule_id, title, message] {
        let lower = source.to_ascii_lowercase();
        let mut idx = 0;
        while let Some(pos) = lower[idx..].find("cwe-") {
            let start = idx + pos + 4;
            let digits: String = lower[start..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if !digits.is_empty() {
                return Some(format!("CWE-{digits}"));
            }
            idx = start;
        }
    }
    None
}

impl Finding {
    pub fn new_tool(
        tool: impl Into<String>,
        rule_id: impl Into<String>,
        file_path: impl Into<String>,
        start_line: u32,
        end_line: Option<u32>,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        let tool = tool.into();
        let rule_id = rule_id.into();
        let file_path = file_path.into();
        let message = message.into();
        let fingerprint = fingerprint_parts(&rule_id, &file_path, start_line, &message);
        let title = message
            .lines()
            .next()
            .unwrap_or(&rule_id)
            .trim()
            .to_string();

        let cwe = extract_cwe(&rule_id, &title, &message);
        // Only auto-populate dedup_key when we extracted a real CWE.
        // Without CWE the bucket would collide too aggressively across
        // unrelated findings — fingerprint dedup is the right level
        // there, and callers that want stronger collisions can attach a
        // dedup_key explicitly with `with_dedup_key`.
        let dedup_key = cwe
            .as_deref()
            .map(|c| compute_dedup_key(&file_path, start_line, Some(c)));
        let vuln_source = Some(VulnSource::from_tool(&tool));

        Self {
            id: None,
            scan_id: None,
            fingerprint,
            rule_id,
            title,
            severity,
            file_path,
            start_line,
            end_line,
            message,
            tool,
            actor_fingerprint: None,
            triage: None,
            created_at: now_isoish(),
            vuln_source,
            dedup_key,
        }
    }

    /// Override the auto-detected vuln source (e.g. when reusing
    /// `new_tool` for a finding that should belong to a non-default
    /// channel).
    pub fn with_vuln_source(mut self, source: VulnSource) -> Self {
        self.vuln_source = Some(source);
        self
    }

    /// Override the auto-computed dedup key.
    pub fn with_dedup_key(mut self, key: impl Into<String>) -> Self {
        self.dedup_key = Some(key.into());
        self
    }

    pub fn new_semgrep(
        rule_id: impl Into<String>,
        file_path: impl Into<String>,
        start_line: u32,
        end_line: Option<u32>,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Self::new_tool(
            "semgrep", rule_id, file_path, start_line, end_line, severity, message,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TriageOutcome {
    pub verdict: TriageVerdict,
    pub confidence: f32,
    pub rationale: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PatchStatus {
    ApplyFailed,
    BuildFailed,
    StillVulnerable,
    TestsFailed,
    Sound,
    Verified,
    Unknown,
}

impl PatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApplyFailed => "APPLY_FAILED",
            Self::BuildFailed => "BUILD_FAILED",
            Self::StillVulnerable => "STILL_VULNERABLE",
            Self::TestsFailed => "TESTS_FAILED",
            Self::Sound => "SOUND",
            Self::Verified => "VERIFIED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

impl TryFrom<&str> for PatchStatus {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "APPLY_FAILED" => Ok(Self::ApplyFailed),
            "BUILD_FAILED" => Ok(Self::BuildFailed),
            "STILL_VULNERABLE" => Ok(Self::StillVulnerable),
            "TESTS_FAILED" => Ok(Self::TestsFailed),
            "SOUND" => Ok(Self::Sound),
            "VERIFIED" => Ok(Self::Verified),
            "UNKNOWN" => Ok(Self::Unknown),
            other => anyhow::bail!("unknown patch status {other:?}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PatchAttempt {
    pub attempt: usize,
    pub diff: String,
    pub status: PatchStatus,
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PatchResult {
    pub patch_run_id: String,
    pub fingerprint: String,
    pub repo: String,
    pub diff: Option<String>,
    pub status: PatchStatus,
    pub iterations: usize,
    pub build_command: Option<String>,
    pub test_command: Option<String>,
    pub worktree_path: Option<String>,
    pub cost_usd: Option<f64>,
    pub validator_log: Option<String>,
    pub history: Vec<PatchAttempt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TriageVerdict {
    TruePositive,
    FalsePositive,
    NeedsReview,
    ByDesign,
}

impl TriageVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TruePositive => "true_positive",
            Self::FalsePositive => "false_positive",
            Self::NeedsReview => "needs_review",
            Self::ByDesign => "by_design",
        }
    }
}

impl TryFrom<&str> for TriageVerdict {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "true_positive" => Ok(Self::TruePositive),
            "false_positive" => Ok(Self::FalsePositive),
            "needs_review" => Ok(Self::NeedsReview),
            "by_design" => Ok(Self::ByDesign),
            other => anyhow::bail!("unknown triage verdict {other:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingVerdictFilter {
    TruePositive,
    FalsePositive,
    NeedsReview,
    ByDesign,
}

impl FindingVerdictFilter {
    pub fn from_input(value: &str) -> Result<Self> {
        match value.trim() {
            "tp" | "true_positive" | "vulnerable" => Ok(Self::TruePositive),
            "fp" | "false_positive" | "safe" => Ok(Self::FalsePositive),
            "needs_review" | "review" | "detected" => Ok(Self::NeedsReview),
            "by_design" | "by-design" => Ok(Self::ByDesign),
            other => anyhow::bail!("unknown findings:list verdict filter {other:?}"),
        }
    }

    fn from_finding(finding: &Finding) -> Self {
        match finding.triage.as_ref().map(|triage| triage.verdict) {
            Some(TriageVerdict::TruePositive) => Self::TruePositive,
            Some(TriageVerdict::FalsePositive) => Self::FalsePositive,
            Some(TriageVerdict::NeedsReview) | None => Self::NeedsReview,
            Some(TriageVerdict::ByDesign) => Self::ByDesign,
        }
    }

    fn as_legacy_str(self) -> &'static str {
        match self {
            Self::TruePositive => "tp",
            Self::FalsePositive => "fp",
            Self::NeedsReview => "needs_review",
            Self::ByDesign => "by_design",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingListFilter {
    pub severity: Vec<Severity>,
    pub verdict: Vec<FindingVerdictFilter>,
    pub name: Option<String>,
    pub file_path: Option<String>,
    /// Filter by discovery channel(s). Empty = no filter.
    pub vuln_source: Vec<VulnSource>,
    pub limit: usize,
}

impl Default for FindingListFilter {
    fn default() -> Self {
        Self {
            severity: Vec::new(),
            verdict: Vec::new(),
            name: None,
            file_path: None,
            vuln_source: Vec::new(),
            limit: 50,
        }
    }
}

impl FindingListFilter {
    pub const MAX_LIMIT: usize = 500;

    pub fn with_limit(limit: usize) -> Self {
        Self {
            limit: limit.min(Self::MAX_LIMIT),
            ..Self::default()
        }
    }

    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let mut filter = Self::default();

        filter.severity = string_values(input, "severity")?
            .into_iter()
            .map(|value| Severity::try_from(value.as_str()))
            .collect::<Result<Vec<_>>>()?;
        filter.verdict = string_values(input, "verdict")?
            .into_iter()
            .map(|value| FindingVerdictFilter::from_input(&value))
            .collect::<Result<Vec<_>>>()?;
        filter.name = normalized_optional_string(input, "name")?;
        filter.file_path = normalized_optional_string(input, "filePath")?
            .or(normalized_optional_string(input, "file_path")?);
        filter.limit = match input.get("limit") {
            Some(Value::Number(number)) => number
                .as_u64()
                .with_context(|| "findings:list limit must be a non-negative integer")?
                .min(Self::MAX_LIMIT as u64) as usize,
            Some(Value::String(value)) => value
                .parse::<usize>()
                .with_context(|| "findings:list limit must be a non-negative integer")?
                .min(Self::MAX_LIMIT),
            Some(_) => anyhow::bail!("findings:list limit must be a number"),
            None => filter.limit,
        };

        Ok(filter)
    }

    pub fn from_parts(
        severity: Vec<String>,
        verdict: Vec<String>,
        name: Option<String>,
        file_path: Option<String>,
        limit: usize,
    ) -> Result<Self> {
        Self::from_parts_full(severity, verdict, name, file_path, Vec::new(), limit)
    }

    pub fn from_parts_full(
        severity: Vec<String>,
        verdict: Vec<String>,
        name: Option<String>,
        file_path: Option<String>,
        vuln_source: Vec<String>,
        limit: usize,
    ) -> Result<Self> {
        let severity = severity
            .into_iter()
            .flat_map(split_csv)
            .map(|value| Severity::try_from(value.as_str()))
            .collect::<Result<Vec<_>>>()?;
        let verdict = verdict
            .into_iter()
            .flat_map(split_csv)
            .map(|value| FindingVerdictFilter::from_input(&value))
            .collect::<Result<Vec<_>>>()?;
        let vuln_source = vuln_source
            .into_iter()
            .flat_map(split_csv)
            .map(|value| {
                VulnSource::parse(&value)
                    .ok_or_else(|| anyhow::anyhow!("unknown vuln source {value:?}"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            severity,
            verdict,
            name: normalize_string(name),
            file_path: normalize_string(file_path),
            vuln_source,
            limit: limit.min(Self::MAX_LIMIT),
        })
    }

    fn matches(&self, finding: &Finding) -> bool {
        if !self.severity.is_empty() && !self.severity.contains(&finding.severity) {
            return false;
        }

        if !self.verdict.is_empty()
            && !self
                .verdict
                .contains(&FindingVerdictFilter::from_finding(finding))
        {
            return false;
        }

        if let Some(name) = &self.name {
            let title = finding.title.to_ascii_lowercase();
            if !title.contains(name) {
                return false;
            }
        }

        if !self.vuln_source.is_empty() {
            let observed = finding
                .vuln_source
                .unwrap_or_else(|| VulnSource::from_tool(&finding.tool));
            if !self.vuln_source.contains(&observed) {
                return false;
            }
        }

        if let Some(file_path) = &self.file_path {
            let path = finding.file_path.to_ascii_lowercase();
            if !path.contains(file_path) {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FindingListReport {
    pub count: usize,
    pub findings: Vec<Finding>,
}

impl FindingListReport {
    pub fn output(&self) -> String {
        if self.findings.is_empty() {
            return "  (no findings match)".to_string();
        }

        let id_width = self
            .findings
            .iter()
            .map(|finding| short_id(&finding.fingerprint).len())
            .max()
            .unwrap_or(2)
            .max(2);
        let severity_width = self
            .findings
            .iter()
            .map(|finding| finding.severity.as_str().len())
            .max()
            .unwrap_or(4)
            .max(4);
        let verdict_width = self
            .findings
            .iter()
            .map(|finding| {
                FindingVerdictFilter::from_finding(finding)
                    .as_legacy_str()
                    .len()
            })
            .max()
            .unwrap_or(5)
            .max(5);
        let name_width = self
            .findings
            .iter()
            .map(|finding| finding.title.len())
            .max()
            .unwrap_or(4)
            .max(4);

        let mut lines = vec![
            format!(
                "  {}  {}  {}  {}",
                pad("Id", id_width),
                pad("Sev", severity_width),
                pad("Check", verdict_width),
                pad("Name", name_width)
            ),
            format!(
                "  {}  {}  {}  {}",
                "-".repeat(id_width),
                "-".repeat(severity_width),
                "-".repeat(verdict_width),
                "-".repeat(name_width)
            ),
        ];

        for finding in &self.findings {
            lines.push(format!(
                "  {}  {}  {}  {}",
                pad(&short_id(&finding.fingerprint), id_width),
                pad(finding.severity.as_str(), severity_width),
                pad(
                    FindingVerdictFilter::from_finding(finding).as_legacy_str(),
                    verdict_width
                ),
                finding.title
            ));
        }

        lines.push(String::new());
        lines.push(format!(
            "  {} matching (showing {})",
            self.count,
            self.findings.len()
        ));
        lines.join("\n")
    }

    pub fn to_tool_json(&self) -> Value {
        json!({
            "ok": true,
            "output": self.output(),
            "data": self,
        })
    }
}

pub struct FindingStore {
    conn: Connection,
}

impl FindingStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Could not create {}", parent.display()))?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("Could not open {}", path.display()))?;
        let store = Self { conn };
        store.init()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let store = Self {
            conn: Connection::open_in_memory().context("Could not open in-memory findings DB")?,
        };
        store.init()?;
        Ok(store)
    }

    pub fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            pragma foreign_keys = on;

            create table if not exists scan_runs (
              id text primary key,
              target text not null,
              status text not null,
              started_at text not null,
              completed_at text,
              findings_count integer not null default 0
            );

            create table if not exists findings (
              id integer primary key autoincrement,
              scan_id text not null references scan_runs(id) on delete cascade,
              fingerprint text not null,
              rule_id text not null,
              title text not null,
              severity text not null,
              file_path text not null,
              start_line integer not null,
              end_line integer,
              message text not null,
              tool text not null,
              actor_fingerprint text,
              created_at text not null,
              unique(scan_id, fingerprint)
            );

            create table if not exists triage (
              finding_id integer primary key references findings(id) on delete cascade,
              verdict text not null,
              confidence real not null,
              rationale text not null,
              created_at text not null
            );

            create table if not exists patch_results (
              patch_run_id text primary key,
              fingerprint text not null,
              repo text not null,
              diff text,
              status text not null
                check (status in ('APPLY_FAILED','BUILD_FAILED','STILL_VULNERABLE',
                                  'TESTS_FAILED','SOUND','VERIFIED','UNKNOWN')),
              iterations integer not null default 1,
              build_command text,
              test_command text,
              worktree_path text,
              cost_usd real,
              validator_log text,
              history_json text not null,
              created_at text not null default (datetime('now')),
              updated_at text not null default (datetime('now'))
            );

            create index if not exists idx_patch_results_fingerprint
              on patch_results(fingerprint, created_at desc);
            create index if not exists idx_patch_results_repo_status
              on patch_results(repo, status);
            "#,
        )?;
        ensure_column(
            &self.conn,
            "findings",
            "actor_fingerprint",
            "alter table findings add column actor_fingerprint text",
        )?;
        ensure_column(
            &self.conn,
            "findings",
            "vuln_source",
            "alter table findings add column vuln_source text",
        )?;
        ensure_column(
            &self.conn,
            "findings",
            "dedup_key",
            "alter table findings add column dedup_key text",
        )?;
        self.conn.execute_batch(
            "create index if not exists idx_findings_dedup_key
               on findings(scan_id, dedup_key) where dedup_key is not null;
             create index if not exists idx_findings_vuln_source
               on findings(vuln_source) where vuln_source is not null;",
        )?;
        Ok(())
    }

    pub fn insert_scan_run(&self, id: &str, target: &Path, status: &str) -> Result<()> {
        self.conn.execute(
            r#"
            insert into scan_runs(id, target, status, started_at, findings_count)
            values (?1, ?2, ?3, ?4, 0)
            on conflict(id) do update set status = excluded.status
            "#,
            params![id, target.display().to_string(), status, now_isoish()],
        )?;
        Ok(())
    }

    pub fn complete_scan_run(&self, id: &str, status: &str, findings_count: usize) -> Result<()> {
        self.conn.execute(
            r#"
            update scan_runs
            set status = ?2, completed_at = ?3, findings_count = ?4
            where id = ?1
            "#,
            params![id, status, now_isoish(), findings_count as i64],
        )?;
        Ok(())
    }

    pub fn insert_finding(&self, scan_id: &str, finding: &Finding) -> Result<i64> {
        // Cross-channel dedup: when a finding with the same dedup_key but a
        // different fingerprint already exists in this scan, merge instead
        // of inserting a duplicate row. Higher severity wins; tools merge
        // into a comma-list. Skipped silently when the new finding has no
        // dedup_key (legacy callers).
        if let Some(dedup_key) = finding.dedup_key.as_deref() {
            if let Some(existing) = self.find_collision(scan_id, dedup_key, &finding.fingerprint)? {
                let new_sev = finding.severity;
                let merge_id = existing.id.expect("existing finding always has id");
                let merged_tool = merge_tool_list(&existing.tool, &finding.tool);
                let merged_source = merge_vuln_source(existing.vuln_source, finding.vuln_source);
                if new_sev > existing.severity {
                    // Replace the headline rule_id/title/message with the
                    // higher-severity finding so the operator sees the
                    // dominant one.
                    self.conn.execute(
                        r#"update findings set
                             severity = ?, rule_id = ?, title = ?, message = ?,
                             tool = ?, vuln_source = ?
                           where id = ?"#,
                        params![
                            new_sev.as_str(),
                            finding.rule_id,
                            finding.title,
                            finding.message,
                            merged_tool,
                            merged_source.map(|s| s.as_str()),
                            merge_id,
                        ],
                    )?;
                } else if existing.tool != merged_tool {
                    self.conn.execute(
                        "update findings set tool = ?, vuln_source = ? where id = ?",
                        params![merged_tool, merged_source.map(|s| s.as_str()), merge_id],
                    )?;
                }
                return Ok(merge_id);
            }
        }

        self.conn.execute(
            r#"
            insert into findings(
              scan_id, fingerprint, rule_id, title, severity, file_path,
              start_line, end_line, message, tool, actor_fingerprint, created_at,
              vuln_source, dedup_key
            )
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            on conflict(scan_id, fingerprint) do update set
              title = excluded.title,
              severity = excluded.severity,
              message = excluded.message,
              actor_fingerprint = excluded.actor_fingerprint,
              vuln_source = coalesce(excluded.vuln_source, findings.vuln_source),
              dedup_key = coalesce(excluded.dedup_key, findings.dedup_key)
            "#,
            params![
                scan_id,
                finding.fingerprint,
                finding.rule_id,
                finding.title,
                finding.severity.as_str(),
                finding.file_path,
                finding.start_line,
                finding.end_line,
                finding.message,
                finding.tool,
                finding.actor_fingerprint,
                finding.created_at,
                finding.vuln_source.map(|s| s.as_str()),
                finding.dedup_key,
            ],
        )?;

        let id: i64 = self.conn.query_row(
            "select id from findings where scan_id = ?1 and fingerprint = ?2",
            params![scan_id, finding.fingerprint],
            |row| row.get(0),
        )?;
        Ok(id)
    }

    /// Look up an existing finding in the same scan that shares the
    /// dedup_key but differs in fingerprint. Returns the existing
    /// finding's `(id, severity, tool, vuln_source)` enough to drive
    /// merge logic.
    fn find_collision(
        &self,
        scan_id: &str,
        dedup_key: &str,
        new_fingerprint: &str,
    ) -> Result<Option<Finding>> {
        let mut stmt = self.conn.prepare(
            "select id, severity, tool, vuln_source
               from findings
              where scan_id = ?1
                and dedup_key = ?2
                and fingerprint != ?3
              limit 1",
        )?;
        let row: Option<(i64, String, String, Option<String>)> = stmt
            .query_row(params![scan_id, dedup_key, new_fingerprint], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .optional()?;
        Ok(row.map(|(id, sev_str, tool, src_str)| {
            let severity = Severity::try_from(sev_str.as_str()).unwrap_or(Severity::Unknown);
            let vuln_source = src_str.as_deref().and_then(VulnSource::parse);
            Finding {
                id: Some(id),
                scan_id: Some(scan_id.to_string()),
                fingerprint: String::new(),
                rule_id: String::new(),
                title: String::new(),
                severity,
                file_path: String::new(),
                start_line: 0,
                end_line: None,
                message: String::new(),
                tool,
                actor_fingerprint: None,
                triage: None,
                created_at: String::new(),
                vuln_source,
                dedup_key: Some(dedup_key.to_string()),
            }
        }))
    }

    pub fn save_triage(&self, finding_id: i64, triage: &TriageOutcome) -> Result<()> {
        self.conn.execute(
            r#"
            insert into triage(finding_id, verdict, confidence, rationale, created_at)
            values (?1, ?2, ?3, ?4, ?5)
            on conflict(finding_id) do update set
              verdict = excluded.verdict,
              confidence = excluded.confidence,
              rationale = excluded.rationale,
              created_at = excluded.created_at
            "#,
            params![
                finding_id,
                triage.verdict.as_str(),
                triage.confidence,
                triage.rationale,
                now_isoish(),
            ],
        )?;
        Ok(())
    }

    pub fn insert_patch_result(&self, result: &PatchResult) -> Result<()> {
        let history_json =
            serde_json::to_string(&result.history).context("Could not serialize patch history")?;
        self.conn.execute(
            r#"
            insert into patch_results(
              patch_run_id, fingerprint, repo, diff, status, iterations,
              build_command, test_command, worktree_path, cost_usd,
              validator_log, history_json
            )
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            params![
                &result.patch_run_id,
                &result.fingerprint,
                &result.repo,
                &result.diff,
                result.status.as_str(),
                result.iterations as i64,
                &result.build_command,
                &result.test_command,
                &result.worktree_path,
                result.cost_usd,
                &result.validator_log,
                history_json,
            ],
        )?;
        Ok(())
    }

    pub fn get_patch_results_for_finding(&self, fingerprint: &str) -> Result<Vec<PatchResult>> {
        let mut stmt = self.conn.prepare(
            r#"
            select patch_run_id, fingerprint, repo, diff, status, iterations,
                   build_command, test_command, worktree_path, cost_usd,
                   validator_log, history_json, created_at, updated_at
            from patch_results
            where fingerprint = ?1
            order by created_at desc
            "#,
        )?;
        let rows = stmt.query_map(params![fingerprint], row_to_patch_result)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list patch results")
    }

    pub fn list_findings(&self, limit: usize) -> Result<Vec<Finding>> {
        Ok(self
            .list_findings_filtered(&FindingListFilter::with_limit(limit))?
            .findings)
    }

    pub fn list_findings_for_scan_id(&self, scan_id: &str) -> Result<Vec<Finding>> {
        let mut stmt = self.conn.prepare(
            r#"
            select
              f.id, f.scan_id, f.fingerprint, f.rule_id, f.title, f.severity,
              f.file_path, f.start_line, f.end_line, f.message, f.tool, f.actor_fingerprint,
              f.created_at,
              t.verdict, t.confidence, t.rationale,
              f.vuln_source, f.dedup_key
            from findings f
            left join triage t on t.finding_id = f.id
            where f.scan_id = ?1
            order by f.id asc
            "#,
        )?;
        let rows = stmt.query_map(params![scan_id], row_to_finding)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list findings for scan run")
    }

    pub fn list_findings_filtered(&self, filter: &FindingListFilter) -> Result<FindingListReport> {
        let mut stmt = self.conn.prepare(
            r#"
            select
              f.id, f.scan_id, f.fingerprint, f.rule_id, f.title, f.severity,
              f.file_path, f.start_line, f.end_line, f.message, f.tool, f.actor_fingerprint,
              f.created_at,
              t.verdict, t.confidence, t.rationale,
              f.vuln_source, f.dedup_key
            from findings f
            left join triage t on t.finding_id = f.id
            order by
              case f.severity
                when 'critical' then 0
                when 'high' then 1
                when 'medium' then 2
                when 'low' then 3
                when 'info' then 4
                else 5
              end,
              f.id desc
            "#,
        )?;

        let rows = stmt.query_map([], row_to_finding)?;
        let mut count = 0;
        let mut findings = Vec::new();
        for row in rows {
            let finding = row.context("Could not list findings")?;
            if !filter.matches(&finding) {
                continue;
            }
            count += 1;
            if findings.len() < filter.limit {
                findings.push(finding);
            }
        }

        Ok(FindingListReport { count, findings })
    }

    pub fn get_finding_by_fingerprint(&self, fingerprint: &str) -> Result<Option<Finding>> {
        self.conn
            .query_row(
                r#"
                select
                  f.id, f.scan_id, f.fingerprint, f.rule_id, f.title, f.severity,
                  f.file_path, f.start_line, f.end_line, f.message, f.tool, f.actor_fingerprint,
                  f.created_at,
                  t.verdict, t.confidence, t.rationale
                from findings f
                left join triage t on t.finding_id = f.id
                where f.fingerprint = ?1
                order by f.id desc
                limit 1
                "#,
                params![fingerprint],
                row_to_finding,
            )
            .optional()
            .context("Could not load finding")
    }

    pub fn get_finding_by_reference(&self, reference: &str) -> Result<Option<Finding>> {
        let reference = reference.trim();
        if reference.is_empty() {
            anyhow::bail!("finding reference must not be empty");
        }

        if let Some(finding) = self.get_finding_by_fingerprint(reference)? {
            return Ok(Some(finding));
        }

        let like_pattern = format!("{reference}%");
        let mut stmt = self.conn.prepare(
            r#"
            select
              f.id, f.scan_id, f.fingerprint, f.rule_id, f.title, f.severity,
              f.file_path, f.start_line, f.end_line, f.message, f.tool, f.actor_fingerprint,
              f.created_at,
              t.verdict, t.confidence, t.rationale,
              f.vuln_source, f.dedup_key
            from findings f
            left join triage t on t.finding_id = f.id
            where f.fingerprint like ?1
            order by f.id desc
            limit 2
            "#,
        )?;

        let rows = stmt.query_map(params![like_pattern], row_to_finding)?;
        let matches = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not resolve finding reference")?;

        match matches.len() {
            0 => Ok(None),
            1 => Ok(matches.into_iter().next()),
            _ => anyhow::bail!("finding reference {reference:?} is ambiguous"),
        }
    }
}

fn row_to_patch_result(row: &rusqlite::Row<'_>) -> rusqlite::Result<PatchResult> {
    let status: String = row.get(4)?;
    let history_json: String = row.get(11)?;
    let history = serde_json::from_str::<Vec<PatchAttempt>>(&history_json)
        .map_err(|error| to_sql_error(anyhow::Error::new(error)))?;

    Ok(PatchResult {
        patch_run_id: row.get(0)?,
        fingerprint: row.get(1)?,
        repo: row.get(2)?,
        diff: row.get(3)?,
        status: PatchStatus::try_from(status.as_str()).map_err(to_sql_error)?,
        iterations: row.get::<_, i64>(5)? as usize,
        build_command: row.get(6)?,
        test_command: row.get(7)?,
        worktree_path: row.get(8)?,
        cost_usd: row.get(9)?,
        validator_log: row.get(10)?,
        history,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
    })
}

fn row_to_finding(row: &rusqlite::Row<'_>) -> rusqlite::Result<Finding> {
    let severity: String = row.get(5)?;
    let verdict: Option<String> = row.get(13)?;
    let triage = match verdict {
        Some(verdict) => Some(TriageOutcome {
            verdict: TriageVerdict::try_from(verdict.as_str()).map_err(to_sql_error)?,
            confidence: row.get::<_, f32>(14)?,
            rationale: row.get(15)?,
        }),
        None => None,
    };

    let vuln_source: Option<String> = row.get(16).ok();
    let dedup_key: Option<String> = row.get(17).ok();
    Ok(Finding {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        fingerprint: row.get(2)?,
        rule_id: row.get(3)?,
        title: row.get(4)?,
        severity: Severity::try_from(severity.as_str()).map_err(to_sql_error)?,
        file_path: row.get(6)?,
        start_line: row.get::<_, u32>(7)?,
        end_line: row.get(8)?,
        message: row.get(9)?,
        tool: row.get(10)?,
        actor_fingerprint: row.get(11)?,
        created_at: row.get(12)?,
        triage,
        vuln_source: vuln_source.as_deref().and_then(VulnSource::parse),
        dedup_key,
    })
}

fn ensure_column(conn: &Connection, table: &str, column: &str, alter_sql: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("pragma table_info({table})"))?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !columns.iter().any(|existing| existing == column) {
        conn.execute_batch(alter_sql)?;
    }
    Ok(())
}

fn to_sql_error(error: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            error.to_string(),
        )),
    )
}

fn fingerprint_parts(rule_id: &str, file_path: &str, start_line: u32, message: &str) -> String {
    let mut hasher = DefaultHasher::new();
    rule_id.hash(&mut hasher);
    file_path.hash(&mut hasher);
    start_line.hash(&mut hasher);
    message.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Merge a comma-separated tool list `existing` with a new `incoming`
/// tool name. Order is stable (sorted) so the test output is
/// deterministic.
pub(crate) fn merge_tool_list(existing: &str, incoming: &str) -> String {
    let mut tools: std::collections::BTreeSet<String> = existing
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    tools.insert(incoming.trim().to_string());
    tools.into_iter().collect::<Vec<_>>().join(",")
}

/// Merge two `VulnSource` values: keep the existing if both are set,
/// since tool merging already records the new channel via the tool list.
pub(crate) fn merge_vuln_source(
    existing: Option<VulnSource>,
    incoming: Option<VulnSource>,
) -> Option<VulnSource> {
    existing.or(incoming)
}

fn now_isoish() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{secs}")
}

fn string_values(input: &Value, key: &str) -> Result<Vec<String>> {
    let Some(value) = input.get(key) else {
        return Ok(Vec::new());
    };

    match value {
        Value::Array(values) => values
            .iter()
            .map(|value| match value {
                Value::String(text) => Ok(split_csv(text.to_string())),
                other => {
                    anyhow::bail!("findings:list {key} entries must be strings, got {}", other)
                }
            })
            .collect::<Result<Vec<_>>>()
            .map(|values| values.into_iter().flatten().collect()),
        Value::String(text) => Ok(split_csv(text.to_string()).collect()),
        _ => anyhow::bail!("findings:list {key} must be an array of strings"),
    }
}

fn normalized_optional_string(input: &Value, key: &str) -> Result<Option<String>> {
    match input.get(key) {
        Some(Value::String(value)) => Ok(normalize_string(Some(value.to_string()))),
        Some(_) => anyhow::bail!("findings:list {key} must be a string"),
        None => Ok(None),
    }
}

fn normalize_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

fn split_csv(value: String) -> impl Iterator<Item = String> {
    value
        .split(',')
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .into_iter()
}

fn short_id(fingerprint: &str) -> String {
    fingerprint.chars().take(8).collect()
}

fn pad(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_cwe_finds_first_cwe_in_message() {
        assert_eq!(
            extract_cwe("rule-x", "OOB write", "user-controlled length, see CWE-787"),
            Some("CWE-787".to_string())
        );
    }

    #[test]
    fn extract_cwe_handles_lowercase_and_multiple() {
        assert_eq!(
            extract_cwe("cwe-125/rule", "title", "msg"),
            Some("CWE-125".to_string())
        );
        assert_eq!(
            extract_cwe(
                "rule",
                "title",
                "could be CWE-787 or CWE-125 — needs review"
            ),
            Some("CWE-787".to_string()) // first hit wins
        );
    }

    #[test]
    fn normalize_cwe_collapses_variants() {
        assert_eq!(normalize_cwe("CWE-787"), "787");
        assert_eq!(normalize_cwe("cwe_787"), "787");
        assert_eq!(normalize_cwe("CWE787"), "787");
        assert_eq!(normalize_cwe(" 787 "), "787");
    }

    #[test]
    fn compute_dedup_key_buckets_lines_by_16() {
        let a = compute_dedup_key("src/foo.c", 42, Some("CWE-787"));
        let b = compute_dedup_key("src/foo.c", 47, Some("CWE-787"));
        let c = compute_dedup_key("src/foo.c", 60, Some("CWE-787"));
        assert_eq!(a, b, "lines 42 and 47 share the bucket 42/16=2");
        assert_ne!(a, c, "line 60 is in bucket 60/16=3");
    }

    #[test]
    fn vuln_source_round_trips_through_parse() {
        for src in [
            VulnSource::Sarif,
            VulnSource::Ainalysis,
            VulnSource::AinalysisMulti,
            VulnSource::DiffAnalyzer,
            VulnSource::Infer,
            VulnSource::Fuzzing,
        ] {
            assert_eq!(VulnSource::parse(src.as_str()), Some(src));
        }
    }

    #[test]
    fn vuln_source_from_tool_classifies_known_tools() {
        assert_eq!(VulnSource::from_tool("semgrep"), VulnSource::Sarif);
        assert_eq!(VulnSource::from_tool("codeql"), VulnSource::Sarif);
        assert_eq!(VulnSource::from_tool("systems-hunt"), VulnSource::Ainalysis);
        assert_eq!(VulnSource::from_tool("full-mode-multi"), VulnSource::AinalysisMulti);
        assert_eq!(VulnSource::from_tool("variant-ndiff"), VulnSource::DiffAnalyzer);
    }

    #[test]
    fn new_tool_only_sets_dedup_key_when_cwe_was_extracted() {
        let with_cwe = Finding::new_tool(
            "semgrep",
            "rule",
            "src/foo.c",
            10,
            Some(15),
            Severity::High,
            "OOB write CWE-787 in handler",
        );
        assert!(with_cwe.dedup_key.is_some());
        let without_cwe = Finding::new_tool(
            "semgrep",
            "rule",
            "src/foo.c",
            10,
            Some(15),
            Severity::High,
            "Hardcoded credential in source",
        );
        assert!(without_cwe.dedup_key.is_none());
    }

    #[test]
    fn merge_tool_list_is_set_union() {
        assert_eq!(merge_tool_list("semgrep", "codeql"), "codeql,semgrep");
        assert_eq!(merge_tool_list("semgrep,codeql", "semgrep"), "codeql,semgrep");
        assert_eq!(merge_tool_list("", "semgrep"), "semgrep");
    }

    #[test]
    fn cross_channel_dedup_merges_higher_severity_finding() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-dedup";
        store.insert_scan_run(run, std::path::Path::new("/tmp"), "running").unwrap();

        // Two findings on the same file/line/CWE from different channels.
        let semgrep = Finding::new_tool(
            "semgrep",
            "java.injection.tainted-system-call",
            "src/foo.c",
            42,
            Some(42),
            Severity::Medium,
            "user-controlled exec, CWE-78",
        );
        let id1 = store.insert_finding(run, &semgrep).unwrap();

        // Higher-severity collision from full-mode-multi.
        let mut chunked = Finding::new_tool(
            "full-mode-multi",
            "full-mode-multi/cwe-78",
            "src/foo.c",
            45, // same 16-line bucket as 42
            Some(45),
            Severity::High,
            "exec with attacker-controlled argv, CWE-78",
        );
        // Make sure both have the same dedup_key.
        assert_eq!(semgrep.dedup_key, chunked.dedup_key);
        // …but different fingerprints (rule_id differs).
        assert_ne!(semgrep.fingerprint, chunked.fingerprint);
        chunked = chunked; // no-op for clarity

        let id2 = store.insert_finding(run, &chunked).unwrap();

        // Merge means same row id is returned.
        assert_eq!(id1, id2);

        let listed = store.list_findings(10).unwrap();
        assert_eq!(listed.len(), 1, "merged into a single row");
        let row = &listed[0];
        // High wins.
        assert_eq!(row.severity, Severity::High);
        // Tool list merged.
        assert!(row.tool.contains("semgrep"));
        assert!(row.tool.contains("full-mode-multi"));
        assert_eq!(row.dedup_key, semgrep.dedup_key);
    }

    #[test]
    fn cross_channel_dedup_preserves_existing_when_lower_severity_arrives() {
        let store = FindingStore::open_in_memory().unwrap();
        let run = "run-dedup-2";
        store.insert_scan_run(run, std::path::Path::new("/tmp"), "running").unwrap();

        let high = Finding::new_tool(
            "full-mode-multi",
            "full-mode-multi/cwe-787",
            "src/foo.c",
            42,
            Some(42),
            Severity::Critical,
            "OOB write CWE-787",
        );
        store.insert_finding(run, &high).unwrap();
        let low = Finding::new_tool(
            "semgrep",
            "rule",
            "src/foo.c",
            47, // same bucket as 42 (both in 32..47)
            Some(47),
            Severity::Low,
            "weakish suspicion CWE-787",
        );
        store.insert_finding(run, &low).unwrap();
        let listed = store.list_findings(10).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].severity, Severity::Critical);
        // Tool list still merges even when severity didn't change.
        assert!(listed[0].tool.contains("semgrep"));
        assert!(listed[0].tool.contains("full-mode-multi"));
    }

    #[test]
    fn stores_and_lists_findings_with_triage() {
        let store = FindingStore::open_in_memory().unwrap();
        let run_id = "run-1";
        store
            .insert_scan_run(run_id, Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.rule",
            "src/app.ts",
            12,
            Some(12),
            Severity::High,
            "User input reaches sink",
        );
        let finding_id = store.insert_finding(run_id, &finding).unwrap();
        store
            .save_triage(
                finding_id,
                &TriageOutcome {
                    verdict: TriageVerdict::NeedsReview,
                    confidence: 0.42,
                    rationale: "needs dataflow confirmation".to_string(),
                },
            )
            .unwrap();

        let rows = store.list_findings(10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].rule_id, "demo.rule");
        assert_eq!(
            rows[0].triage.as_ref().unwrap().verdict,
            TriageVerdict::NeedsReview
        );
    }

    #[test]
    fn resolves_finding_by_fingerprint_prefix() {
        let store = FindingStore::open_in_memory().unwrap();
        let run_id = "run-1";
        store
            .insert_scan_run(run_id, Path::new("/tmp/repo"), "running")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.rule",
            "src/app.ts",
            12,
            Some(12),
            Severity::High,
            "User input reaches sink",
        );
        store.insert_finding(run_id, &finding).unwrap();

        let prefix = &finding.fingerprint[..8];
        let resolved = store.get_finding_by_reference(prefix).unwrap().unwrap();

        assert_eq!(resolved.fingerprint, finding.fingerprint);
    }

    #[test]
    fn filters_findings_by_severity_name_file_and_limit() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-1", Path::new("/tmp/repo"), "completed")
            .unwrap();

        for (rule, file, severity, message) in [
            (
                "demo.ssrf",
                "src/routes/fetch.ts",
                Severity::Critical,
                "SSRF in /fetch",
            ),
            (
                "demo.token",
                "tests/fixtures/token.ts",
                Severity::Low,
                "Hardcoded token in tests",
            ),
            (
                "demo.sql",
                "src/db/query.ts",
                Severity::High,
                "SQL injection in search",
            ),
        ] {
            let finding = Finding::new_semgrep(rule, file, 8, Some(8), severity, message);
            store.insert_finding("run-1", &finding).unwrap();
        }

        let report = store
            .list_findings_filtered(
                &FindingListFilter::from_parts(
                    vec!["critical,high".to_string()],
                    vec![],
                    Some("in".to_string()),
                    Some("src/".to_string()),
                    1,
                )
                .unwrap(),
            )
            .unwrap();

        assert_eq!(report.count, 2);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "demo.ssrf");
        assert!(report.output().contains("2 matching (showing 1)"));
    }

    #[test]
    fn filters_findings_by_legacy_verdict_values() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-1", Path::new("/tmp/repo"), "completed")
            .unwrap();

        let true_positive = Finding::new_semgrep(
            "demo.tp",
            "src/a.ts",
            1,
            Some(1),
            Severity::High,
            "confirmed issue",
        );
        let false_positive = Finding::new_semgrep(
            "demo.fp",
            "src/b.ts",
            1,
            Some(1),
            Severity::High,
            "dismissed issue",
        );
        let untriaged = Finding::new_semgrep(
            "demo.review",
            "src/c.ts",
            1,
            Some(1),
            Severity::High,
            "review issue",
        );
        let true_positive_id = store.insert_finding("run-1", &true_positive).unwrap();
        let false_positive_id = store.insert_finding("run-1", &false_positive).unwrap();
        store.insert_finding("run-1", &untriaged).unwrap();
        store
            .save_triage(
                true_positive_id,
                &TriageOutcome {
                    verdict: TriageVerdict::TruePositive,
                    confidence: 0.9,
                    rationale: "confirmed".to_string(),
                },
            )
            .unwrap();
        store
            .save_triage(
                false_positive_id,
                &TriageOutcome {
                    verdict: TriageVerdict::FalsePositive,
                    confidence: 0.8,
                    rationale: "safe".to_string(),
                },
            )
            .unwrap();

        let tp = store
            .list_findings_filtered(
                &FindingListFilter::from_parts(vec![], vec!["tp".to_string()], None, None, 10)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(tp.count, 1);
        assert_eq!(tp.findings[0].rule_id, "demo.tp");

        let review = store
            .list_findings_filtered(
                &FindingListFilter::from_tool_input(&json!({"verdict": ["needs_review"]})).unwrap(),
            )
            .unwrap();
        assert_eq!(review.count, 1);
        assert_eq!(review.findings[0].rule_id, "demo.review");
    }
}
