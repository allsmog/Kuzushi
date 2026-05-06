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
    #[serde(
        rename = "staticProofState",
        alias = "static_proof_state",
        skip_serializing_if = "Option::is_none"
    )]
    pub static_proof_state: Option<StaticProofState>,
    pub triage: Option<TriageOutcome>,
    pub created_at: String,
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
            static_proof_state: None,
            triage: None,
            created_at: now_isoish(),
        }
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

    pub fn with_static_proof_state(mut self, state: StaticProofState) -> Self {
        self.static_proof_state = Some(state);
        self
    }

    pub fn set_static_proof_state(&mut self, state: StaticProofState) {
        self.static_proof_state = Some(state);
    }

    pub fn set_static_proof_state_from_str(&mut self, state: &str) -> Result<()> {
        self.static_proof_state = Some(StaticProofState::try_from(state)?);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum StaticProofState {
    SignalOnly,
    CodeCited,
    SourceSinkLinked,
    SanitizerChecked,
    StaticallyConfirmed,
    StaticallyRejected,
    NeedsRuntimeEvidence,
}

impl StaticProofState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignalOnly => "signal_only",
            Self::CodeCited => "code_cited",
            Self::SourceSinkLinked => "source_sink_linked",
            Self::SanitizerChecked => "sanitizer_checked",
            Self::StaticallyConfirmed => "statically_confirmed",
            Self::StaticallyRejected => "statically_rejected",
            Self::NeedsRuntimeEvidence => "needs_runtime_evidence",
        }
    }

    pub fn is_static_terminal_state(self) -> bool {
        matches!(
            self,
            Self::StaticallyConfirmed | Self::StaticallyRejected | Self::NeedsRuntimeEvidence
        )
    }
}

impl TryFrom<&str> for StaticProofState {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value.trim() {
            "signal_only" | "signal-only" | "signal" => Ok(Self::SignalOnly),
            "code_cited" | "code-cited" | "cited" => Ok(Self::CodeCited),
            "source_sink_linked" | "source-sink-linked" | "linked" => Ok(Self::SourceSinkLinked),
            "sanitizer_checked" | "sanitizer-checked" | "sanitizer" => Ok(Self::SanitizerChecked),
            "statically_confirmed" | "statically-confirmed" => Ok(Self::StaticallyConfirmed),
            "statically_rejected" | "statically-rejected" => Ok(Self::StaticallyRejected),
            "needs_runtime_evidence" | "needs-runtime-evidence" | "needs_runtime" => {
                Ok(Self::NeedsRuntimeEvidence)
            }
            "execution_confirmed"
            | "runtime_confirmed"
            | "dynamic_confirmed"
            | "exploit_confirmed"
            | "poc_confirmed" => {
                anyhow::bail!("execution proof state {value:?} is not valid static proof")
            }
            other => anyhow::bail!("unknown static proof state {other:?}"),
        }
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
    pub limit: usize,
}

impl Default for FindingListFilter {
    fn default() -> Self {
        Self {
            severity: Vec::new(),
            verdict: Vec::new(),
            name: None,
            file_path: None,
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

        Ok(Self {
            severity,
            verdict,
            name: normalize_string(name),
            file_path: normalize_string(file_path),
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

        let aliased = sorted_finding_aliases(&self.findings);
        let alias_width = aliased
            .iter()
            .map(|(alias, _)| alias.len())
            .max()
            .unwrap_or(5)
            .max(5);
        let fingerprint_width = aliased
            .iter()
            .map(|(_, finding)| short_id(&finding.fingerprint).len())
            .max()
            .unwrap_or(8)
            .max(8);
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
                "  {}  {}  {}  {}  {}",
                pad("Alias", alias_width),
                pad("Fingerprint", fingerprint_width),
                pad("Sev", severity_width),
                pad("Check", verdict_width),
                pad("Name", name_width)
            ),
            format!(
                "  {}  {}  {}  {}  {}",
                "-".repeat(alias_width),
                "-".repeat(fingerprint_width),
                "-".repeat(severity_width),
                "-".repeat(verdict_width),
                "-".repeat(name_width)
            ),
        ];

        for (alias, finding) in aliased {
            lines.push(format!(
                "  {}  {}  {}  {}  {}",
                pad(&alias, alias_width),
                pad(&short_id(&finding.fingerprint), fingerprint_width),
                pad(finding.severity.as_str(), severity_width),
                pad(
                    FindingVerdictFilter::from_finding(&finding).as_legacy_str(),
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

pub fn format_finding_alias(index: usize) -> String {
    format!("F-{:04}", index + 1)
}

pub fn parse_finding_alias(reference: &str) -> Option<usize> {
    let reference = reference.trim();
    let suffix = reference
        .strip_prefix("F-")
        .or_else(|| reference.strip_prefix("f-"))?;
    let index = suffix.parse::<usize>().ok()?;
    index.checked_sub(1)
}

pub fn sorted_finding_aliases(findings: &[Finding]) -> Vec<(String, Finding)> {
    let mut indexed: Vec<&Finding> = findings.iter().collect();
    indexed.sort_by(|a, b| {
        let by_severity = severity_rank(a.severity).cmp(&severity_rank(b.severity));
        if by_severity == std::cmp::Ordering::Equal {
            a.fingerprint.cmp(&b.fingerprint)
        } else {
            by_severity
        }
    });
    indexed
        .into_iter()
        .enumerate()
        .map(|(index, finding)| (format_finding_alias(index), finding.clone()))
        .collect()
}

pub fn stable_finding_alias(findings: &[Finding], fingerprint: &str) -> Option<String> {
    sorted_finding_aliases(findings)
        .into_iter()
        .find(|(_, finding)| finding.fingerprint == fingerprint)
        .map(|(alias, _)| alias)
}

pub fn resolve_finding_alias(findings: &[Finding], reference: &str) -> Option<Finding> {
    let index = parse_finding_alias(reference)?;
    sorted_finding_aliases(findings)
        .into_iter()
        .nth(index)
        .map(|(_, finding)| finding)
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
              static_proof_state text,
              created_at text not null,
              analysis_history_json text not null default '[]',
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
            "static_proof_state",
            "alter table findings add column static_proof_state text",
        )?;
        ensure_column(
            &self.conn,
            "findings",
            "analysis_history_json",
            "alter table findings add column analysis_history_json text not null default '[]'",
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
        self.conn.execute(
            r#"
            insert into findings(
              scan_id, fingerprint, rule_id, title, severity, file_path,
              start_line, end_line, message, tool, actor_fingerprint,
              static_proof_state, created_at
            )
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            on conflict(scan_id, fingerprint) do update set
              title = excluded.title,
              severity = excluded.severity,
              message = excluded.message,
              actor_fingerprint = excluded.actor_fingerprint,
              static_proof_state = excluded.static_proof_state
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
                finding.static_proof_state.map(StaticProofState::as_str),
                finding.created_at,
            ],
        )?;

        let id: i64 = self.conn.query_row(
            "select id from findings where scan_id = ?1 and fingerprint = ?2",
            params![scan_id, finding.fingerprint],
            |row| row.get(0),
        )?;
        Ok(id)
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
              f.static_proof_state, f.created_at,
              t.verdict, t.confidence, t.rationale
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
              f.static_proof_state, f.created_at,
              t.verdict, t.confidence, t.rationale
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
                  f.static_proof_state, f.created_at,
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

    pub fn latest_scan_run(&self) -> Result<Option<ScanRunRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, target, status, started_at, completed_at, findings_count
            from scan_runs
            order by started_at desc, id desc
            limit 1
            "#,
        )?;
        let mut rows = stmt.query_map([], row_to_scan_run_record)?;
        match rows.next() {
            None => Ok(None),
            Some(row) => Ok(Some(row.context("Could not load latest scan_run")?)),
        }
    }

    pub fn list_scan_runs(&self, limit: usize) -> Result<Vec<ScanRunRecord>> {
        let limit = limit.max(1).min(500);
        let mut stmt = self.conn.prepare(
            r#"
            select id, target, status, started_at, completed_at, findings_count
            from scan_runs
            order by started_at desc, id desc
            limit ?1
            "#,
        )?;
        let rows = stmt.query_map(params![limit as i64], row_to_scan_run_record)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list scan_runs")
    }

    /// Append an [`AnalysisEntry`] to every row matching the given fingerprint.
    /// Stored in the `analysis_history_json` column as a JSON array; existing
    /// triage_outcome / verdict rows are not modified — this is purely additive.
    /// Returns the number of rows updated.
    pub fn append_analysis_entry(
        &self,
        fingerprint: &str,
        entry: &AnalysisEntry,
    ) -> Result<usize> {
        let fingerprint = fingerprint.trim();
        if fingerprint.is_empty() {
            anyhow::bail!("fingerprint must not be empty");
        }
        let mut updated = 0usize;
        let mut stmt = self
            .conn
            .prepare("select id, analysis_history_json from findings where fingerprint = ?1")?;
        let rows = stmt
            .query_map(params![fingerprint], |row| {
                let id: i64 = row.get(0)?;
                let raw: String = row.get(1)?;
                Ok((id, raw))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (id, raw) in rows {
            let mut history: Vec<AnalysisEntry> = if raw.trim().is_empty() {
                Vec::new()
            } else {
                serde_json::from_str(&raw).unwrap_or_default()
            };
            history.push(entry.clone());
            let serialized =
                serde_json::to_string(&history).context("Could not encode analysis history")?;
            self.conn.execute(
                "update findings set analysis_history_json = ?1 where id = ?2",
                params![serialized, id],
            )?;
            updated += 1;
        }
        Ok(updated)
    }

    pub fn get_analysis_history(&self, fingerprint: &str) -> Result<Vec<AnalysisEntry>> {
        let raw: Option<String> = self
            .conn
            .query_row(
                "select analysis_history_json from findings where fingerprint = ?1 limit 1",
                params![fingerprint],
                |row| row.get(0),
            )
            .optional()
            .context("Could not load analysis history")?;
        let Some(raw) = raw else {
            return Ok(Vec::new());
        };
        if raw.trim().is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_str::<Vec<AnalysisEntry>>(&raw)
            .with_context(|| format!("Could not parse analysis_history_json for {fingerprint}"))
    }

    /// Convenience for emit-hook callers: build an [`AnalysisEntry`] from the
    /// most-common subset of fields and append it. `created_at` is filled in
    /// automatically. Use [`append_analysis_entry`] directly when you need
    /// per-call usage tokens or a reinvestigate marker.
    pub fn record_analysis(
        &self,
        fingerprint: &str,
        run_id: &str,
        agent_type: &str,
        model: &str,
        cost_usd: f64,
        refusal: &RefusalReport,
    ) -> Result<()> {
        let entry = AnalysisEntry {
            run_id: run_id.to_string(),
            agent_type: agent_type.to_string(),
            model: model.to_string(),
            agent_session_id: None,
            finding_count: 1,
            num_turns: 0,
            cost_usd,
            usage: AnalysisUsage::default(),
            reinvestigate_marker: None,
            refusal: refusal.clone(),
            created_at: now_isoish(),
        };
        self.append_analysis_entry(fingerprint, &entry)?;
        Ok(())
    }

    pub fn aggregate_severity_counts(&self) -> Result<Vec<(Severity, usize)>> {
        let mut stmt = self.conn.prepare(
            r#"
            select severity, count(*)
            from findings
            group by severity
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            let severity: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((severity, count as usize))
        })?;
        let mut out: Vec<(Severity, usize)> = Vec::new();
        for row in rows {
            let (severity_str, count) = row.context("Could not aggregate severity counts")?;
            if let Ok(severity) = Severity::try_from(severity_str.as_str()) {
                out.push((severity, count));
            }
        }
        out.sort_by_key(|(severity, _)| severity_rank(*severity));
        Ok(out)
    }

    pub fn aggregate_verdict_counts(&self) -> Result<Vec<(String, usize)>> {
        let mut stmt = self.conn.prepare(
            r#"
            select coalesce(t.verdict, 'untriaged') as verdict, count(*)
            from findings f
            left join triage t on t.finding_id = f.id
            group by coalesce(t.verdict, 'untriaged')
            order by verdict
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            let verdict: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((verdict, count as usize))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not aggregate verdict counts")
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
              f.static_proof_state, f.created_at,
              t.verdict, t.confidence, t.rationale
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

/// One entry in a finding's append-only `analysis_history_json` array.
/// Borrows deepsec's AnalysisEntry shape — captures every per-call event
/// (model, agent_type, cost, tokens, refusal) so re-running scan with a
/// different model is additive instead of overwriting prior verdicts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisEntry {
    pub run_id: String,
    pub agent_type: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_session_id: Option<String>,
    #[serde(default)]
    pub finding_count: usize,
    #[serde(default)]
    pub num_turns: usize,
    #[serde(default)]
    pub cost_usd: f64,
    #[serde(default, skip_serializing_if = "AnalysisUsage::is_empty")]
    pub usage: AnalysisUsage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reinvestigate_marker: Option<String>,
    #[serde(default, skip_serializing_if = "RefusalReport::is_empty")]
    pub refusal: RefusalReport,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisUsage {
    #[serde(default)]
    pub input: u64,
    #[serde(default)]
    pub output: u64,
    #[serde(default)]
    pub cache_read: u64,
    #[serde(default)]
    pub cache_create: u64,
}

impl AnalysisUsage {
    pub fn is_empty(&self) -> bool {
        self.input == 0 && self.output == 0 && self.cache_read == 0 && self.cache_create == 0
    }
}

/// Structured record of an agent declining to fully investigate something.
/// Inspired by deepsec's parseRefusalReport — captures the cases where the
/// model returns a verdict but explicitly states it skipped or refused
/// portions of the analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefusalReport {
    pub refused: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub raw: String,
}

impl RefusalReport {
    pub fn is_empty(&self) -> bool {
        !self.refused && self.reason.is_empty() && self.skipped.is_empty()
    }
}

/// Parse a refusal-report JSON blob. Falls back to a heuristic scan over the
/// raw text — useful when the model returns prose. Caller should treat the
/// returned report as advisory; persistence is the operator's choice.
pub fn parse_refusal_report(raw: &str) -> RefusalReport {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return RefusalReport::default();
    }
    if let Ok(report) = serde_json::from_str::<RefusalReport>(trimmed) {
        let mut report = report;
        if report.raw.is_empty() {
            report.raw = trimmed.to_string();
        }
        return report;
    }
    detect_refusal_in_text(trimmed)
}

/// Heuristic — looks for refusal-language ("I cannot", "I won't", "I declined")
/// at the start of any line. Used both as a stand-alone helper and as the
/// fallback for `parse_refusal_report` when the model prose isn't JSON.
pub fn detect_refusal_in_text(raw: &str) -> RefusalReport {
    const MARKERS: &[&str] = &[
        "i cannot",
        "i can't",
        "i won't",
        "i will not",
        "i declined",
        "i decline to",
        "i refuse",
        "i'm not able",
        "i am not able",
        "skipped because",
        "out of an abundance of caution",
    ];
    let lower = raw.to_ascii_lowercase();
    let refused = MARKERS.iter().any(|marker| lower.contains(marker));
    if refused {
        let reason = raw
            .lines()
            .find(|line| {
                let lower = line.to_ascii_lowercase();
                MARKERS.iter().any(|marker| lower.contains(marker))
            })
            .map(|line| line.trim().to_string())
            .unwrap_or_default();
        RefusalReport {
            refused: true,
            reason,
            skipped: Vec::new(),
            raw: raw.to_string(),
        }
    } else {
        RefusalReport::default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanRunRecord {
    pub id: String,
    pub target: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub findings_count: usize,
}

#[cfg(test)]
mod refusal_tests {
    use super::*;

    #[test]
    fn parses_structured_refusal_json() {
        let raw = r#"{"refused":true,"reason":"too noisy","skipped":["src/secrets.rs"]}"#;
        let report = parse_refusal_report(raw);
        assert!(report.refused);
        assert_eq!(report.reason, "too noisy");
        assert_eq!(report.skipped, vec!["src/secrets.rs".to_string()]);
        assert_eq!(report.raw, raw);
    }

    #[test]
    fn parses_no_refusal_json() {
        let report = parse_refusal_report(r#"{"refused":false}"#);
        assert!(!report.refused);
        assert!(report.is_empty());
    }

    #[test]
    fn falls_back_to_heuristic_for_prose() {
        let report =
            parse_refusal_report("I cannot continue analyzing because of safety concerns.");
        assert!(report.refused);
        assert!(report.reason.starts_with("I cannot"));
        assert!(report.skipped.is_empty());
    }

    #[test]
    fn heuristic_finds_skipped_because() {
        let report = parse_refusal_report("Skipped because the file looked sensitive.");
        assert!(report.refused);
        assert!(report.reason.contains("sensitive"));
    }

    #[test]
    fn empty_input_is_no_refusal() {
        let report = parse_refusal_report("   ");
        assert!(!report.refused);
        assert!(report.is_empty());
    }

    #[test]
    fn neutral_prose_is_no_refusal() {
        let report = parse_refusal_report("True positive: SQL injection in login handler.");
        assert!(!report.refused);
    }

    #[test]
    fn detect_in_text_handles_mixed_case() {
        let report = detect_refusal_in_text("I'M Not Able to evaluate this safely.");
        assert!(report.refused);
    }
}

fn row_to_scan_run_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanRunRecord> {
    Ok(ScanRunRecord {
        id: row.get(0)?,
        target: row.get(1)?,
        status: row.get(2)?,
        started_at: row.get(3)?,
        completed_at: row.get(4)?,
        findings_count: row.get::<_, i64>(5)? as usize,
    })
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
    let static_proof_state: Option<String> = row.get(12)?;
    let verdict: Option<String> = row.get(14)?;
    let triage = match verdict {
        Some(verdict) => Some(TriageOutcome {
            verdict: TriageVerdict::try_from(verdict.as_str()).map_err(to_sql_error)?,
            confidence: row.get::<_, f32>(15)?,
            rationale: row.get(16)?,
        }),
        None => None,
    };

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
        static_proof_state: static_proof_state
            .as_deref()
            .map(StaticProofState::try_from)
            .transpose()
            .map_err(to_sql_error)?,
        created_at: row.get(13)?,
        triage,
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

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
        Severity::Unknown => 5,
    }
}

fn pad(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn append_analysis_entry_round_trips() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-1", Path::new("/tmp/repo"), "running")
            .unwrap();
        let mut finding = Finding::new_semgrep(
            "demo.rule",
            "src/app.ts",
            12,
            None,
            Severity::High,
            "demo",
        );
        finding.fingerprint = "fp-001".to_string();
        store.insert_finding("run-1", &finding).unwrap();

        let entry = AnalysisEntry {
            run_id: "run-1".to_string(),
            agent_type: "triage".to_string(),
            model: "openai:gpt-4.1".to_string(),
            agent_session_id: Some("sess-1".to_string()),
            finding_count: 1,
            num_turns: 3,
            cost_usd: 0.0123,
            usage: AnalysisUsage {
                input: 1500,
                output: 200,
                cache_read: 0,
                cache_create: 800,
            },
            reinvestigate_marker: None,
            refusal: RefusalReport::default(),
            created_at: "2026-05-06T00:00:00Z".to_string(),
        };
        assert_eq!(store.append_analysis_entry("fp-001", &entry).unwrap(), 1);
        let history = store.get_analysis_history("fp-001").unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].run_id, "run-1");
        assert_eq!(history[0].cost_usd, 0.0123);
    }

    #[test]
    fn append_analysis_entry_is_additive_across_runs() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-1", Path::new("/tmp/repo"), "running")
            .unwrap();
        store
            .insert_scan_run("run-2", Path::new("/tmp/repo"), "running")
            .unwrap();
        let mut a = Finding::new_semgrep("rule", "file.ts", 1, None, Severity::High, "demo");
        a.fingerprint = "fp-shared".to_string();
        let mut b = a.clone();
        store.insert_finding("run-1", &a).unwrap();
        store.insert_finding("run-2", &b).unwrap();
        b.fingerprint = "fp-shared".to_string();

        for run_id in ["run-1", "run-2"] {
            store
                .append_analysis_entry(
                    "fp-shared",
                    &AnalysisEntry {
                        run_id: run_id.to_string(),
                        agent_type: "triage".to_string(),
                        model: "openai:gpt-4.1".to_string(),
                        created_at: format!("2026-05-06T00:00:0{}Z", run_id.chars().last().unwrap()),
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let history = store.get_analysis_history("fp-shared").unwrap();
        // Two scan_runs share the fingerprint; each row's history grows
        // independently and `get_analysis_history` returns the first row.
        assert_eq!(history.len(), 2);
        let run_ids: Vec<_> = history.iter().map(|entry| entry.run_id.clone()).collect();
        assert_eq!(run_ids, vec!["run-1", "run-2"]);
    }

    #[test]
    fn analysis_history_returns_empty_when_no_entries() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-1", Path::new("/tmp/repo"), "running")
            .unwrap();
        let mut finding =
            Finding::new_semgrep("rule", "file.ts", 1, None, Severity::High, "demo");
        finding.fingerprint = "fp-empty".to_string();
        store.insert_finding("run-1", &finding).unwrap();
        let history = store.get_analysis_history("fp-empty").unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn static_proof_taxonomy_parses_and_serializes_expected_states() {
        let states = [
            ("signal_only", StaticProofState::SignalOnly),
            ("code_cited", StaticProofState::CodeCited),
            ("source_sink_linked", StaticProofState::SourceSinkLinked),
            ("sanitizer_checked", StaticProofState::SanitizerChecked),
            (
                "statically_confirmed",
                StaticProofState::StaticallyConfirmed,
            ),
            ("statically_rejected", StaticProofState::StaticallyRejected),
            (
                "needs_runtime_evidence",
                StaticProofState::NeedsRuntimeEvidence,
            ),
        ];

        for (raw, state) in states {
            assert_eq!(StaticProofState::try_from(raw).unwrap(), state);
            assert_eq!(state.as_str(), raw);
        }

        assert!(StaticProofState::StaticallyConfirmed.is_static_terminal_state());
        assert!(!StaticProofState::SourceSinkLinked.is_static_terminal_state());
    }

    #[test]
    fn static_proof_taxonomy_rejects_execution_confirmed_states() {
        for raw in [
            "execution_confirmed",
            "runtime_confirmed",
            "dynamic_confirmed",
            "exploit_confirmed",
            "poc_confirmed",
        ] {
            let error = StaticProofState::try_from(raw).unwrap_err().to_string();
            assert!(error.contains("not valid static proof"));
        }
    }

    #[test]
    fn static_proof_state_round_trips_through_findings_store() {
        let store = FindingStore::open_in_memory().unwrap();
        store
            .insert_scan_run("run-static", Path::new("/tmp/repo"), "completed")
            .unwrap();
        let finding = Finding::new_semgrep(
            "demo.static",
            "src/app.ts",
            9,
            Some(10),
            Severity::High,
            "scanner signal",
        )
        .with_static_proof_state(StaticProofState::SignalOnly);

        store.insert_finding("run-static", &finding).unwrap();
        let stored = store.list_findings_for_scan_id("run-static").unwrap();

        assert_eq!(stored.len(), 1);
        assert_eq!(
            stored[0].static_proof_state,
            Some(StaticProofState::SignalOnly)
        );
        let serialized = serde_json::to_value(&stored[0]).unwrap();
        assert_eq!(serialized["staticProofState"], json!("signal_only"));
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
    fn stable_aliases_sort_by_severity_then_fingerprint() {
        let mut high_late = Finding::new_semgrep(
            "demo.high",
            "src/b.ts",
            2,
            Some(2),
            Severity::High,
            "high z",
        );
        high_late.fingerprint = "zzzz1111".to_string();
        let mut high_early = Finding::new_semgrep(
            "demo.high",
            "src/a.ts",
            1,
            Some(1),
            Severity::High,
            "high a",
        );
        high_early.fingerprint = "aaaa1111".to_string();
        let mut critical = Finding::new_semgrep(
            "demo.critical",
            "src/c.ts",
            3,
            Some(3),
            Severity::Critical,
            "critical",
        );
        critical.fingerprint = "mmmm1111".to_string();

        let input = vec![high_late.clone(), high_early.clone(), critical.clone()];
        let aliases = sorted_finding_aliases(&input);

        assert_eq!(aliases[0].0, "F-0001");
        assert_eq!(aliases[0].1.fingerprint, critical.fingerprint);
        assert_eq!(aliases[1].0, "F-0002");
        assert_eq!(aliases[1].1.fingerprint, high_early.fingerprint);
        assert_eq!(
            stable_finding_alias(&input, &high_late.fingerprint).as_deref(),
            Some("F-0003")
        );
        assert_eq!(
            resolve_finding_alias(&input, "f-0002")
                .as_ref()
                .map(|finding| finding.fingerprint.as_str()),
            Some(high_early.fingerprint.as_str())
        );
        assert!(parse_finding_alias("F-0000").is_none());
    }

    #[test]
    fn finding_report_outputs_alias_with_secondary_fingerprint() {
        let mut high_late =
            Finding::new_semgrep("demo.b", "src/b.ts", 2, Some(2), Severity::High, "b");
        high_late.fingerprint = "zzzz1111".to_string();
        let mut high_early =
            Finding::new_semgrep("demo.a", "src/a.ts", 1, Some(1), Severity::High, "a");
        high_early.fingerprint = "aaaa1111".to_string();
        let report = FindingListReport {
            count: 2,
            findings: vec![high_late, high_early],
        };

        let output = report.output();

        assert!(output.contains("Alias"));
        assert!(output.contains("Fingerprint"));
        let first = output.find("F-0001").unwrap();
        let second = output.find("F-0002").unwrap();
        assert!(first < second);
        assert!(output[first..].contains("aaaa1111"));
        assert!(output[second..].contains("zzzz1111"));
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
