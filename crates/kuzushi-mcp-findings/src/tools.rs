//! Read-only prior-finding queries over the workspace findings DB
//! (`.kuzushi/v3/index.sqlite3`). Attached by the bridge when the artifact
//! exists so a hunting agent can check what is already known about a file
//! before re-reporting it.

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::{ReadRootCapability, Tool, ToolHandler, ToolRegistry};
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use std::path::Path;

pub(crate) const ARTIFACT_ENV: &str = "KUZUSHI_MCP_FINDINGS_ARTIFACT";
const DEFAULT_QUERY_LIMIT: usize = 25;
const MAX_QUERY_LIMIT: usize = 200;

/// Latest observation per stable finding key — the same identity rule the
/// core projection uses (identityId when present, else fingerprint).
const LATEST_FINDINGS_SQL: &str = r#"
with observations as (
    select finding_json,
           coalesce(nullif(json_extract(finding_json, '$.identityId'), ''),
                    json_extract(finding_json, '$.fingerprint')) as stable_key,
           created_seq
      from finding_observations
     where finding_json is not null
), ranked as (
    select finding_json,
           row_number() over (partition by stable_key order by created_seq desc) as rank
      from observations
)
select finding_json from ranked where rank = 1
"#;

pub(crate) fn build_registry() -> Result<ToolRegistry> {
    Ok(build_registry_with_capability(
        ReadRootCapability::from_environment()?,
    ))
}

fn build_registry_with_capability(read_capability: ReadRootCapability) -> ToolRegistry {
    ToolRegistry::new()
        .register(query_descriptor(), QueryHandler(read_capability.clone()))
        .register(stats_descriptor(), StatsHandler(read_capability))
}

/// Stored finding JSON uses snake_case keys (`file_path`, `rule_id`,
/// `start_line`); accept camelCase too for forward compatibility.
fn query_descriptor() -> Tool {
    Tool {
        name: "findings:query".to_string(),
        description: "List prior findings recorded for this target. Filter by filePath \
substring, ruleId substring, and/or minimum severity (critical|high|medium|low|info). \
Use before reporting on a file to avoid duplicating a known finding."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "filePath": {"type": "string", "description": "Substring match on the finding file path, e.g. 'execd_lib.cpp'"},
                "ruleId": {"type": "string", "description": "Substring match on the rule id"},
                "severity": {"type": "string", "description": "Minimum severity: critical, high, medium, low, or info"},
                "limit": {"type": "integer", "description": "Max rows (default 25, cap 200)"}
            }
        }),
    }
}

fn stats_descriptor() -> Tool {
    Tool {
        name: "findings:stats".to_string(),
        description: "Prior-finding counts for this target, grouped by severity and tool."
            .to_string(),
        input_schema: json!({"type": "object", "properties": {}}),
    }
}

struct QueryHandler(ReadRootCapability);
struct StatsHandler(ReadRootCapability);

#[async_trait]
impl ToolHandler for QueryHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let rows = load_latest_findings(&self.0)?;
        let filter = QueryFilter::from_args(&args)?;
        let matched: Vec<Value> = rows
            .iter()
            .filter(|finding| filter.matches(finding))
            .map(compact_finding)
            .collect();
        let total = matched.len();
        let shown: Vec<Value> = matched.into_iter().take(filter.limit).collect();
        Ok(json!({"total": total, "shown": shown.len(), "findings": shown}))
    }
}

#[async_trait]
impl ToolHandler for StatsHandler {
    async fn call(&self, _args: Value) -> Result<Value> {
        let rows = load_latest_findings(&self.0)?;
        let mut by_severity = std::collections::BTreeMap::new();
        let mut by_tool = std::collections::BTreeMap::new();
        for finding in &rows {
            *by_severity
                .entry(text_field(finding, &["severity"]).unwrap_or_else(|| "unknown".into()))
                .or_insert(0u64) += 1;
            *by_tool
                .entry(text_field(finding, &["tool"]).unwrap_or_else(|| "unknown".into()))
                .or_insert(0u64) += 1;
        }
        Ok(json!({"total": rows.len(), "bySeverity": by_severity, "byTool": by_tool}))
    }
}

struct QueryFilter {
    file_path: Option<String>,
    rule_id: Option<String>,
    min_severity: Option<u8>,
    limit: usize,
}

impl QueryFilter {
    fn from_args(args: &Value) -> Result<Self> {
        Ok(Self {
            file_path: lowercase_arg(args, "filePath"),
            rule_id: lowercase_arg(args, "ruleId"),
            min_severity: args
                .get("severity")
                .and_then(Value::as_str)
                .map(severity_rank)
                .transpose()?,
            limit: args
                .get("limit")
                .and_then(Value::as_u64)
                .map(|limit| (limit as usize).clamp(1, MAX_QUERY_LIMIT))
                .unwrap_or(DEFAULT_QUERY_LIMIT),
        })
    }

    fn matches(&self, finding: &Value) -> bool {
        self.matches_substring(finding, &["file_path", "filePath"], &self.file_path)
            && self.matches_substring(finding, &["rule_id", "ruleId"], &self.rule_id)
            && self.matches_severity(finding)
    }

    fn matches_substring(&self, finding: &Value, keys: &[&str], needle: &Option<String>) -> bool {
        let Some(needle) = needle else { return true };
        text_field(finding, keys)
            .map(|value| value.to_ascii_lowercase().contains(needle))
            .unwrap_or(false)
    }

    fn matches_severity(&self, finding: &Value) -> bool {
        let Some(minimum) = self.min_severity else {
            return true;
        };
        text_field(finding, &["severity"])
            .and_then(|value| severity_rank(&value).ok())
            .is_some_and(|rank| rank >= minimum)
    }
}

fn lowercase_arg(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
}

fn severity_rank(value: &str) -> Result<u8> {
    match value.trim().to_ascii_lowercase().as_str() {
        "critical" => Ok(5),
        "high" => Ok(4),
        "medium" => Ok(3),
        "low" => Ok(2),
        "info" => Ok(1),
        other => anyhow::bail!(
            "unsupported severity {other:?}; expected critical, high, medium, low, or info"
        ),
    }
}

fn compact_finding(finding: &Value) -> Value {
    let start_line = finding
        .get("start_line")
        .or_else(|| finding.get("startLine"))
        .cloned()
        .unwrap_or(Value::Null);
    json!({
        "fingerprint": text_field(finding, &["fingerprint"]),
        "ruleId": text_field(finding, &["rule_id", "ruleId"]),
        "severity": text_field(finding, &["severity"]),
        "filePath": text_field(finding, &["file_path", "filePath"]),
        "startLine": start_line,
        "title": text_field(finding, &["title"]),
        "tool": text_field(finding, &["tool"]),
    })
}

fn text_field(finding: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| finding.get(key).and_then(Value::as_str))
        .map(str::to_string)
}

fn load_latest_findings(read_capability: &ReadRootCapability) -> Result<Vec<Value>> {
    let path = std::env::var(ARTIFACT_ENV).with_context(|| {
        format!(
            "{ARTIFACT_ENV} is unset — the bridge should set it to the absolute path of \
             .kuzushi/v3/index.sqlite3 before attaching this MCP."
        )
    })?;
    let authorized = read_capability
        .resolve(Path::new(&path))
        .with_context(|| format!("findings DB {path} is outside the granted read roots"))?;
    let conn = Connection::open_with_flags(&authorized, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("opening findings DB at {}", authorized.display()))?;
    let mut stmt = conn.prepare(LATEST_FINDINGS_SQL)?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut findings = Vec::new();
    for row in rows {
        let raw = row.context("reading finding row")?;
        if let Ok(parsed) = serde_json::from_str::<Value>(&raw) {
            findings.push(parsed);
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn seed_db(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("index.sqlite3");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "create table finding_observations (created_seq integer primary key, finding_json text);",
        )
        .unwrap();
        for (seq, (fingerprint, file, severity)) in [
            ("fp-1", "execd_lib.cpp", "high"),
            ("fp-1", "execd_lib.cpp", "critical"),
            ("fp-2", "client_lib.cpp", "low"),
        ]
        .iter()
        .enumerate()
        {
            conn.execute(
                "insert into finding_observations (created_seq, finding_json) values (?1, ?2)",
                rusqlite::params![
                    seq as i64,
                    json!({
                        "fingerprint": fingerprint,
                        "rule_id": "cmd-injection",
                        "severity": severity,
                        "file_path": file,
                        "start_line": 42,
                        "title": "finding",
                        "tool": "agentic-sast",
                    })
                    .to_string()
                ],
            )
            .unwrap();
        }
        path
    }

    #[tokio::test]
    async fn query_serves_latest_observation_per_fingerprint_with_filters() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let db = seed_db(tmp.path());
        std::env::set_var(ARTIFACT_ENV, &db);
        let capability = ReadRootCapability::new([tmp.path().to_path_buf()]).unwrap();

        let all = QueryHandler(capability.clone())
            .call(json!({}))
            .await
            .unwrap();
        assert_eq!(all["total"], 2, "latest-per-key projection: {all}");

        let execd = QueryHandler(capability.clone())
            .call(json!({"filePath": "execd", "severity": "high"}))
            .await
            .unwrap();
        assert_eq!(execd["total"], 1);
        assert_eq!(execd["findings"][0]["severity"], "critical");

        let stats = StatsHandler(capability).call(json!({})).await.unwrap();
        assert_eq!(stats["total"], 2);
        assert_eq!(stats["bySeverity"]["critical"], 1);
        std::env::remove_var(ARTIFACT_ENV);
    }
}
