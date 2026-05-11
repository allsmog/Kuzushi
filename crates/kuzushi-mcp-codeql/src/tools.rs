//! CodeQL MCP tools — `flows_for_cwe`, `query`, `db_info`.
//!
//! Wraps `codeql database analyze` with focused selectors so an agent
//! can ask narrow per-CWE questions instead of running the full
//! 179-query security-and-quality suite. Each tool spawns codeql, waits
//! for SARIF output, parses the thread-flow paths, and returns a small
//! JSON summary the agent can reason about.
//!
//! Latency strategy: we keep two layers of caching to amortise the
//! ~60s-per-CWE pack-compile cost on cold runs.
//!
//! 1. CodeQL's own on-disk pack cache (`--common-caches=$HOME/.codeql`,
//!    or `KUZUSHI_CODEQL_CACHE_DIR` if set). Persists across MCP server
//!    restarts. First call to each CWE folder on a given language is
//!    still slow because that's when the pack is compiled.
//! 2. An in-process result memo keyed on `(db, selector, limit)`. The
//!    agent often re-queries the same CWE folder when iterating on
//!    findings during a single hunt; the second call returns instantly.
//!    Keyed on the canonical absolute DB path so a typo or symlink swap
//!    doesn't poison the cache.
//!
//! Optional: if `KUZUSHI_CODEQL_PREWARM` is set, on MCP server startup
//! we spawn a background task that compiles the common CWE folders
//! (CWE-022, CWE-078, CWE-079, CWE-089, CWE-120, CWE-190, CWE-416, CWE-918)
//! for the C/C++ pack so the first agent call is also a cache hit.
//! See `prewarm.rs`.

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::{Tool, ToolHandler, ToolRegistry};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::sync::OnceLock;

pub(crate) fn build_registry() -> ToolRegistry {
    ToolRegistry::new()
        .register(flows_for_cwe_descriptor(), FlowsForCweHandler)
        .register(db_info_descriptor(), DbInfoHandler)
        .register(query_descriptor(), QueryHandler)
}

fn flows_for_cwe_descriptor() -> Tool {
    Tool {
        name: "codeql:flows_for_cwe".to_string(),
        description: "Run CodeQL's CWE-specific query folder against a built database and return source-to-sink reaching flows. Each result has a rule, message, and a list of {file,line,code} steps from source to sink. Slow per call (the DB reloads); use it to verify or refute a specific candidate, not to enumerate every flow.".to_string(),
        input_schema: json!({
            "type": "object",
            "required": ["db", "cwe"],
            "properties": {
                "db": {"type": "string", "description": "Absolute or workspace-relative path to a built CodeQL DB (the directory containing codeql-database.yml + db-<lang>/)."},
                "cwe": {"type": "string", "description": "CWE identifier, e.g. \"CWE-89\" or \"89\"."},
                "language": {"type": "string", "description": "Optional: cpp, python, javascript, java, go, ruby, csharp. Inferred from the DB if omitted."},
                "limit": {"type": "integer", "minimum": 1, "default": 50, "description": "Cap returned flows (default 50)."}
            }
        }),
    }
}

fn db_info_descriptor() -> Tool {
    Tool {
        name: "codeql:db_info".to_string(),
        description: "Return basic metadata about a CodeQL database (language, source root, baseline counts) so the agent can decide whether running queries against it is feasible.".to_string(),
        input_schema: json!({
            "type": "object",
            "required": ["db"],
            "properties": {
                "db": {"type": "string"}
            }
        }),
    }
}

fn query_descriptor() -> Tool {
    Tool {
        name: "codeql:query".to_string(),
        description: "Run an arbitrary CodeQL query selector (e.g. `codeql/cpp-queries:Security/CWE/CWE-089/SqlTainted.ql`) against the DB and return SARIF results parsed into the same {file,line,code} shape as flows_for_cwe.".to_string(),
        input_schema: json!({
            "type": "object",
            "required": ["db", "query"],
            "properties": {
                "db": {"type": "string"},
                "query": {"type": "string", "description": "Query selector (pack:relative-path or absolute .ql path)."},
                "limit": {"type": "integer", "minimum": 1, "default": 50}
            }
        }),
    }
}

struct FlowsForCweHandler;
struct DbInfoHandler;
struct QueryHandler;

#[async_trait]
impl ToolHandler for FlowsForCweHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let db = read_required_path(&args, "db")?;
        let cwe = read_required_string(&args, "cwe")?;
        let language = args
            .get("language")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| db_language(&db));
        let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;

        let pack = language
            .as_deref()
            .and_then(query_pack_for_language)
            .context("could not infer CodeQL language pack from DB metadata or input")?;
        let folder = cwe_folder(&cwe).context("invalid CWE identifier")?;
        let selector = format!("{pack}:Security/CWE/{folder}");

        let flows = run_codeql_and_parse(&db, &selector, limit).await?;
        Ok(json!({
            "db": db.display().to_string(),
            "cwe": cwe,
            "selector": selector,
            "flow_count": flows.len(),
            "flows": flows,
        }))
    }
}

#[async_trait]
impl ToolHandler for DbInfoHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let db = read_required_path(&args, "db")?;
        let yaml_path = db.join("codeql-database.yml");
        let metadata = std::fs::read_to_string(&yaml_path)
            .with_context(|| format!("could not read {}", yaml_path.display()))?;
        Ok(json!({
            "db": db.display().to_string(),
            "language": db_language(&db),
            "metadata_excerpt": metadata.chars().take(800).collect::<String>(),
            "exists": db.is_dir(),
        }))
    }
}

#[async_trait]
impl ToolHandler for QueryHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let db = read_required_path(&args, "db")?;
        let query = read_required_string(&args, "query")?;
        let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
        let flows = run_codeql_and_parse(&db, &query, limit).await?;
        Ok(json!({
            "db": db.display().to_string(),
            "query": query,
            "flow_count": flows.len(),
            "flows": flows,
        }))
    }
}

/// (db_canonical, selector, limit) → memoised flow set, populated on the
/// first call of each combo and reused for the rest of the MCP server's
/// lifetime. The memo is bounded by the agent's appetite for distinct
/// queries (~10 per hunt in practice), so we don't bother with eviction.
fn flow_memo() -> &'static Mutex<HashMap<(PathBuf, String, usize), Vec<Value>>> {
    static MEMO: OnceLock<Mutex<HashMap<(PathBuf, String, usize), Vec<Value>>>> = OnceLock::new();
    MEMO.get_or_init(|| Mutex::new(HashMap::new()))
}

fn memo_key(db: &Path, selector: &str, limit: usize) -> (PathBuf, String, usize) {
    let canonical = std::fs::canonicalize(db).unwrap_or_else(|_| db.to_path_buf());
    (canonical, selector.to_string(), limit)
}

fn lookup_memo(db: &Path, selector: &str, limit: usize) -> Option<Vec<Value>> {
    let memo = flow_memo().lock().ok()?;
    memo.get(&memo_key(db, selector, limit)).cloned()
}

fn store_memo(db: &Path, selector: &str, limit: usize, flows: &[Value]) {
    if let Ok(mut memo) = flow_memo().lock() {
        memo.insert(memo_key(db, selector, limit), flows.to_vec());
    }
}

/// Resolve the CodeQL pack cache directory. CodeQL defaults to
/// `$HOME/.codeql` and creates it on demand; we honor an explicit
/// override via `KUZUSHI_CODEQL_CACHE_DIR` so operators with shared
/// cache volumes (CI, multi-tenant boxes) can point all kuzushi
/// invocations at the same disk.
pub(crate) fn codeql_cache_dir() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("KUZUSHI_CODEQL_CACHE_DIR") {
        let candidate = PathBuf::from(value);
        if !candidate.as_os_str().is_empty() {
            return Some(candidate);
        }
    }
    None
}

async fn run_codeql_and_parse(db: &Path, selector: &str, limit: usize) -> Result<Vec<Value>> {
    if let Some(cached) = lookup_memo(db, selector, limit) {
        return Ok(cached);
    }
    let codeql = locate_codeql_binary().context("could not find the codeql binary")?;
    let sarif = tempfile::NamedTempFile::new()?;
    let mut command = Command::new(&codeql);
    command
        .arg("database")
        .arg("analyze")
        .arg("--format=sarif-latest")
        .arg("--output")
        .arg(sarif.path())
        .arg("--ram=4096")
        .arg("--threads=4");
    if let Some(cache) = codeql_cache_dir() {
        command.arg(format!("--common-caches={}", cache.display()));
    }
    command
        .arg(db)
        .arg(selector)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let status = command
        .status()
        .with_context(|| format!("could not invoke {}", codeql.display()))?;
    if !status.success() {
        anyhow::bail!("codeql database analyze exited with {status}");
    }
    let raw = std::fs::read_to_string(sarif.path()).context("could not read SARIF output")?;
    let flows = parse_sarif(&raw, limit);
    store_memo(db, selector, limit, &flows);
    Ok(flows)
}

fn parse_sarif(raw: &str, limit: usize) -> Vec<Value> {
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    let Some(runs) = value.get("runs").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for run in runs {
        let Some(results) = run.get("results").and_then(Value::as_array) else {
            continue;
        };
        for result in results {
            if out.len() >= limit {
                return out;
            }
            let rule_id = result
                .get("ruleId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let message = result
                .pointer("/message/text")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let steps = sarif_thread_flow_steps(result).unwrap_or_else(|| {
                result
                    .get("locations")
                    .and_then(Value::as_array)
                    .map(|locs| locs.iter().filter_map(sarif_step).collect())
                    .unwrap_or_default()
            });
            if steps.is_empty() {
                continue;
            }
            let first = steps.first().cloned().unwrap_or(Value::Null);
            let last = steps.last().cloned().unwrap_or(Value::Null);
            out.push(json!({
                "rule": rule_id,
                "message": message,
                "source": first,
                "sink": last,
                "steps": steps,
            }));
        }
    }
    out
}

fn sarif_thread_flow_steps(result: &Value) -> Option<Vec<Value>> {
    let code_flows = result.get("codeFlows").and_then(Value::as_array)?;
    let first_flow = code_flows.first()?;
    let thread_flows = first_flow.get("threadFlows").and_then(Value::as_array)?;
    let first_thread = thread_flows.first()?;
    let locations = first_thread.get("locations").and_then(Value::as_array)?;
    let steps: Vec<Value> = locations
        .iter()
        .filter_map(|loc| sarif_step(loc.get("location").unwrap_or(loc)))
        .collect();
    if steps.is_empty() {
        None
    } else {
        Some(steps)
    }
}

fn sarif_step(location: &Value) -> Option<Value> {
    let physical = location.get("physicalLocation")?;
    let file = physical
        .pointer("/artifactLocation/uri")
        .and_then(Value::as_str)?
        .to_string();
    let line = physical
        .pointer("/region/startLine")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let snippet = physical
        .pointer("/region/snippet/text")
        .and_then(Value::as_str)
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    Some(json!({"file": file, "line": line, "code": snippet}))
}

/// Compile common CWE query folders for each installed language pack so
/// the agent's first `flows_for_cwe` call hits the codeql pack cache
/// instead of paying a 60s+ cold compile. Runs as a detached background
/// task; failures are logged to stderr and ignored — pre-warm is an
/// optimisation, not a correctness gate.
pub(crate) async fn spawn_prewarm() {
    const COMMON_CWES: &[&str] = &[
        "CWE-022", "CWE-078", "CWE-079", "CWE-089", "CWE-120", "CWE-190", "CWE-416", "CWE-918",
    ];
    const PACKS: &[&str] = &[
        "codeql/cpp-queries",
        "codeql/python-queries",
        "codeql/javascript-queries",
        "codeql/java-queries",
        "codeql/go-queries",
    ];
    let Some(codeql) = locate_codeql_binary() else {
        eprintln!("[kuzushi-mcp-codeql] prewarm skipped: codeql binary not found");
        return;
    };
    eprintln!(
        "[kuzushi-mcp-codeql] prewarm: compiling {} pack/CWE pairs in background",
        PACKS.len() * COMMON_CWES.len()
    );
    for pack in PACKS {
        for cwe in COMMON_CWES {
            let selector = format!("{pack}:Security/CWE/{cwe}");
            let mut command = Command::new(&codeql);
            command.arg("query").arg("compile").arg(&selector);
            if let Some(cache) = codeql_cache_dir() {
                command.arg(format!("--common-caches={}", cache.display()));
            }
            let outcome = command
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            match outcome {
                Ok(status) if status.success() => {
                    eprintln!("[kuzushi-mcp-codeql] prewarm ok: {selector}");
                }
                Ok(status) => {
                    eprintln!("[kuzushi-mcp-codeql] prewarm skipped (exit {status}): {selector}");
                }
                Err(err) => {
                    eprintln!("[kuzushi-mcp-codeql] prewarm error: {selector}: {err}");
                }
            }
            tokio::task::yield_now().await;
        }
    }
    eprintln!("[kuzushi-mcp-codeql] prewarm: complete");
}

fn locate_codeql_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("KUZUSHI_CODEQL_BIN") {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    for candidate in [
        PathBuf::from("/opt/codeql/codeql/codeql"),
        PathBuf::from("/usr/local/bin/codeql"),
        PathBuf::from("/usr/bin/codeql"),
    ] {
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn db_language(db: &Path) -> Option<String> {
    let yaml = std::fs::read_to_string(db.join("codeql-database.yml")).ok()?;
    for line in yaml.lines() {
        if let Some(rest) = line.strip_prefix("primaryLanguage:") {
            let trimmed = rest.trim().trim_matches('"').to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

fn query_pack_for_language(language: &str) -> Option<&'static str> {
    match language.trim().to_lowercase().as_str() {
        "cpp" | "c" | "c-cpp" => Some("codeql/cpp-queries"),
        "python" => Some("codeql/python-queries"),
        "javascript" | "typescript" | "javascript-typescript" => Some("codeql/javascript-queries"),
        "java" | "kotlin" | "java-kotlin" => Some("codeql/java-queries"),
        "go" => Some("codeql/go-queries"),
        "ruby" => Some("codeql/ruby-queries"),
        "csharp" => Some("codeql/csharp-queries"),
        _ => None,
    }
}

fn cwe_folder(cwe: &str) -> Option<String> {
    let stripped = cwe
        .trim()
        .strip_prefix("CWE-")
        .or_else(|| cwe.trim().strip_prefix("cwe-"))
        .unwrap_or(cwe.trim());
    let number: u32 = stripped.parse().ok()?;
    Some(format!("CWE-{:03}", number))
}

fn read_required_string(args: &Value, field: &str) -> Result<String> {
    args.get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .with_context(|| format!("missing required string field `{field}`"))
}

fn read_required_path(args: &Value, field: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(read_required_string(args, field)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cwe_folder_pads_three_digits() {
        assert_eq!(cwe_folder("CWE-89"), Some("CWE-089".to_string()));
        assert_eq!(cwe_folder("89"), Some("CWE-089".to_string()));
        assert_eq!(cwe_folder("CWE-1078"), Some("CWE-1078".to_string()));
        assert!(cwe_folder("not-a-cwe").is_none());
    }

    #[test]
    fn parse_sarif_extracts_thread_flow_path() {
        let sarif = r#"{
            "runs": [{
                "tool": {"driver": {"rules": []}},
                "results": [{
                    "ruleId": "cpp/path-injection",
                    "message": {"text": "path traversal"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/io.c"},
                            "region": {"startLine": 99, "snippet": {"text": "open(name);"}}
                        }
                    }],
                    "codeFlows": [{
                        "threadFlows": [{
                            "locations": [
                                {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/api.c"}, "region": {"startLine": 10, "snippet": {"text": "name = arg"}}}}},
                                {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/io.c"}, "region": {"startLine": 99, "snippet": {"text": "open(name);"}}}}}
                            ]
                        }]
                    }]
                }]
            }]
        }"#;
        let flows = parse_sarif(sarif, 50);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0]["rule"], json!("cpp/path-injection"));
        assert_eq!(flows[0]["steps"].as_array().unwrap().len(), 2);
        assert_eq!(flows[0]["source"]["line"], json!(10));
        assert_eq!(flows[0]["sink"]["line"], json!(99));
    }

    #[test]
    fn query_pack_for_language_picks_cpp_for_aliases() {
        assert_eq!(query_pack_for_language("c"), Some("codeql/cpp-queries"));
        assert_eq!(query_pack_for_language("cpp"), Some("codeql/cpp-queries"));
        assert_eq!(query_pack_for_language("c-cpp"), Some("codeql/cpp-queries"));
        assert_eq!(
            query_pack_for_language("python"),
            Some("codeql/python-queries")
        );
        assert!(query_pack_for_language("rust").is_none());
    }
}
