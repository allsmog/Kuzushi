//! CodeQL MCP tools — `flows_for_cwe`, `query`, `db_info`.
//!
//! Wraps `codeql database analyze` with focused selectors so an agent
//! can ask narrow per-CWE questions instead of running the full
//! 179-query security-and-quality suite. Analysis cache misses spawn CodeQL,
//! wait for SARIF output, parse the thread-flow paths, and return a small JSON
//! summary the agent can reason about. `db_info` and eligible memo hits do not
//! spawn CodeQL.
//!
//! Latency strategy: we use two independent mechanisms to reduce CodeQL work.
//!
//! 1. CodeQL's own on-disk pack cache (`--common-caches=$HOME/.codeql`,
//!    or `KUZUSHI_CODEQL_CACHE_DIR` if set). Persists across MCP server
//!    restarts. First call to each CWE folder on a given language is
//!    still slow because that's when the pack is compiled.
//! 2. A bounded in-process result memo keyed on content-authenticated
//!    database-tree revision,
//!    dependency-free local selector revision, CodeQL executable revision,
//!    and result limit. Pack selectors bypass the memo. Imported local queries
//!    are rejected because their complete dependency graph cannot be
//!    authenticated without executing CodeQL's resolver. Database identity uses the same
//!    bounded content tree as the promotion receipt; databases outside those
//!    bounds fail closed before CodeQL executes. A memo hit skips CodeQL
//!    execution only after the complete database tree has been authenticated,
//!    so its latency remains proportional to database size.
//!    Keyed on the canonical absolute DB path so a typo or symlink swap
//!    doesn't poison the cache.
//! On the first execution for a CodeQL bundle revision, the complete bundle is
//! copied into an authenticated operator-owned snapshot. The authenticated
//! database is copied into a separate receipt-bound snapshot. Analysis and
//! prewarm execute only sandboxed snapshot paths; later calls reuse the
//! one-entry bundle/database caches while full source identities remain part
//! of per-request authentication. Abandoned server-session roots are reclaimed
//! under a cross-process owner lock at startup.
//!
//! Optional: if `KUZUSHI_CODEQL_PREWARM` is set, on MCP server startup
//! we spawn a background task that compiles the common CWE folders
//! (CWE-022, CWE-078, CWE-079, CWE-089, CWE-120, CWE-190, CWE-416, CWE-918)
//! for the C/C++ pack so the first agent call avoids a cold pack compile.
//! Database content authentication still runs.
//! See `prewarm.rs`.

use anyhow::{Context, Result};
use async_trait::async_trait;
use kuzushi_mcp_common::{
    bounded_bundle_identity, resolve_codeql_bundle_root, BundleIdentityConfig, ReadRootCapability,
    Tool, ToolHandler, ToolRegistry,
};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

mod snapshot_store;
use snapshot_store::{CodeqlExecutionSnapshot, CodeqlSnapshotStore, DatabaseExecutionSnapshot};

const DEFAULT_RESULT_LIMIT: usize = 50;
const MAX_RESULT_LIMIT: usize = 500;
const MAX_DATABASE_METADATA_BYTES: usize = 1024 * 1024;
const MAX_LOCAL_QUERY_BYTES: usize = 4 * 1024 * 1024;
const MAX_SARIF_BYTES: usize = 64 * 1024 * 1024;
const MAX_MEMO_ENTRIES: usize = 64;
const MAX_MEMO_BYTES: usize = 16 * 1024 * 1024;
const MAX_CODEQL_BUNDLE_ENTRIES: u64 = 500_000;
const MAX_CODEQL_BUNDLE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_CODEQL_BUNDLE_DEPTH: usize = 128;
const CODEQL_BUNDLE_CONFIG: BundleIdentityConfig = BundleIdentityConfig::new(
    b"kuzushi-codeql-external-bundle-v1\0",
    "CodeQL executable bundle",
    MAX_CODEQL_BUNDLE_ENTRIES,
    MAX_CODEQL_BUNDLE_BYTES,
    MAX_CODEQL_BUNDLE_DEPTH,
);
const CODEQL_ARTIFACT_ENV: &str = "KUZUSHI_MCP_CODEQL_ARTIFACT";
const CODEQL_ARTIFACT_IDENTITY_ENV: &str = "KUZUSHI_MCP_CODEQL_ARTIFACT_IDENTITY";

pub(crate) struct CodeqlRuntime {
    snapshots: CodeqlSnapshotStore,
}

impl CodeqlRuntime {
    fn new() -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            snapshots: CodeqlSnapshotStore::new()?,
        }))
    }

    pub(crate) fn cancel(&self) {
        self.snapshots.cancel_all();
    }
}

pub(crate) fn build_runtime_and_registry() -> Result<(Arc<CodeqlRuntime>, ToolRegistry)> {
    let runtime = CodeqlRuntime::new()?;
    let registry = build_registry_with_capability(
        ReadRootCapability::from_environment()?,
        Arc::clone(&runtime),
    );
    Ok((runtime, registry))
}

fn build_registry_with_capability(
    read_capability: ReadRootCapability,
    runtime: Arc<CodeqlRuntime>,
) -> ToolRegistry {
    ToolRegistry::new()
        .register(
            flows_for_cwe_descriptor(),
            FlowsForCweHandler(read_capability.clone(), Arc::clone(&runtime)),
        )
        .register(db_info_descriptor(), DbInfoHandler(read_capability.clone()))
        .register(query_descriptor(), QueryHandler(read_capability, runtime))
}

fn flows_for_cwe_descriptor() -> Tool {
    Tool {
        name: "codeql:flows_for_cwe".to_string(),
        description: "Run CodeQL's CWE-specific query folder against a built database and return source-to-sink reaching flows. Each result has a rule, message, and a list of {file,line,code} steps from source to sink. CWE pack selectors bypass the result memo. Every call performs full database content authentication, so authentication latency is proportional to database size; use this tool to verify or refute a specific candidate, not to enumerate every flow.".to_string(),
        input_schema: json!({
            "type": "object",
            "required": ["db", "cwe"],
            "properties": {
                "db": {"type": "string", "description": "Absolute or workspace-relative path to a built CodeQL DB (the directory containing codeql-database.yml + db-<lang>/)."},
                "cwe": {"type": "string", "description": "CWE identifier, e.g. \"CWE-89\" or \"89\"."},
                "language": {"type": "string", "description": "Optional: cpp, python, javascript, java, go, ruby, csharp. Inferred from the DB if omitted."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50, "description": "Cap returned flows (default 50, maximum 500)."}
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
        description: "Run an arbitrary CodeQL query selector (e.g. `codeql/cpp-queries:Security/CWE/CWE-089/SqlTainted.ql`) against the DB and return SARIF results parsed into the same {file,line,code} shape as flows_for_cwe. An eligible dependency-free local query may use the in-process result memo; a memo hit skips CodeQL execution but still performs full database content authentication, so authentication latency remains proportional to database size. Pack selectors bypass the result memo. Local queries with imports are rejected because their dependency closure cannot be authenticated.".to_string(),
        input_schema: json!({
            "type": "object",
            "required": ["db", "query"],
            "properties": {
                "db": {"type": "string"},
                "query": {"type": "string", "description": "Query selector (pack:relative-path or absolute .ql path)."},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50}
            }
        }),
    }
}

struct FlowsForCweHandler(ReadRootCapability, Arc<CodeqlRuntime>);
struct DbInfoHandler(ReadRootCapability);
struct QueryHandler(ReadRootCapability, Arc<CodeqlRuntime>);

#[async_trait]
impl ToolHandler for FlowsForCweHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let db = authorized_database(&self.0, &args)?;
        let cwe = read_required_string(&args, "cwe")?;
        let language = requested_or_database_language(&self.0, &db, &args)?;
        let limit = result_limit(&args);

        let pack = language
            .as_deref()
            .and_then(query_pack_for_language)
            .context("could not infer CodeQL language pack from DB metadata or input")?;
        let folder = cwe_folder(&cwe).context("invalid CWE identifier")?;
        let selector = format!("{pack}:Security/CWE/{folder}");

        let flows =
            run_codeql_and_parse_with_runtime(&self.1, &self.0, &db, &selector, limit).await?;
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
        let db = authorized_database(&self.0, &args)?;
        validate_planned_database_if_present(&db)?;
        let metadata = database_metadata(&self.0, &db)?;
        Ok(json!({
            "db": db.display().to_string(),
            "language": language_from_database_metadata(&metadata),
            "metadata_excerpt": metadata.chars().take(800).collect::<String>(),
            "exists": db.is_dir(),
        }))
    }
}

#[async_trait]
impl ToolHandler for QueryHandler {
    async fn call(&self, args: Value) -> Result<Value> {
        let db = authorized_database(&self.0, &args)?;
        let query = authorized_query_selector(&self.0, &args)?;
        let limit = result_limit(&args);
        let flows = run_codeql_and_parse_with_runtime(&self.1, &self.0, &db, &query, limit).await?;
        Ok(json!({
            "db": db.display().to_string(),
            "query": query,
            "flow_count": flows.len(),
            "flows": flows,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MemoKey {
    db: PathBuf,
    db_revision: String,
    selector: String,
    selector_revision: String,
    codeql: PathBuf,
    codeql_revision: String,
    limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AnalysisIdentity {
    db: PathBuf,
    db_revision: String,
    codeql: PathBuf,
    codeql_revision: String,
}

struct MemoEntry {
    flows: Vec<Value>,
    bytes: usize,
}

struct FlowMemo {
    entries: HashMap<MemoKey, MemoEntry>,
    order: VecDeque<MemoKey>,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
}

impl FlowMemo {
    fn bounded(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            max_entries,
            max_bytes,
        }
    }

    fn get(&self, key: &MemoKey) -> Option<Vec<Value>> {
        self.entries.get(key).map(|entry| entry.flows.clone())
    }

    fn insert(&mut self, key: MemoKey, flows: &[Value]) {
        let Some(bytes) = serialized_flow_bytes(flows) else {
            return;
        };
        if bytes > self.max_bytes || self.max_entries == 0 {
            return;
        }
        self.remove(&key);
        while self.entries.len() >= self.max_entries || self.bytes + bytes > self.max_bytes {
            self.evict_oldest();
        }
        self.bytes += bytes;
        self.order.push_back(key.clone());
        self.entries.insert(
            key,
            MemoEntry {
                flows: flows.to_vec(),
                bytes,
            },
        );
    }

    fn remove(&mut self, key: &MemoKey) {
        let Some(entry) = self.entries.remove(key) else {
            return;
        };
        self.bytes = self.bytes.saturating_sub(entry.bytes);
        self.order.retain(|candidate| candidate != key);
    }

    fn evict_oldest(&mut self) {
        while let Some(key) = self.order.pop_front() {
            let Some(entry) = self.entries.remove(&key) else {
                continue;
            };
            self.bytes = self.bytes.saturating_sub(entry.bytes);
            return;
        }
    }
}

fn flow_memo() -> &'static Mutex<FlowMemo> {
    static MEMO: OnceLock<Mutex<FlowMemo>> = OnceLock::new();
    MEMO.get_or_init(|| Mutex::new(FlowMemo::bounded(MAX_MEMO_ENTRIES, MAX_MEMO_BYTES)))
}

#[cfg(test)]
fn memo_key(db: &Path, selector: &str, limit: usize, codeql: &Path) -> Option<MemoKey> {
    let identity = analysis_identity(db, codeql).ok()?;
    memo_key_from_identity(&identity, selector, limit)
}

fn analysis_identity(db: &Path, codeql: &Path) -> Result<AnalysisIdentity> {
    let db = std::fs::canonicalize(db)?;
    let codeql = std::fs::canonicalize(codeql)?;
    Ok(AnalysisIdentity {
        db_revision: authenticated_database_identity(&db)?,
        codeql_revision: codeql_revision(&codeql)?,
        codeql,
        db,
    })
}

// Recompute this identity for every request, including memo lookups. The MCP
// attachment is a mutable filesystem path plus an expected digest, not an
// immutable server-lifetime snapshot, so metadata cannot authenticate content.
fn authenticated_database_identity(db: &Path) -> Result<String> {
    let actual = crate::database_identity::database_identity(db)?;
    let artifact = std::env::var_os(CODEQL_ARTIFACT_ENV);
    let expected = std::env::var_os(CODEQL_ARTIFACT_IDENTITY_ENV);
    validate_planned_database_identity(db, &actual, artifact, expected)?;
    Ok(actual)
}

fn validate_planned_database_if_present(db: &Path) -> Result<()> {
    let artifact = std::env::var_os(CODEQL_ARTIFACT_ENV);
    let expected = std::env::var_os(CODEQL_ARTIFACT_IDENTITY_ENV);
    if artifact.is_none() && expected.is_none() {
        return Ok(());
    }
    let actual = crate::database_identity::database_identity(db)?;
    validate_planned_database_identity(db, &actual, artifact, expected)
}

fn validate_planned_database_identity(
    db: &Path,
    actual: &str,
    artifact: Option<std::ffi::OsString>,
    expected: Option<std::ffi::OsString>,
) -> Result<()> {
    let (artifact, expected) = match (artifact, expected) {
        (None, None) => return Ok(()),
        (Some(artifact), Some(expected)) => (artifact, expected),
        _ => anyhow::bail!(
            "planned CodeQL attachment is missing its authenticated artifact identity"
        ),
    };
    let artifact = std::fs::canonicalize(PathBuf::from(artifact))?;
    anyhow::ensure!(
        artifact == std::fs::canonicalize(db)?,
        "CodeQL request database does not match the planned managed attachment"
    );
    let expected = expected
        .to_str()
        .filter(|identity| valid_blake3_identity(identity))
        .context("planned CodeQL attachment identity is malformed")?;
    anyhow::ensure!(
        actual == expected,
        "managed CodeQL database does not match the planned attachment identity"
    );
    Ok(())
}

fn valid_blake3_identity(identity: &str) -> bool {
    identity.len() == 64
        && identity
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn memo_key_from_identity(
    identity: &AnalysisIdentity,
    selector: &str,
    limit: usize,
) -> Option<MemoKey> {
    Some(MemoKey {
        db_revision: identity.db_revision.clone(),
        selector_revision: local_query_revision(selector).ok()??,
        codeql_revision: identity.codeql_revision.clone(),
        codeql: identity.codeql.clone(),
        db: identity.db.clone(),
        selector: selector.to_string(),
        limit,
    })
}

fn lookup_memo(key: &MemoKey) -> Option<Vec<Value>> {
    let memo = flow_memo().lock().ok()?;
    memo.get(key)
}

fn store_memo(key: MemoKey, flows: &[Value]) {
    if let Ok(mut memo) = flow_memo().lock() {
        memo.insert(key, flows);
    }
}

fn local_query_revision(selector: &str) -> Result<Option<String>> {
    if is_pack_selector(selector) {
        return Ok(None);
    }
    let path = Path::new(selector);
    let parent = path.parent().context("local CodeQL query has no parent")?;
    let query =
        ReadRootCapability::new([parent.to_path_buf()])?.read_utf8(path, MAX_LOCAL_QUERY_BYTES)?;
    if local_query_has_imports(&query) {
        return Ok(None);
    }
    Ok(Some(kuzushi_mcp_common::cache::sha256_hex_bytes(
        query.as_bytes(),
    )))
}

fn local_query_has_imports(query: &str) -> bool {
    query
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .any(|token| token == "import")
}

fn codeql_revision(codeql: &Path) -> Result<String> {
    anyhow::ensure!(codeql.is_file(), "CodeQL executable is not a regular file");
    let bundle = resolve_codeql_bundle_root(codeql)?;
    bounded_bundle_identity(&bundle, CODEQL_BUNDLE_CONFIG)
}

fn serialized_flow_bytes(flows: &[Value]) -> Option<usize> {
    serde_json::to_vec(flows).ok().map(|encoded| encoded.len())
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

async fn run_codeql_and_parse_with_runtime(
    runtime: &CodeqlRuntime,
    read_capability: &ReadRootCapability,
    db: &Path,
    selector: &str,
    limit: usize,
) -> Result<Vec<Value>> {
    let plan = prepare_analysis(runtime, read_capability, db, selector, limit).await?;
    let prepared = match plan {
        AnalysisPlan::Cached(flows) => return Ok(flows),
        AnalysisPlan::Execute(prepared) => prepared,
    };
    let flows = execute_prepared_analysis(&prepared, limit).await?;
    authenticate_and_store_current_result(
        db,
        selector,
        limit,
        &prepared.codeql,
        prepared.identity,
        prepared.key,
        &flows,
    )?;
    Ok(flows)
}

enum AnalysisPlan {
    Cached(Vec<Value>),
    Execute(PreparedAnalysis),
}

struct PreparedAnalysis {
    codeql: PathBuf,
    identity: AnalysisIdentity,
    key: Option<MemoKey>,
    execution: CodeqlExecutionSnapshot,
    inputs: ExecutionInputs,
}

async fn prepare_analysis(
    runtime: &CodeqlRuntime,
    read_capability: &ReadRootCapability,
    db: &Path,
    selector: &str,
    limit: usize,
) -> Result<AnalysisPlan> {
    let configured = locate_codeql_binary()?.context("could not find the codeql binary")?;
    let codeql = std::fs::canonicalize(&configured)
        .with_context(|| format!("could not canonicalize {}", configured.display()))?;
    let identity = analysis_identity(db, &codeql)
        .context("could not authenticate CodeQL database and executable before analysis")?;
    let key = memo_key_from_identity(&identity, selector, limit);
    if let Some(cached) = key.as_ref().and_then(lookup_memo) {
        return Ok(AnalysisPlan::Cached(cached));
    }
    let execution = runtime
        .snapshots
        .authenticated(&identity.codeql, &identity.codeql_revision)
        .await
        .context("could not prepare authenticated CodeQL execution snapshot")?;
    let inputs = snapshot_execution_inputs(
        &runtime.snapshots,
        read_capability,
        db,
        selector,
        &identity.db_revision,
        key.as_ref().map(|key| key.selector_revision.as_str()),
    )
    .await?;
    Ok(AnalysisPlan::Execute(PreparedAnalysis {
        codeql,
        identity,
        key,
        execution,
        inputs,
    }))
}

async fn execute_prepared_analysis(
    prepared: &PreparedAnalysis,
    limit: usize,
) -> Result<Vec<Value>> {
    let run = prepared.inputs.db.temporary_directory("run-")?;
    let cache = effective_codeql_cache_dir()?;
    let sarif = run.path().join("result.sarif");
    let logs = run.path().join("logs");
    std::fs::create_dir(&logs)?;
    let args = codeql_analyze_args(
        &prepared.inputs.db.directory,
        &prepared.inputs.selector,
        &sarif,
        &logs,
        Some(&cache),
    );
    let access = analysis_sandbox_access(&prepared.execution, &prepared.inputs, &run, &cache)?;
    let mut sandboxed = kuzushi_mcp_common::read_only_sandbox::restricted_command(
        &prepared.execution.launcher,
        args,
        access,
    )
    .await
    .context("CodeQL analysis requires an available read-only sandbox")?;
    silence_sandboxed_command(&mut sandboxed)?;
    let (mut child, _scratch) = sandboxed.spawn("CodeQL analysis")?;
    let status = wait_for_analysis(&mut child, &prepared.execution, &prepared.inputs.db).await?;
    anyhow::ensure!(
        status.success(),
        "codeql database analyze exited with {status}"
    );
    Ok(parse_sarif(&read_generated_sarif(&sarif)?, limit))
}

fn silence_sandboxed_command(
    sandboxed: &mut kuzushi_mcp_common::read_only_sandbox::SandboxedCommand,
) -> Result<()> {
    sandboxed
        .command_mut()?
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    Ok(())
}

async fn wait_for_analysis(
    child: &mut tokio::process::Child,
    execution: &CodeqlExecutionSnapshot,
    database: &DatabaseExecutionSnapshot,
) -> Result<std::process::ExitStatus> {
    let status = tokio::select! {
        result = child.wait() => result?,
        () = execution.cancelled() => {
            kuzushi_mcp_common::read_only_sandbox::terminate_child_group(child).await;
            anyhow::bail!("CodeQL execution snapshot became stale during analysis");
        }
        () = database.cancelled() => {
            kuzushi_mcp_common::read_only_sandbox::terminate_child_group(child).await;
            anyhow::bail!("CodeQL database snapshot became stale during analysis");
        }
    };
    Ok(status)
}

#[cfg(test)]
async fn run_codeql_and_parse(db: &Path, selector: &str, limit: usize) -> Result<Vec<Value>> {
    let runtime = CodeqlRuntime::new()?;
    let capability = ReadRootCapability::new([db.parent().unwrap_or(db).to_path_buf()])?;
    run_codeql_and_parse_with_runtime(&runtime, &capability, db, selector, limit).await
}

fn codeql_analyze_args(
    db: &Path,
    selector: &str,
    sarif: &Path,
    log_dir: &Path,
    cache_dir: Option<&Path>,
) -> Vec<OsString> {
    let mut args = vec![
        "database".into(),
        "analyze".into(),
        "--format=sarif-latest".into(),
        "--rerun".into(),
        "--max-disk-cache=0".into(),
        "--expect-discarded-cache".into(),
        format!("--logdir={}", log_dir.display()).into(),
        "--output".into(),
        sarif.as_os_str().to_owned(),
        "--ram=4096".into(),
        "--threads=4".into(),
    ];
    if let Some(cache) = cache_dir {
        args.push(format!("--common-caches={}", cache.display()).into());
    }
    args.push(db.as_os_str().to_owned());
    args.push(selector.into());
    args
}

struct ExecutionInputs {
    db: DatabaseExecutionSnapshot,
    query: Option<tempfile::TempDir>,
    selector: String,
}

async fn snapshot_execution_inputs(
    snapshots: &CodeqlSnapshotStore,
    read_capability: &ReadRootCapability,
    db: &Path,
    selector: &str,
    expected_db_revision: &str,
    expected_selector_revision: Option<&str>,
) -> Result<ExecutionInputs> {
    let database = snapshots.database(db, expected_db_revision).await?;
    let read_capability = read_capability.clone();
    let selector = selector.to_string();
    let expected_selector_revision = expected_selector_revision.map(str::to_string);
    let query_directory = Path::new(&selector)
        .is_absolute()
        .then(|| database.temporary_directory("query-"))
        .transpose()?;
    let (query, selector) = tokio::task::spawn_blocking(move || {
        snapshot_local_query(
            &read_capability,
            selector,
            expected_selector_revision,
            query_directory,
        )
    })
    .await
    .context("CodeQL input snapshot worker stopped")??;
    Ok(ExecutionInputs {
        db: database,
        query,
        selector,
    })
}

fn snapshot_local_query(
    read_capability: &ReadRootCapability,
    selector: String,
    expected_revision: Option<String>,
    query: Option<tempfile::TempDir>,
) -> Result<(Option<tempfile::TempDir>, String)> {
    let query_path = Path::new(&selector);
    if !query_path.is_absolute() {
        return Ok((None, selector));
    }
    let file = query_path
        .file_name()
        .context("local query has no file name")?;
    let expected = expected_revision
        .context("local query has unresolved imports and cannot be snapshotted safely")?;
    let bytes = read_capability
        .open_strict(query_path, MAX_LOCAL_QUERY_BYTES)?
        .read_bytes()?;
    let actual = kuzushi_mcp_common::cache::sha256_hex_bytes(&bytes);
    anyhow::ensure!(
        actual == expected,
        "local CodeQL query changed while creating its execution snapshot"
    );
    let query = query.context("local query snapshot directory is unavailable")?;
    std::fs::write(query.path().join(file), bytes)?;
    let selector = query.path().join(file).display().to_string();
    Ok((Some(query), selector))
}

fn effective_codeql_cache_dir() -> Result<PathBuf> {
    let cache = codeql_cache_dir()
        .or_else(|| dirs::home_dir().map(|home| home.join(".codeql")))
        .context("could not resolve the CodeQL common cache directory")?;
    std::fs::create_dir_all(&cache)?;
    std::fs::canonicalize(&cache)
        .with_context(|| format!("could not resolve CodeQL cache {}", cache.display()))
}

fn analysis_sandbox_access(
    execution: &CodeqlExecutionSnapshot,
    inputs: &ExecutionInputs,
    run: &tempfile::TempDir,
    cache: &Path,
) -> Result<kuzushi_mcp_common::read_only_sandbox::RestrictedSandboxAccess> {
    let tool = authorize_directory(&execution.bundle_root)?;
    let database = authorize_directory(&inputs.db.directory)?;
    let read_only = inputs
        .query
        .as_ref()
        .map(|query| authorize_directory(query.path()))
        .transpose()?
        .into_iter()
        .collect();
    Ok(
        kuzushi_mcp_common::read_only_sandbox::RestrictedSandboxAccess {
            working_directory: database,
            tool_root: tool,
            read_only,
            read_write: vec![
                authorize_directory(run.path())?,
                authorize_directory(cache)?,
            ],
            environment: vec![(
                "CODEQL_DIST".into(),
                execution.bundle_root.as_os_str().to_owned(),
            )],
        },
    )
}

fn authorize_directory(path: &Path) -> Result<kuzushi_mcp_common::AuthorizedDirectory> {
    ReadRootCapability::new([path.to_path_buf()])?.authorize_directory(path)
}

fn authenticate_and_store_current_result(
    db: &Path,
    selector: &str,
    limit: usize,
    codeql: &Path,
    identity: AnalysisIdentity,
    key: Option<MemoKey>,
    flows: &[Value],
) -> Result<()> {
    let current = analysis_identity(db, codeql).context(
        "CodeQL database or executable changed during analysis; rejecting unauthenticated output",
    )?;
    anyhow::ensure!(
        current == identity,
        "CodeQL database, query, or executable changed during analysis; rejecting unauthenticated output"
    );
    authenticate_and_store_memo(&current, selector, limit, key, flows)
}

fn authenticate_and_store_memo(
    identity: &AnalysisIdentity,
    selector: &str,
    limit: usize,
    key: Option<MemoKey>,
    flows: &[Value],
) -> Result<()> {
    let Some(key) = key else {
        return Ok(());
    };
    let current = memo_key_from_identity(identity, selector, limit);
    anyhow::ensure!(
        current.as_ref() == Some(&key),
        "CodeQL database, query, or executable changed during analysis; rejecting unauthenticated output"
    );
    store_memo(key, flows);
    Ok(())
}

fn read_generated_sarif(path: &Path) -> Result<String> {
    let parent = path.parent().context("SARIF output path has no parent")?;
    ReadRootCapability::new([parent.to_path_buf()])?
        .read_utf8(path, MAX_SARIF_BYTES)
        .context("could not read SARIF output")
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
pub(crate) async fn spawn_prewarm(runtime: &CodeqlRuntime) {
    let Some(codeql) = codeql_snapshot_for_prewarm(runtime).await else {
        return;
    };
    let selectors = prewarm_selectors();
    eprintln!(
        "[kuzushi-mcp-codeql] prewarm: compiling {} pack/CWE pairs in background",
        selectors.len()
    );
    for selector in selectors {
        if codeql.is_cancelled() {
            eprintln!("[kuzushi-mcp-codeql] prewarm: snapshot replaced; stopping stale work");
            return;
        }
        log_prewarm_outcome(&selector, run_prewarm_compile(&codeql, &selector).await);
        tokio::task::yield_now().await;
    }
    eprintln!("[kuzushi-mcp-codeql] prewarm: complete");
}

async fn codeql_snapshot_for_prewarm(runtime: &CodeqlRuntime) -> Option<CodeqlExecutionSnapshot> {
    match locate_codeql_binary() {
        Ok(Some(codeql)) => runtime
            .snapshots
            .current(&codeql)
            .await
            .map_err(|error| eprintln!("[kuzushi-mcp-codeql] prewarm skipped: {error}"))
            .ok(),
        Ok(None) => {
            eprintln!("[kuzushi-mcp-codeql] prewarm skipped: codeql binary not found");
            None
        }
        Err(error) => {
            eprintln!("[kuzushi-mcp-codeql] prewarm skipped: {error}");
            None
        }
    }
}

fn prewarm_selectors() -> Vec<String> {
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
    PACKS
        .iter()
        .flat_map(|pack| {
            COMMON_CWES
                .iter()
                .map(move |cwe| format!("{pack}:Security/CWE/{cwe}"))
        })
        .collect()
}

async fn run_prewarm_compile(
    execution: &CodeqlExecutionSnapshot,
    selector: &str,
) -> Result<std::process::ExitStatus> {
    let cache = effective_codeql_cache_dir()?;
    let args = vec![
        OsString::from("query"),
        OsString::from("compile"),
        selector.into(),
        format!("--common-caches={}", cache.display()).into(),
    ];
    let access = kuzushi_mcp_common::read_only_sandbox::RestrictedSandboxAccess {
        working_directory: authorize_directory(&execution.bundle_root)?,
        tool_root: authorize_directory(&execution.bundle_root)?,
        read_only: Vec::new(),
        read_write: vec![authorize_directory(&cache)?],
        environment: vec![(
            "CODEQL_DIST".into(),
            execution.bundle_root.as_os_str().to_owned(),
        )],
    };
    let mut sandboxed = kuzushi_mcp_common::read_only_sandbox::restricted_command(
        &execution.launcher,
        args,
        access,
    )
    .await
    .context("CodeQL prewarm requires an available read-only sandbox")?;
    silence_sandboxed_command(&mut sandboxed)?;
    let (mut child, _scratch) = sandboxed.spawn("CodeQL prewarm")?;
    tokio::select! {
        result = child.wait() => Ok(result?),
        () = execution.cancelled() => {
            kuzushi_mcp_common::read_only_sandbox::terminate_child_group(&mut child).await;
            anyhow::bail!("CodeQL prewarm snapshot became stale")
        }
    }
}

fn log_prewarm_outcome(selector: &str, outcome: Result<std::process::ExitStatus>) {
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
}

fn locate_codeql_binary() -> Result<Option<PathBuf>> {
    if let Some(configured) = configured_codeql_binary()? {
        return Ok(Some(configured));
    }
    Ok(find_executable_on_path("codeql").or_else(standard_codeql_binary))
}

fn configured_codeql_binary() -> Result<Option<PathBuf>> {
    let Some(path) = std::env::var_os("KUZUSHI_CODEQL_BIN") else {
        return Ok(None);
    };
    let candidate = PathBuf::from(path);
    if candidate.is_file() {
        return Ok(Some(candidate));
    }
    anyhow::bail!(
        "KUZUSHI_CODEQL_BIN points to a missing CodeQL binary: {}",
        candidate.display()
    )
}

fn standard_codeql_binary() -> Option<PathBuf> {
    [
        PathBuf::from("/opt/homebrew/bin/codeql"),
        PathBuf::from("/opt/codeql/codeql/codeql"),
        PathBuf::from("/usr/local/bin/codeql"),
        PathBuf::from("/usr/bin/codeql"),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())
}

fn find_executable_on_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn requested_or_database_language(
    read_capability: &ReadRootCapability,
    db: &Path,
    args: &Value,
) -> Result<Option<String>> {
    if let Some(language) = args.get("language").and_then(Value::as_str) {
        return Ok(Some(language.to_string()));
    }
    Ok(language_from_database_metadata(&database_metadata(
        read_capability,
        db,
    )?))
}

fn database_metadata(read_capability: &ReadRootCapability, db: &Path) -> Result<String> {
    let yaml_path = db.join("codeql-database.yml");
    read_capability
        .read_utf8(&yaml_path, MAX_DATABASE_METADATA_BYTES)
        .with_context(|| format!("could not read {}", yaml_path.display()))
}

fn language_from_database_metadata(metadata: &str) -> Option<String> {
    for line in metadata.lines() {
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

fn authorized_database(read_capability: &ReadRootCapability, args: &Value) -> Result<PathBuf> {
    let requested = read_required_path(args, "db")?;
    let database = read_capability.resolve(&requested)?;
    anyhow::ensure!(
        database.is_dir(),
        "CodeQL database is not a directory: {}",
        database.display()
    );
    Ok(database)
}

fn authorized_query_selector(read_capability: &ReadRootCapability, args: &Value) -> Result<String> {
    let selector = read_required_string(args, "query")?;
    if is_pack_selector(&selector) {
        return Ok(selector);
    }
    let query = read_capability.resolve(Path::new(&selector))?;
    anyhow::ensure!(
        query.is_file() && query.extension().and_then(|value| value.to_str()) == Some("ql"),
        "local CodeQL query must be an existing .ql file: {}",
        query.display()
    );
    let source = read_capability
        .open_strict(&query, MAX_LOCAL_QUERY_BYTES)?
        .read_utf8()?;
    anyhow::ensure!(
        !local_query_has_imports(&source),
        "local CodeQL queries with imports are not supported because their dependency closure cannot be authenticated"
    );
    Ok(query.display().to_string())
}

fn is_pack_selector(selector: &str) -> bool {
    let Some((pack, query)) = selector.split_once(':') else {
        return false;
    };
    selector.len() <= 2_048 && safe_pack_name(pack) && safe_pack_query_path(query)
}

fn safe_pack_name(pack: &str) -> bool {
    !pack.is_empty()
        && pack
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "/_.@^-~".contains(ch))
        && Path::new(pack)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn safe_pack_query_path(query: &str) -> bool {
    !query.is_empty()
        && !query.contains('\\')
        && Path::new(query).components().all(|component| {
            matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

fn result_limit(args: &Value) -> usize {
    args.get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_RESULT_LIMIT as u64)
        .clamp(1, MAX_RESULT_LIMIT as u64) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    const FAKE_CODEQL_SCRIPT: &str = r#"#!/usr/bin/env bash
set -euo pipefail
out=""
cache=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    shift
    out="$1"
  elif [ "${1#--common-caches=}" != "$1" ]; then
    cache="${1#--common-caches=}"
  fi
  shift || true
done
counter="${cache:-/tmp}/codeql.invocations"
count=0
if [ -f "$counter" ]; then
  count="$(cat "$counter")"
fi
echo "$((count + 1))" > "$counter"
if [ -n "$out" ]; then
  cat > "$out" <<'JSON'
{"runs":[{"tool":{"driver":{"rules":[]}},"results":[{"ruleId":"cpp/sql-injection","message":{"text":"sql injection"},"codeFlows":[{"threadFlows":[{"locations":[{"location":{"physicalLocation":{"artifactLocation":{"uri":"src/api.c"},"region":{"startLine":7,"snippet":{"text":"input = arg;"}}}}},{"location":{"physicalLocation":{"artifactLocation":{"uri":"src/db.c"},"region":{"startLine":11,"snippet":{"text":"query(input);"}}}}}]}]}]}]}]}
JSON
fi
"#;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn restore_env(name: &str, previous: Option<std::ffi::OsString>) {
        match previous {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }

    #[cfg(unix)]
    fn fake_codeql(temp: &tempfile::TempDir) -> PathBuf {
        let bundle = temp.path().join("codeql-bundle");
        let path = bundle.join("bin/codeql");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, FAKE_CODEQL_SCRIPT).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();
        }
        path
    }

    #[cfg(unix)]
    fn invocation_count(codeql: &Path) -> usize {
        let counter = fake_codeql_counter(codeql);
        std::fs::read_to_string(counter)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    #[cfg(unix)]
    fn codeql_bundle(codeql: &Path) -> &Path {
        codeql.parent().unwrap().parent().unwrap()
    }

    #[cfg(unix)]
    fn fake_codeql_counter(codeql: &Path) -> PathBuf {
        codeql_bundle(codeql)
            .parent()
            .unwrap()
            .join("test-cache/codeql.invocations")
    }

    #[cfg(unix)]
    struct FakeCodeqlEnvironment {
        previous_binary: Option<std::ffi::OsString>,
        previous_cache: Option<std::ffi::OsString>,
    }

    #[cfg(unix)]
    fn install_fake_codeql(codeql: &Path) -> FakeCodeqlEnvironment {
        let previous_binary = std::env::var_os("KUZUSHI_CODEQL_BIN");
        let previous_cache = std::env::var_os("KUZUSHI_CODEQL_CACHE_DIR");
        let counter = fake_codeql_counter(codeql);
        let cache = counter.parent().unwrap();
        std::fs::create_dir_all(cache).unwrap();
        std::env::set_var("KUZUSHI_CODEQL_BIN", codeql);
        std::env::set_var("KUZUSHI_CODEQL_CACHE_DIR", cache);
        FakeCodeqlEnvironment {
            previous_binary,
            previous_cache,
        }
    }

    #[cfg(unix)]
    fn restore_fake_codeql(environment: FakeCodeqlEnvironment) {
        restore_env("KUZUSHI_CODEQL_BIN", environment.previous_binary);
        restore_env("KUZUSHI_CODEQL_CACHE_DIR", environment.previous_cache);
    }

    fn codeql_db(temp: &tempfile::TempDir) -> PathBuf {
        let db = temp.path().join("codeql-db");
        std::fs::create_dir_all(db.join("db-cpp")).unwrap();
        std::fs::write(db.join("codeql-database.yml"), "primaryLanguage: cpp\n").unwrap();
        db
    }

    fn capability(temp: &tempfile::TempDir) -> ReadRootCapability {
        ReadRootCapability::new([temp.path().to_path_buf()]).unwrap()
    }

    fn restore_file_times(path: &Path, metadata: &std::fs::Metadata) {
        let mut times = std::fs::FileTimes::new().set_modified(metadata.modified().unwrap());
        if let Ok(accessed) = metadata.accessed() {
            times = times.set_accessed(accessed);
        }
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(times)
            .unwrap();
    }

    #[test]
    fn cwe_folder_pads_three_digits() {
        assert_eq!(cwe_folder("CWE-89"), Some("CWE-089".to_string()));
        assert_eq!(cwe_folder("89"), Some("CWE-089".to_string()));
        assert_eq!(cwe_folder("CWE-1078"), Some("CWE-1078".to_string()));
        assert!(cwe_folder("not-a-cwe").is_none());
    }

    #[test]
    fn descriptors_disclose_memo_scope_and_authentication_cost() {
        let flows = flows_for_cwe_descriptor().description;
        assert!(flows.contains("CWE pack selectors bypass the result memo"));
        assert!(flows.contains("full database content authentication"));
        assert!(flows.contains("proportional to database size"));

        let query = query_descriptor().description;
        assert!(query.contains("memo hit skips CodeQL execution"));
        assert!(query.contains("full database content authentication"));
        assert!(query.contains("proportional to database size"));
        assert!(query.contains("Local queries with imports are rejected"));
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

    #[cfg(unix)]
    #[test]
    fn memo_key_changes_with_database_and_local_query_revisions() {
        let temp = tempdir().unwrap();
        let db = codeql_db(&temp);
        let codeql = fake_codeql(&temp);
        let query = temp.path().join("queries/local.ql");
        std::fs::create_dir_all(query.parent().unwrap()).unwrap();
        std::fs::write(&query, "select 1").unwrap();
        let selector = query.display().to_string();

        let first = memo_key(&db, &selector, 10, &codeql).unwrap();
        std::fs::write(
            db.join("codeql-database.yml"),
            "primaryLanguage: cpp\nrevision: two\n",
        )
        .unwrap();
        let changed_db = memo_key(&db, &selector, 10, &codeql).unwrap();
        assert_ne!(first.db_revision, changed_db.db_revision);

        std::fs::write(&query, "select 2").unwrap();
        let changed_query = memo_key(&db, &selector, 10, &codeql).unwrap();
        assert_ne!(
            changed_db.selector_revision,
            changed_query.selector_revision
        );
    }

    #[test]
    #[cfg(unix)]
    fn memo_key_tracks_database_and_full_codeql_bundle_revisions() {
        let temp = tempdir().unwrap();
        let db = codeql_db(&temp);
        let internal = db.join("db-cpp/internal.bin");
        std::fs::write(&internal, b"one").unwrap();
        let codeql = fake_codeql(&temp);
        let runtime = codeql_bundle(&codeql).join("lib/runtime.bin");
        std::fs::create_dir_all(runtime.parent().unwrap()).unwrap();
        std::fs::write(&runtime, b"one").unwrap();
        let query = temp.path().join("local.ql");
        std::fs::write(&query, "select 1").unwrap();
        let selector = query.display().to_string();
        let first = memo_key(&db, &selector, 10, &codeql).unwrap();
        let stable_metadata = std::fs::metadata(&internal).unwrap();

        std::fs::write(&internal, b"two").unwrap();
        restore_file_times(&internal, &stable_metadata);
        let changed_metadata = std::fs::metadata(&internal).unwrap();
        assert_eq!(stable_metadata.len(), changed_metadata.len());
        assert_eq!(
            stable_metadata.modified().unwrap(),
            changed_metadata.modified().unwrap()
        );
        let changed_db = memo_key(&db, &selector, 10, &codeql).unwrap();
        assert_ne!(first.db_revision, changed_db.db_revision);

        std::fs::write(&runtime, b"two").unwrap();
        let changed_runtime = memo_key(&db, &selector, 10, &codeql).unwrap();
        assert_ne!(changed_db.codeql_revision, changed_runtime.codeql_revision);

        std::fs::OpenOptions::new()
            .append(true)
            .open(&codeql)
            .unwrap()
            .write_all(b"\n# executable revision two\n")
            .unwrap();
        let changed_binary = memo_key(&db, &selector, 10, &codeql).unwrap();
        assert_ne!(
            changed_runtime.codeql_revision,
            changed_binary.codeql_revision
        );
    }

    #[test]
    #[cfg(unix)]
    fn changed_database_rejects_even_unmemoized_pack_output() {
        let temp = tempdir().unwrap();
        let db = codeql_db(&temp);
        let internal = db.join("db-cpp/internal.bin");
        std::fs::write(&internal, "before").unwrap();
        let codeql = fake_codeql(&temp);
        let identity = analysis_identity(&db, &codeql).unwrap();
        std::fs::write(&internal, "after").unwrap();

        let error = authenticate_and_store_current_result(
            &db,
            "codeql/cpp-queries:Security/CWE/CWE-089",
            10,
            &codeql,
            identity,
            None,
            &[],
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("rejecting unauthenticated output"),
            "{error}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn changed_adjacent_codeql_helper_rejects_analysis_output() {
        let temp = tempdir().unwrap();
        let db = codeql_db(&temp);
        let codeql = fake_codeql(&temp);
        let helper = codeql_bundle(&codeql).join("lib/runtime.bin");
        std::fs::create_dir_all(helper.parent().unwrap()).unwrap();
        std::fs::write(&helper, "trusted runtime").unwrap();
        let identity = analysis_identity(&db, &codeql).unwrap();

        std::fs::write(&helper, "mutated runtime").unwrap();
        let error = authenticate_and_store_current_result(
            &db,
            "codeql/cpp-queries:Security/CWE/CWE-089",
            10,
            &codeql,
            identity,
            None,
            &[],
        )
        .unwrap_err()
        .to_string();

        assert!(
            error.contains("rejecting unauthenticated output"),
            "{error}"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn execution_snapshot_retains_authenticated_launcher_and_runtime_bytes() {
        let temp = tempdir().unwrap();
        let db = codeql_db(&temp);
        let codeql = fake_codeql(&temp);
        let runtime = codeql_bundle(&codeql).join("lib/runtime.bin");
        std::fs::create_dir_all(runtime.parent().unwrap()).unwrap();
        std::fs::write(&runtime, b"trusted runtime").unwrap();
        let identity = analysis_identity(&db, &codeql).unwrap();

        let store = CodeqlSnapshotStore::new().unwrap();
        let execution = store
            .authenticated(&identity.codeql, &identity.codeql_revision)
            .await
            .unwrap();
        std::fs::write(&codeql, b"malicious launcher").unwrap();
        std::fs::write(&runtime, b"malicious runtime").unwrap();

        let snapshot_bundle = resolve_codeql_bundle_root(&execution.launcher).unwrap();
        assert_eq!(
            std::fs::read(&execution.launcher).unwrap(),
            FAKE_CODEQL_SCRIPT.as_bytes()
        );
        assert_eq!(
            std::fs::read(snapshot_bundle.join("lib/runtime.bin")).unwrap(),
            b"trusted runtime"
        );
    }

    #[test]
    fn planned_database_identity_is_mandatory_and_content_bound() {
        let temp = tempdir().unwrap();
        let db = codeql_db(&temp);
        let actual = crate::database_identity::database_identity(&db).unwrap();

        let missing = validate_planned_database_identity(
            &db,
            &actual,
            Some(db.clone().into_os_string()),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(missing.contains("missing its authenticated"), "{missing}");

        let mismatch = validate_planned_database_identity(
            &db,
            &actual,
            Some(db.clone().into_os_string()),
            Some("0".repeat(64).into()),
        )
        .unwrap_err()
        .to_string();
        assert!(mismatch.contains("does not match"), "{mismatch}");

        validate_planned_database_identity(
            &db,
            &actual,
            Some(db.clone().into_os_string()),
            Some(actual.clone().into()),
        )
        .unwrap();
    }

    #[test]
    fn analyze_command_keeps_logs_and_caches_out_of_the_database() {
        let temp = tempdir().unwrap();
        let db = temp.path().join("database");
        let sarif = temp.path().join("result.sarif");
        let logs = temp.path().join("analysis-logs");
        let args = codeql_analyze_args(&db, "pack:query", &sarif, &logs, None)
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        for required in ["--rerun", "--max-disk-cache=0", "--expect-discarded-cache"] {
            assert!(args.iter().any(|arg| arg == required), "missing {required}");
        }
        assert!(args
            .iter()
            .any(|arg| arg == &format!("--logdir={}", logs.display())));
        assert!(!logs.starts_with(&db));
    }

    #[test]
    #[cfg(unix)]
    fn memo_bypasses_pack_and_imported_local_query_selectors() {
        let temp = tempdir().unwrap();
        let db = codeql_db(&temp);
        let codeql = fake_codeql(&temp);
        assert!(memo_key(&db, "codeql/cpp-queries:Security/CWE/CWE-089", 10, &codeql,).is_none());

        let query = temp.path().join("queries/local.ql");
        std::fs::create_dir_all(query.parent().unwrap()).unwrap();
        std::fs::write(&query, "import helper\nselect 1").unwrap();
        std::fs::write(
            query.parent().unwrap().join("helper.qll"),
            "predicate helper() { any() }",
        )
        .unwrap();
        assert!(memo_key(&db, &query.display().to_string(), 10, &codeql).is_none());
    }

    #[test]
    fn memo_enforces_entry_and_serialized_byte_limits() {
        let flows = vec![json!({"flow": "small"})];
        let bytes = serialized_flow_bytes(&flows).unwrap();
        let first = test_memo_key("first");
        let second = test_memo_key("second");
        let third = test_memo_key("third");
        let mut memo = FlowMemo::bounded(2, bytes * 2);
        memo.insert(first.clone(), &flows);
        memo.insert(second.clone(), &flows);
        memo.insert(third.clone(), &flows);

        assert!(memo.get(&first).is_none());
        assert!(memo.get(&second).is_some());
        assert!(memo.get(&third).is_some());
        assert_eq!(memo.entries.len(), 2);
        assert!(memo.bytes <= bytes * 2);

        let mut too_small = FlowMemo::bounded(2, bytes.saturating_sub(1));
        too_small.insert(first, &flows);
        assert!(too_small.entries.is_empty());
    }

    fn test_memo_key(name: &str) -> MemoKey {
        MemoKey {
            db: PathBuf::from(format!("/{name}")),
            db_revision: "revision".to_string(),
            selector: "pack:query".to_string(),
            selector_revision: "selector-revision".to_string(),
            codeql: PathBuf::from("/codeql"),
            codeql_revision: "codeql-revision".to_string(),
            limit: 10,
        }
    }

    #[test]
    fn imported_local_queries_are_rejected_before_execution() {
        let temp = tempdir().unwrap();
        let query = temp.path().join("queries/local.ql");
        std::fs::create_dir_all(query.parent().unwrap()).unwrap();
        std::fs::write(&query, "import helper\nselect 1").unwrap();
        let error = authorized_query_selector(
            &capability(&temp),
            &json!({"query": query.display().to_string()}),
        )
        .unwrap_err();

        assert!(error.to_string().contains("dependency closure"));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn authenticated_local_query_returns_from_memo_on_second_call() {
        let _guard = lock_env();
        if !kuzushi_mcp_common::read_only_sandbox::sandbox_available().await {
            return;
        }
        let temp = tempdir().unwrap();
        let fake = fake_codeql(&temp);
        let db = codeql_db(&temp);
        let query = temp.path().join("local.ql");
        std::fs::write(&query, "select 1").unwrap();
        let environment = install_fake_codeql(&fake);

        for _ in 0..2 {
            run_codeql_and_parse(&db, &query.display().to_string(), 10)
                .await
                .unwrap();
        }

        restore_fake_codeql(environment);
        assert_eq!(invocation_count(&fake), 1);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn memo_lookup_reauthenticates_same_metadata_database_content() {
        let _guard = lock_env();
        if !kuzushi_mcp_common::read_only_sandbox::sandbox_available().await {
            return;
        }
        let temp = tempdir().unwrap();
        let fake = fake_codeql(&temp);
        let db = codeql_db(&temp);
        let internal = db.join("db-cpp/internal.bin");
        std::fs::write(&internal, b"one").unwrap();
        let query = temp.path().join("local.ql");
        std::fs::write(&query, "select 1").unwrap();
        let environment = install_fake_codeql(&fake);

        run_codeql_and_parse(&db, &query.display().to_string(), 10)
            .await
            .unwrap();
        let stable_metadata = std::fs::metadata(&internal).unwrap();
        std::fs::write(&internal, b"two").unwrap();
        restore_file_times(&internal, &stable_metadata);
        run_codeql_and_parse(&db, &query.display().to_string(), 10)
            .await
            .unwrap();

        restore_fake_codeql(environment);
        assert_eq!(invocation_count(&fake), 2);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn query_handler_invokes_codeql_and_parses_sarif_flows() {
        let _guard = lock_env();
        if !kuzushi_mcp_common::read_only_sandbox::sandbox_available().await {
            return;
        }
        let temp = tempdir().unwrap();
        let fake = fake_codeql(&temp);
        let db = codeql_db(&temp);
        let environment = install_fake_codeql(&fake);

        let response = QueryHandler(capability(&temp), CodeqlRuntime::new().unwrap())
            .call(json!({
                "db": db.display().to_string(),
                "query": "codeql/cpp-queries:Security/CWE/CWE-089",
                "limit": 10
            }))
            .await
            .unwrap();

        restore_fake_codeql(environment);

        assert_eq!(response["flow_count"], json!(1));
        assert_eq!(response["flows"][0]["source"]["line"], json!(7));
        assert_eq!(response["flows"][0]["sink"]["line"], json!(11));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn flows_for_cwe_handler_infers_language_and_selector() {
        let _guard = lock_env();
        if !kuzushi_mcp_common::read_only_sandbox::sandbox_available().await {
            return;
        }
        let temp = tempdir().unwrap();
        let fake = fake_codeql(&temp);
        let db = codeql_db(&temp);
        let environment = install_fake_codeql(&fake);

        let response = FlowsForCweHandler(capability(&temp), CodeqlRuntime::new().unwrap())
            .call(json!({"db": db.display().to_string(), "cwe": "89", "limit": 5}))
            .await
            .unwrap();

        restore_fake_codeql(environment);

        assert_eq!(
            response["selector"],
            json!("codeql/cpp-queries:Security/CWE/CWE-089")
        );
        assert_eq!(response["flow_count"], json!(1));
    }

    #[tokio::test]
    async fn db_info_rejects_databases_outside_the_read_root() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let db = codeql_db(&outside);

        let error = DbInfoHandler(capability(&root))
            .call(json!({"db": db}))
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("outside the MCP read roots"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn db_info_rejects_a_database_symlink_that_escapes_the_read_root() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let db = codeql_db(&outside);
        let link = root.path().join("escaped-db");
        symlink(&db, &link).unwrap();

        let error = DbInfoHandler(capability(&root))
            .call(json!({"db": link}))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("outside the MCP read roots"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn db_info_rejects_an_escaping_metadata_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let db = codeql_db(&root);
        let metadata = db.join("codeql-database.yml");
        std::fs::remove_file(&metadata).unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        symlink(outside.path(), &metadata).unwrap();

        let error = DbInfoHandler(capability(&root))
            .call(json!({"db": db}))
            .await
            .unwrap_err();

        assert!(format!("{error:#}").contains("outside the MCP read roots"));
    }

    #[test]
    fn query_selector_allows_pack_selectors_and_authorized_local_files() {
        let root = tempdir().unwrap();
        let query = root.path().join("queries/check.ql");
        std::fs::create_dir_all(query.parent().unwrap()).unwrap();
        std::fs::write(&query, "select 1").unwrap();
        let capability = capability(&root);

        assert_eq!(
            authorized_query_selector(
                &capability,
                &json!({"query": "codeql/cpp-queries:Security/CWE/CWE-089/SqlTainted.ql"}),
            )
            .unwrap(),
            "codeql/cpp-queries:Security/CWE/CWE-089/SqlTainted.ql"
        );
        assert_eq!(
            authorized_query_selector(&capability, &json!({"query": "queries/check.ql"})).unwrap(),
            std::fs::canonicalize(query).unwrap().display().to_string()
        );
    }

    #[cfg(unix)]
    #[test]
    fn query_selector_rejects_outside_and_symlinked_local_queries() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let outside_root = tempdir().unwrap();
        let outside = outside_root.path().join("outside.ql");
        std::fs::write(&outside, "select 1").unwrap();
        let link = root.path().join("escaped.ql");
        symlink(&outside, &link).unwrap();
        let capability = capability(&root);

        for path in [outside.as_path(), link.as_path()] {
            let error = authorized_query_selector(
                &capability,
                &json!({"query": path.display().to_string()}),
            )
            .unwrap_err();
            assert!(error.to_string().contains("outside the MCP read roots"));
        }
    }

    #[test]
    fn query_selector_rejects_pack_path_traversal_and_clamps_limits() {
        let root = tempdir().unwrap();
        let capability = capability(&root);

        let error = authorized_query_selector(
            &capability,
            &json!({"query": "codeql/cpp-queries:../../outside.ql"}),
        )
        .unwrap_err();

        assert!(error.to_string().contains("outside the MCP read roots"));
        assert_eq!(result_limit(&json!({"limit": 0})), 1);
        assert_eq!(result_limit(&json!({"limit": u64::MAX})), MAX_RESULT_LIMIT);
    }

    #[test]
    fn sarif_reader_rejects_oversized_output_before_json_parsing() {
        let root = tempdir().unwrap();
        let sarif = root.path().join("results.sarif");
        let file = std::fs::File::create(&sarif).unwrap();
        file.set_len(MAX_SARIF_BYTES as u64 + 1).unwrap();

        let error = read_generated_sarif(&sarif).unwrap_err();

        assert!(error.to_string().contains("could not read SARIF output"));
        assert!(format!("{error:#}").contains("maximum supported size"));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn prewarm_uses_configured_codeql_binary_without_requiring_a_db() {
        let _guard = lock_env();
        if !kuzushi_mcp_common::read_only_sandbox::sandbox_available().await {
            return;
        }
        let temp = tempdir().unwrap();
        let fake = fake_codeql(&temp);
        let previous = std::env::var_os("KUZUSHI_CODEQL_BIN");
        std::env::set_var("KUZUSHI_CODEQL_BIN", &fake);

        spawn_prewarm(&CodeqlRuntime::new().unwrap()).await;

        restore_env("KUZUSHI_CODEQL_BIN", previous);
    }

    #[test]
    #[cfg(unix)]
    fn locate_codeql_binary_uses_valid_override() {
        let _guard = lock_env();
        let temp = tempdir().unwrap();
        let fake = fake_codeql(&temp);
        let previous = std::env::var_os("KUZUSHI_CODEQL_BIN");
        std::env::set_var("KUZUSHI_CODEQL_BIN", &fake);

        let resolved = locate_codeql_binary().unwrap().unwrap();

        restore_env("KUZUSHI_CODEQL_BIN", previous);
        assert_eq!(resolved, fake);
    }

    #[test]
    #[cfg(unix)]
    fn locate_codeql_binary_rejects_invalid_override_without_path_fallback() {
        let _guard = lock_env();
        let temp = tempdir().unwrap();
        let fake = fake_codeql(&temp);
        let previous_bin = std::env::var_os("KUZUSHI_CODEQL_BIN");
        let previous_path = std::env::var_os("PATH");
        std::env::set_var("KUZUSHI_CODEQL_BIN", temp.path().join("missing-codeql"));
        std::env::set_var("PATH", fake.parent().unwrap());

        let error = locate_codeql_binary().unwrap_err().to_string();

        restore_env("KUZUSHI_CODEQL_BIN", previous_bin);
        restore_env("PATH", previous_path);
        assert!(error.contains("KUZUSHI_CODEQL_BIN points to a missing CodeQL binary"));
    }

    #[test]
    #[cfg(unix)]
    fn locate_codeql_binary_falls_back_to_path_when_override_unset() {
        let _guard = lock_env();
        let temp = tempdir().unwrap();
        let fake = fake_codeql(&temp);
        let previous_bin = std::env::var_os("KUZUSHI_CODEQL_BIN");
        let previous_path = std::env::var_os("PATH");
        std::env::remove_var("KUZUSHI_CODEQL_BIN");
        std::env::set_var("PATH", fake.parent().unwrap());

        let resolved = locate_codeql_binary().unwrap().unwrap();

        restore_env("KUZUSHI_CODEQL_BIN", previous_bin);
        restore_env("PATH", previous_path);
        assert_eq!(resolved, fake);
    }
}
