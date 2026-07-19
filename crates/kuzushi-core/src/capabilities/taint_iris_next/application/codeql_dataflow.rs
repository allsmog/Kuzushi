use super::*;
use std::path::PathBuf;
use std::process::{Child, Command};
#[cfg(not(test))]
use std::sync::OnceLock;

/// Wait for a child process to exit. When `timeout_secs == 0` we block
/// indefinitely (semantic: "no timeout, however long the analysis
/// takes"). When non-zero we poll every 2s and kill on deadline.
pub(crate) fn wait_with_optional_timeout(
    child: &mut Child,
    timeout_secs: u64,
) -> anyhow::Result<std::process::Output> {
    let readers = start_codeql_output_readers(child);
    match wait_for_codeql_exit(child, timeout_secs) {
        Ok(status) => finish_codeql_output(status, readers),
        Err(error) => {
            kill_and_reap_child(child);
            let _ = join_codeql_reader(readers.0, "stdout");
            let _ = join_codeql_reader(readers.1, "stderr");
            Err(error)
        }
    }
}

fn wait_for_codeql_exit(
    child: &mut Child,
    timeout_secs: u64,
) -> anyhow::Result<std::process::ExitStatus> {
    if timeout_secs == 0 {
        return child.wait().context("could not wait for child process");
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    wait_for_codeql_exit_until(child, deadline, timeout_secs)
}

fn wait_for_codeql_exit_until(
    child: &mut Child,
    deadline: std::time::Instant,
    timeout_secs: u64,
) -> anyhow::Result<std::process::ExitStatus> {
    loop {
        if let Some(status) = child.try_wait().context("could not poll child process")? {
            return Ok(status);
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("analysis child exceeded {timeout_secs}s timeout")
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn kill_and_reap_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

type CodeqlOutputReader = std::thread::JoinHandle<Result<Vec<u8>>>;

fn start_codeql_output_readers(child: &mut Child) -> (CodeqlOutputReader, CodeqlOutputReader) {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout = std::thread::spawn(move || {
        read_optional_pipe(
            stdout,
            crate::bounded_subprocess::DEFAULT_STDOUT_LIMIT,
            "analysis stdout",
        )
    });
    let stderr = std::thread::spawn(move || {
        read_optional_pipe(
            stderr,
            crate::bounded_subprocess::DEFAULT_STDERR_LIMIT,
            "analysis stderr",
        )
    });
    (stdout, stderr)
}

fn finish_codeql_output(
    status: std::process::ExitStatus,
    readers: (CodeqlOutputReader, CodeqlOutputReader),
) -> Result<std::process::Output> {
    Ok(std::process::Output {
        status,
        stdout: join_codeql_reader(readers.0, "stdout")?,
        stderr: join_codeql_reader(readers.1, "stderr")?,
    })
}

fn read_optional_pipe<R: std::io::Read>(
    pipe: Option<R>,
    limit: usize,
    label: &str,
) -> Result<Vec<u8>> {
    let Some(pipe) = pipe else {
        return Ok(Vec::new());
    };
    crate::bounded_subprocess::drain_bounded(pipe, limit, label)
}

fn join_codeql_reader(reader: CodeqlOutputReader, stream: &str) -> Result<Vec<u8>> {
    reader
        .join()
        .map_err(|_| anyhow::anyhow!("codeql {stream} reader panicked"))?
}

/// True iff a usable `codeql` CLI is on PATH (or under `/opt/codeql/`).
pub(crate) fn codeql_available() -> bool {
    #[cfg(test)]
    {
        return codeql_launcher_path().is_some();
    }
    #[cfg(not(test))]
    {
        static AVAILABLE: OnceLock<bool> = OnceLock::new();
        *AVAILABLE.get_or_init(|| codeql_launcher_path().is_some())
    }
}

/// Resolve the CodeQL CLI launcher.
pub(crate) fn codeql_launcher_path() -> Option<PathBuf> {
    configured_codeql_launcher()
        .or_else(|| crate::process_lookup::executable_on_path("codeql"))
        .or_else(first_standard_codeql_launcher)
}

fn configured_codeql_launcher() -> Option<PathBuf> {
    let candidate = PathBuf::from(std::env::var_os("KUZUSHI_CODEQL_BIN")?);
    candidate.is_file().then_some(candidate)
}

fn first_standard_codeql_launcher() -> Option<PathBuf> {
    [
        PathBuf::from("/opt/codeql/codeql/codeql"),
        PathBuf::from("/usr/local/bin/codeql"),
        PathBuf::from("/usr/bin/codeql"),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())
}

/// Standard locations kuzushi expects for an existing CodeQL DB.
pub(crate) fn codeql_db_path(repo_root: &Path) -> Result<Option<PathBuf>> {
    crate::codeql_repository_execution::resolve_managed_codeql_database(repo_root)
        .map(|database| database.map(|database| database.path().to_path_buf()))
}

/// One source-to-sink path discovered by a CodeQL query, distilled from
/// SARIF. Mirrors `JoernFlow` so the rest of the pipeline doesn't care
/// which engine produced the result.
#[derive(Debug, Clone)]
pub(crate) struct CodeqlFlow {
    pub(crate) cwe: String,
    pub(crate) taint_class: String,
    pub(crate) file_path: String,
    pub(crate) source_line: u32,
    pub(crate) sink_line: u32,
    pub(crate) source_code: String,
    pub(crate) sink_code: String,
    pub(crate) steps: Vec<CodeqlStep>,
    pub(crate) rule_id: String,
    pub(crate) message: String,
}

#[derive(Debug, Clone)]
pub(crate) struct CodeqlStep {
    pub(crate) file: String,
    pub(crate) line: u32,
    pub(crate) code: String,
}

/// Run a CodeQL security-and-quality query suite against the DB at
/// `<target>/.kuzushi/v3/codeql-db` and return the resulting source-to-sink
/// flows. Returns `Ok(None)` when CodeQL is unavailable, the DB is
/// missing, or the query suite isn't installed — callers fall back to
/// joern or the heuristic linker without surfacing an error.
pub(crate) fn run_codeql_flows(plan: &TaintIrisNextPlan) -> Result<Option<Vec<CodeqlFlow>>> {
    if !codeql_available() {
        return Ok(None);
    }
    let Some(database) =
        crate::codeql_repository_execution::resolve_managed_codeql_database(&plan.scan_root)?
    else {
        return Ok(None);
    };
    let Some(launcher) = codeql_launcher_path() else {
        return Ok(None);
    };
    let queries = selected_codeql_queries(plan);
    let analysis_dir = tempfile::tempdir().context("could not create codeql analysis directory")?;
    let sarif_path = analysis_dir.path().join("results.sarif");
    let timeout_secs = (plan.caps.codeql_analyze_timeout_ms as u64).div_ceil(1_000);
    let output = database.run_verified(|database_path| {
        run_codeql_analysis(
            &launcher,
            database_path,
            &sarif_path,
            &queries,
            timeout_secs,
        )
    })?;
    ensure_codeql_analysis_succeeded(&output)?;
    let sarif = crate::bounded_file::read_utf8_text(&sarif_path, 64 * 1024 * 1024)
        .context("could not read codeql SARIF output")?;
    Ok(Some(parse_sarif_flows(&sarif)))
}

fn selected_codeql_queries(plan: &TaintIrisNextPlan) -> Vec<String> {
    let catalog = filter_existing_codeql_selectors(codeql_queries_from_catalog(
        &plan.catalog,
        &plan.languages,
    ));
    if catalog.is_empty() {
        vec![codeql_default_query_suite(&plan.languages)]
    } else {
        catalog
    }
}

fn run_codeql_analysis(
    launcher: &Path,
    db_path: &Path,
    sarif_path: &Path,
    queries: &[String],
    timeout_secs: u64,
) -> Result<std::process::Output> {
    let log_dir = sarif_path
        .parent()
        .context("CodeQL SARIF output has no parent directory")?;
    let mut command = Command::new(launcher);
    command
        .args(["database", "analyze", "--format=sarif-latest", "--output"])
        .arg(sarif_path)
        .args(["--ram=4096", "--threads=4"])
        .args(
            crate::codeql_repository_execution::managed_codeql_analysis_safety_args(log_dir),
        )
        .arg(db_path)
        .args(queries)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| format!("could not invoke codeql at {}", launcher.display()))?;
    wait_with_optional_timeout(&mut child, timeout_secs)
}

fn ensure_codeql_analysis_succeeded(output: &std::process::Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr)
        .chars()
        .take(800)
        .collect::<String>();
    anyhow::bail!("codeql exited with {}: {stderr}", output.status)
}

/// Translate the per-target catalog into specific CodeQL query selectors.
///
/// CodeQL accepts query selectors like `codeql/cpp-queries:Security/CWE/CWE-089`
/// as positional args. Each selector resolves to all `.ql` files in that
/// folder. Per-target catalog generation already produces a list of CWEs
/// that the agent considers relevant to this codebase (postgres got
/// 12 CWEs: 89, 120, 190, 22, 78, 426, 295, 502, 416, 209, 918, 77 — out
/// of the 79 CodeQL covers in the cpp suite). Running just the relevant
/// folders cuts a 179-query suite down to ~25-50 queries that finish
/// many times faster while still surfacing every CWE the catalog cares
/// about.
///
/// Languages without a CodeQL `<lang>-queries` pack return an empty list
/// so callers fall back to the per-language `<lang>-security-and-quality`
/// suite.
fn codeql_queries_from_catalog(
    catalog: &[TaintIrisNextRankedCatalogEntry],
    languages: &[String],
) -> Vec<String> {
    let pack = match codeql_query_pack_for_languages(languages) {
        Some(pack) => pack,
        None => return Vec::new(),
    };
    let mut seen = BTreeSet::new();
    let mut selectors = Vec::new();
    for entry in catalog {
        let Some(folder) = codeql_cwe_folder(&entry.cwe) else {
            continue;
        };
        let key = format!("{pack}:Security/CWE/{folder}");
        if seen.insert(key.clone()) {
            selectors.push(key);
        }
    }
    selectors
}

/// Drop selectors whose CWE folder doesn't exist in the installed pack.
/// CodeQL treats missing selectors as fatal errors and aborts the whole
/// analyze, so e.g. a catalog containing CWE-77 (which cpp-queries
/// doesn't ship — only CWE-78 is available) would kill the run unless
/// we filter it here. Separated from `codeql_queries_from_catalog` so
/// the pure resolution stays testable without filesystem dependence.
fn filter_existing_codeql_selectors(selectors: Vec<String>) -> Vec<String> {
    selectors
        .into_iter()
        .filter(|selector| codeql_selector_path_exists(selector))
        .collect()
}

fn codeql_selector_path_exists(selector: &str) -> bool {
    let Some((pack, relative)) = selector.split_once(':') else {
        return true;
    };
    let Some(pack_root) = codeql_pack_root(pack) else {
        return true; // pack not on disk — leave the selector for codeql to surface its own error
    };
    pack_root.join(relative).exists()
}

/// Locate the on-disk root of a CodeQL pack so we can filter selectors
/// by what actually ships. Walks the standard locations the codeql
/// bundle uses; falls back to `None` (treat every CWE folder as
/// potentially valid) when the pack root can't be determined.
fn codeql_pack_root(pack: &str) -> Option<PathBuf> {
    let pack_dir_name = pack.strip_prefix("codeql/").unwrap_or(pack);
    for base in [
        "/opt/codeql/codeql/qlpacks/codeql",
        "/usr/local/codeql/qlpacks/codeql",
        "/usr/local/share/codeql/qlpacks/codeql",
    ] {
        let candidate = PathBuf::from(base).join(pack_dir_name);
        if candidate.is_dir() {
            // Pack roots are versioned: codeql/cpp-queries/<version>/.
            // Pick the most-recent version directory.
            if let Ok(entries) = std::fs::read_dir(&candidate) {
                let mut versions: Vec<_> = entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .filter(|path| path.is_dir())
                    .collect();
                versions.sort();
                if let Some(latest) = versions.into_iter().next_back() {
                    return Some(latest);
                }
            }
        }
    }
    None
}

fn codeql_query_pack_for_languages(languages: &[String]) -> Option<&'static str> {
    for lang in languages {
        match lang.as_str() {
            "c" | "cpp" => return Some("codeql/cpp-queries"),
            "python" => return Some("codeql/python-queries"),
            "javascript" | "typescript" => return Some("codeql/javascript-queries"),
            "java" | "kotlin" => return Some("codeql/java-queries"),
            "go" => return Some("codeql/go-queries"),
            "ruby" => return Some("codeql/ruby-queries"),
            "csharp" => return Some("codeql/csharp-queries"),
            _ => continue,
        }
    }
    None
}

fn codeql_cwe_folder(cwe: &str) -> Option<String> {
    let stripped = cwe.strip_prefix("CWE-")?;
    let number: u32 = stripped.parse().ok()?;
    Some(format!("CWE-{:03}", number))
}

/// Convert detected languages into the default CodeQL query suite.
/// Falls back to "cpp-security-and-quality.qls" since that's the most
/// common large-codebase target where SARIF results are most useful.
fn codeql_default_query_suite(languages: &[String]) -> String {
    let suite_for = |lang: &str| -> Option<&'static str> {
        match lang {
            "c" | "cpp" => Some("cpp-security-and-quality.qls"),
            "python" => Some("python-security-and-quality.qls"),
            "javascript" | "typescript" => Some("javascript-security-and-quality.qls"),
            "java" | "kotlin" => Some("java-security-and-quality.qls"),
            "go" => Some("go-security-and-quality.qls"),
            "ruby" => Some("ruby-security-and-quality.qls"),
            "csharp" => Some("csharp-security-and-quality.qls"),
            _ => None,
        }
    };
    languages
        .iter()
        .find_map(|lang| suite_for(lang))
        .unwrap_or("cpp-security-and-quality.qls")
        .to_string()
}

/// SARIF schema reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/.
/// We only consume `runs[].results[]` and pluck the first/last location
/// of any `codeFlows` thread to model source/sink pairs. Results without
/// codeFlows still surface as 1-step flows so single-location alerts
/// (e.g. "missing return value check") aren't lost.
fn parse_sarif_flows(sarif: &str) -> Vec<CodeqlFlow> {
    let value: Value = match serde_json::from_str(sarif) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let Some(runs) = value.get("runs").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut flows = Vec::new();
    for run in runs {
        let Some(results) = run.get("results").and_then(Value::as_array) else {
            continue;
        };
        for result in results {
            if let Some(flow) = sarif_result_to_flow(result, run) {
                flows.push(flow);
            }
        }
    }
    flows
}

fn sarif_result_to_flow(result: &Value, run: &Value) -> Option<CodeqlFlow> {
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

    // Try codeFlows first — those carry full source-to-sink path info.
    let mut steps = if let Some(thread_steps) = first_thread_flow_locations(result) {
        thread_steps
    } else {
        result
            .get("locations")
            .and_then(Value::as_array)
            .map(|locations| {
                locations
                    .iter()
                    .filter_map(|loc| sarif_location_to_step(loc))
                    .collect()
            })
            .unwrap_or_default()
    };
    if steps.is_empty() {
        return None;
    }
    // Replace each step's `code` with a snippet pulled from the SARIF
    // `region.snippet.text` if present; CodeQL embeds source line text
    // there for most queries.
    enrich_steps_with_snippets(&mut steps, result);

    let cwe = sarif_rule_to_cwe(&rule_id, run);
    let taint_class = sarif_rule_to_taint_class(&rule_id);
    let first = steps.first()?;
    let last = steps.last()?;
    Some(CodeqlFlow {
        cwe,
        taint_class,
        file_path: first.file.clone(),
        source_line: first.line,
        sink_line: last.line,
        source_code: first.code.clone(),
        sink_code: last.code.clone(),
        steps,
        rule_id,
        message,
    })
}

fn first_thread_flow_locations(result: &Value) -> Option<Vec<CodeqlStep>> {
    let steps: Vec<CodeqlStep> = first_thread_flow_location_values(result)?
        .iter()
        .filter_map(|location| sarif_location_to_step(location.get("location").unwrap_or(location)))
        .collect();
    non_empty_codeql_steps(steps)
}

fn first_thread_flow_location_values(result: &Value) -> Option<&Vec<Value>> {
    let first_flow = result.get("codeFlows").and_then(Value::as_array)?.first()?;
    let first_thread = first_flow
        .get("threadFlows")
        .and_then(Value::as_array)?
        .first()?;
    first_thread.get("locations").and_then(Value::as_array)
}

fn non_empty_codeql_steps(steps: Vec<CodeqlStep>) -> Option<Vec<CodeqlStep>> {
    (!steps.is_empty()).then_some(steps)
}

fn sarif_location_to_step(location: &Value) -> Option<CodeqlStep> {
    let physical = location.get("physicalLocation")?;
    let file = physical
        .pointer("/artifactLocation/uri")
        .and_then(Value::as_str)?
        .to_string();
    let line = physical
        .pointer("/region/startLine")
        .and_then(Value::as_u64)
        .unwrap_or(0) as u32;
    let code = physical
        .pointer("/region/snippet/text")
        .and_then(Value::as_str)
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    Some(CodeqlStep { file, line, code })
}

fn enrich_steps_with_snippets(steps: &mut [CodeqlStep], result: &Value) {
    if steps.iter().all(|s| !s.code.is_empty()) {
        return;
    }
    let Some(message) = result.pointer("/message/text").and_then(Value::as_str) else {
        return;
    };
    let trimmed = message.trim();
    for step in steps.iter_mut() {
        if step.code.is_empty() {
            // Fallback: at least preserve the rule's message text so the
            // agent gets a non-empty snippet to reason about.
            step.code = trimmed.chars().take(160).collect();
        }
    }
}

/// Map a CodeQL rule id (`cpp/sql-injection`, `js/path-injection`, etc.)
/// to the catalog CWE we're tracking. Looks up the rule's tags in the
/// SARIF run metadata when available; otherwise infers from the rule id.
fn sarif_rule_to_cwe(rule_id: &str, run: &Value) -> String {
    if let Some(rules) = run.pointer("/tool/driver/rules").and_then(Value::as_array) {
        for rule in rules {
            let id = rule.get("id").and_then(Value::as_str).unwrap_or("");
            if id != rule_id {
                continue;
            }
            if let Some(tags) = rule.pointer("/properties/tags").and_then(Value::as_array) {
                for tag in tags.iter().filter_map(Value::as_str) {
                    if let Some(stripped) = tag.strip_prefix("external/cwe/cwe-") {
                        let normalized = stripped.trim_start_matches('0');
                        return format!(
                            "CWE-{}",
                            if normalized.is_empty() {
                                "0"
                            } else {
                                normalized
                            }
                        );
                    }
                }
            }
        }
    }
    cwe_from_rule_id(rule_id)
}

fn cwe_from_rule_id(rule_id: &str) -> String {
    let lower = rule_id.to_ascii_lowercase();
    codeql_rule_cwe_label(&lower).to_string()
}

fn codeql_rule_cwe_label(lower_rule_id: &str) -> &'static str {
    const CWE_PATTERNS: &[(&[&str], &str)] = &[
        (&["sql-injection"], "CWE-89"),
        (&["path-injection", "path-traversal"], "CWE-22"),
        (&["command-injection", "command-line-injection"], "CWE-78"),
        (&["xss", "cross-site-scripting"], "CWE-79"),
        (&["ssrf", "server-side-request-forgery"], "CWE-918"),
        (&["integer-overflow", "arithmetic-overflow"], "CWE-190"),
        (&["deserialization"], "CWE-502"),
        (&["xxe", "xml-external"], "CWE-611"),
        (&["code-injection"], "CWE-94"),
        (&["log-injection"], "CWE-117"),
        (&["missing-authorization", "missing-auth"], "CWE-862"),
    ];
    CWE_PATTERNS
        .iter()
        .find_map(|(needles, cwe)| contains_any(lower_rule_id, needles).then_some(*cwe))
        .unwrap_or("CWE-CODEQL")
}

fn sarif_rule_to_taint_class(rule_id: &str) -> String {
    let lower = rule_id.to_ascii_lowercase();
    codeql_rule_taint_class_label(&lower).to_string()
}

fn codeql_rule_taint_class_label(lower_rule_id: &str) -> &'static str {
    const TAINT_CLASS_PATTERNS: &[(&[&str], &str)] = &[
        (&["sql-injection"], "sql-injection"),
        (&["path"], "path-traversal"),
        (&["command"], "os-command-injection"),
        (&["xss"], "xss"),
        (&["ssrf"], "ssrf"),
        (&["integer", "arithmetic"], "integer-overflow"),
    ];
    TAINT_CLASS_PATTERNS
        .iter()
        .find_map(|(needles, class)| contains_any(lower_rule_id, needles).then_some(*class))
        .unwrap_or("codeql")
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

pub(crate) fn codeql_flows_to_linked_stories(
    flows: &[CodeqlFlow],
) -> Vec<TaintIrisNextLinkedStory> {
    flows
        .iter()
        // Drop flows whose source or sink is rooted in a non-production
        // path (test harnesses, tutorials, fixtures). Same rationale as
        // the heuristic linker — postgres ships `src/tutorial/funcs.c`
        // as didactic example code that never runs in the production
        // server, so a CodeQL CWE-190 path through it is not an
        // exploitable finding even though the dataflow is real.
        .filter(|flow| {
            !is_taint_iris_next_non_production_path(&flow.file_path)
                && !flow
                    .steps
                    .iter()
                    .any(|step| is_taint_iris_next_non_production_path(&step.file))
        })
        .map(|flow| {
            let source_id = format!(
                "{}:source:{}:{}",
                flow.cwe, flow.file_path, flow.source_line
            );
            let sink_id = format!("{}:sink:{}:{}", flow.cwe, flow.file_path, flow.sink_line);
            let trace = flow
                .steps
                .iter()
                .map(|step| format!("{}:{} {}", step.file, step.line, truncate(&step.code, 120)))
                .collect::<Vec<_>>()
                .join(" -> ");
            TaintIrisNextLinkedStory {
                id: format!(
                    "codeql-{}:{}:{}-{}:{}:{}",
                    flow.cwe,
                    flow.file_path,
                    flow.source_line,
                    flow.cwe,
                    flow.file_path,
                    flow.sink_line
                ),
                cwe: flow.cwe.clone(),
                taint_class: flow.taint_class.clone(),
                track: "taint".to_string(),
                evidence_level: "path".to_string(),
                file_path: flow.file_path.clone(),
                language: language_for_path(Path::new(&flow.file_path)),
                source_candidate_id: source_id,
                sink_candidate_id: sink_id,
                source_line: flow.source_line,
                sink_line: flow.sink_line,
                shared_tokens: Vec::new(),
                rationale: format!("codeql {}: {} | path: {trace}", flow.rule_id, flow.message),
                callees: Vec::new(),
            }
        })
        .collect()
}

pub(crate) fn codeql_flows_to_candidates(flows: &[CodeqlFlow]) -> Vec<TaintIrisNextCandidate> {
    let mut out = Vec::new();
    for flow in flows {
        if is_taint_iris_next_non_production_path(&flow.file_path) {
            continue;
        }
        out.push(codeql_endpoint_candidate(
            flow,
            flow.source_line,
            &flow.source_code,
            "source",
        ));
        out.push(codeql_endpoint_candidate(
            flow,
            flow.sink_line,
            &flow.sink_code,
            "sink",
        ));
    }
    out
}

fn codeql_endpoint_candidate(
    flow: &CodeqlFlow,
    line: u32,
    code: &str,
    role: &str,
) -> TaintIrisNextCandidate {
    TaintIrisNextCandidate {
        id: format!("{}:{}:{}:{}", flow.cwe, role, flow.file_path, line),
        cwe: flow.cwe.clone(),
        taint_class: flow.taint_class.clone(),
        track: "taint".to_string(),
        role: role.to_string(),
        kind: taint_iris_next_kind_for_role(role).to_string(),
        pattern: "codeql-flow".to_string(),
        file_path: flow.file_path.clone(),
        line,
        snippet: truncate(code, 240),
        language: language_for_path(Path::new(&flow.file_path)),
        confidence: "high".to_string(),
        catalog_signal: format!("{role}: codeql ({})", flow.rule_id),
        source: "codeql".to_string(),
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max_chars).collect();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn codeql_dataflow_test_plan(scan_root: PathBuf) -> TaintIrisNextPlan {
        TaintIrisNextPlan {
            target: scan_root.clone(),
            scan_root,
            repo_root: PathBuf::from("."),
            source_paths: std::sync::Arc::from([]),
            mode: TaintIrisNextMode::Hunt,
            caps: dataflow_test_caps(),
            languages: vec!["cpp".to_string()],
            context_status: test_artifact_status(),
            threat_model_status: test_artifact_status(),
            repo_context: None,
            threat_model: None,
            catalog: vec![TaintIrisNextRankedCatalogEntry {
                cwe: "CWE-89".to_string(),
                name: "SQL injection".to_string(),
                taint_class: "sql-injection".to_string(),
                languages: vec!["cpp".to_string()],
                source_signals: vec!["input".to_string()],
                sink_signals: vec!["query".to_string()],
                sanitizer_signals: Vec::new(),
                structural_queries: Vec::new(),
                regex_markers: Vec::new(),
                score: 10,
                reasons: Vec::new(),
            }],
            structural_queries: Vec::new(),
            prompt_catalog: String::new(),
            backend: test_backend_choice(),
            max_budget_usd: None,
            allow_deterministic_fallback: false,
            system_prompt: taint_iris_next_system_prompt(),
            cwe_focus: Vec::new(),
            discovered_signals: DiscoveredSignals::default(),
        }
    }

    fn dataflow_test_caps() -> TaintIrisNextCaps {
        TaintIrisNextCaps {
            max_catalog_entries: 1,
            max_candidates_per_cwe: 10,
            max_evidence_per_cwe: 10,
            max_files_per_query: 10,
            max_specs_per_cwe: 10,
            max_agent_findings: 10,
            codeql_analyze_timeout_ms: 1000,
            min_evidence_level: "candidate".to_string(),
        }
    }

    fn test_artifact_status() -> TaintIrisNextArtifactStatus {
        TaintIrisNextArtifactStatus {
            ok: true,
            path: None,
            reason: "test".to_string(),
        }
    }

    fn test_backend_choice() -> TaintIrisNextBackendChoice {
        TaintIrisNextBackendChoice {
            requested: "codeql".to_string(),
            selected: "codeql".to_string(),
            codeql_db_path: None,
            corroborate_with_codeql: None,
            structural_tool: "test".to_string(),
            warnings: Vec::new(),
        }
    }

    #[test]
    #[cfg(unix)]
    fn run_codeql_flows_invokes_cli_and_parses_sarif() {
        let _guard = crate::test_env::codeql_bin_env_lock();
        let temp = tempdir().unwrap();
        let fake_codeql = write_fake_codeql_flow_script(temp.path());
        initialize_codeql_dataflow_repository(temp.path());
        let db = crate::workspace::workspace_codeql_db_path(temp.path());
        std::fs::create_dir_all(db.join("db-cpp")).unwrap();
        std::fs::write(db.join("codeql-database.yml"), "primaryLanguage: cpp\n").unwrap();
        crate::codeql_repository_execution::write_test_codeql_database_provenance(
            &db,
            temp.path(),
            "cpp",
        );

        let previous = std::env::var_os("KUZUSHI_CODEQL_BIN");
        std::env::set_var("KUZUSHI_CODEQL_BIN", &fake_codeql);
        let plan = codeql_dataflow_test_plan(temp.path().to_path_buf());

        let flows = run_codeql_flows(&plan).unwrap().expect("codeql flows");

        match previous {
            Some(value) => std::env::set_var("KUZUSHI_CODEQL_BIN", value),
            None => std::env::remove_var("KUZUSHI_CODEQL_BIN"),
        }

        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].cwe, "CWE-89");
        assert_eq!(flows[0].taint_class, "sql-injection");
        assert_eq!(flows[0].source_line, 3);
        assert_eq!(flows[0].sink_line, 9);
    }

    #[cfg(unix)]
    fn initialize_codeql_dataflow_repository(root: &Path) {
        run_codeql_dataflow_git(root, &["init", "-q"]);
        std::fs::write(root.join("tracked.cpp"), "int main() { return 0; }\n").unwrap();
        run_codeql_dataflow_git(root, &["add", "tracked.cpp", "codeql"]);
        run_codeql_dataflow_git(root, &["commit", "-qm", "initial"]);
    }

    #[cfg(unix)]
    fn run_codeql_dataflow_git(root: &Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .args(["-c", "user.email=test@example.invalid"])
            .args(["-c", "user.name=Kuzushi Test"])
            .args(args)
            .current_dir(root)
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    #[cfg(unix)]
    fn write_fake_codeql_flow_script(root: &Path) -> PathBuf {
        let fake_codeql = root.join("codeql");
        std::fs::write(&fake_codeql, fake_codeql_flow_script()).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&fake_codeql).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&fake_codeql, perms).unwrap();
        }
        fake_codeql
    }

    fn fake_codeql_flow_script() -> &'static str {
        r#"#!/usr/bin/env bash
set -euo pipefail
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    shift
    out="$1"
  fi
  shift || true
done
cat > "$out" <<'JSON'
{"runs":[{"tool":{"driver":{"rules":[]}},"results":[{"ruleId":"cpp/sql-injection","message":{"text":"sql injection"},"codeFlows":[{"threadFlows":[{"locations":[{"location":{"physicalLocation":{"artifactLocation":{"uri":"src/api.c"},"region":{"startLine":3,"snippet":{"text":"input = arg;"}}}}},{"location":{"physicalLocation":{"artifactLocation":{"uri":"src/db.c"},"region":{"startLine":9,"snippet":{"text":"query(input);"}}}}}]}]}]}]}]}
JSON
"#
    }

    #[test]
    fn cwe_from_rule_id_recognizes_common_codeql_rules() {
        assert_eq!(cwe_from_rule_id("cpp/sql-injection"), "CWE-89");
        assert_eq!(cwe_from_rule_id("js/path-injection"), "CWE-22");
        assert_eq!(cwe_from_rule_id("py/command-line-injection"), "CWE-78");
        assert_eq!(cwe_from_rule_id("cpp/integer-overflow"), "CWE-190");
        assert_eq!(cwe_from_rule_id("js/reflected-xss"), "CWE-79");
        assert_eq!(cwe_from_rule_id("cpp/array-out-of-bounds"), "CWE-CODEQL");
    }

    #[test]
    fn parse_sarif_flows_extracts_one_step_results_when_no_codeflows() {
        let sarif = r#"{
            "runs": [{
                "tool": {"driver": {"rules": []}},
                "results": [{
                    "ruleId": "cpp/sql-injection",
                    "message": {"text": "user input flows to query"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/users.c"},
                            "region": {"startLine": 12, "snippet": {"text": "Run(query);"}}
                        }
                    }]
                }]
            }]
        }"#;
        let flows = parse_sarif_flows(sarif);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].cwe, "CWE-89");
        assert_eq!(flows[0].file_path, "src/users.c");
        assert_eq!(flows[0].source_line, 12);
        assert_eq!(flows[0].steps.len(), 1);
    }

    #[test]
    fn parse_sarif_flows_uses_thread_flow_when_present() {
        let sarif = r#"{
            "runs": [{
                "tool": {"driver": {"rules": [{
                    "id": "cpp/path-injection",
                    "properties": {"tags": ["security", "external/cwe/cwe-22"]}
                }]}},
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
        let flows = parse_sarif_flows(sarif);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].cwe, "CWE-22");
        assert_eq!(flows[0].steps.len(), 2);
        assert_eq!(flows[0].steps[0].file, "src/api.c");
        assert_eq!(flows[0].steps[0].line, 10);
        assert_eq!(flows[0].steps[1].file, "src/io.c");
        assert_eq!(flows[0].steps[1].line, 99);
        assert_eq!(flows[0].source_line, 10);
        assert_eq!(flows[0].sink_line, 99);
    }

    #[test]
    fn codeql_queries_from_catalog_resolves_per_target_cwes_for_cpp() {
        let catalog = vec![
            TaintIrisNextRankedCatalogEntry {
                cwe: "CWE-89".to_string(),
                name: "SQL Injection".to_string(),
                taint_class: "sql-injection".to_string(),
                languages: vec!["c".to_string()],
                source_signals: vec![],
                sink_signals: vec![],
                sanitizer_signals: vec![],
                structural_queries: vec![],
                regex_markers: vec![],
                score: 80,
                reasons: vec![],
            },
            TaintIrisNextRankedCatalogEntry {
                cwe: "CWE-190".to_string(),
                name: "Integer Overflow".to_string(),
                taint_class: "integer-overflow".to_string(),
                languages: vec!["c".to_string()],
                source_signals: vec![],
                sink_signals: vec![],
                sanitizer_signals: vec![],
                structural_queries: vec![],
                regex_markers: vec![],
                score: 70,
                reasons: vec![],
            },
        ];
        let selectors = codeql_queries_from_catalog(&catalog, &["c".to_string()]);
        assert_eq!(
            selectors,
            vec![
                "codeql/cpp-queries:Security/CWE/CWE-089".to_string(),
                "codeql/cpp-queries:Security/CWE/CWE-190".to_string(),
            ]
        );
    }

    #[test]
    fn codeql_queries_from_catalog_dedupes_and_picks_python_pack() {
        let catalog = vec![
            TaintIrisNextRankedCatalogEntry {
                cwe: "CWE-89".to_string(),
                name: "SQL Injection".to_string(),
                taint_class: "sql-injection".to_string(),
                languages: vec!["python".to_string()],
                source_signals: vec![],
                sink_signals: vec![],
                sanitizer_signals: vec![],
                structural_queries: vec![],
                regex_markers: vec![],
                score: 80,
                reasons: vec![],
            },
            TaintIrisNextRankedCatalogEntry {
                cwe: "CWE-89".to_string(),
                name: "SQL Injection".to_string(),
                taint_class: "sql-injection".to_string(),
                languages: vec!["python".to_string()],
                source_signals: vec![],
                sink_signals: vec![],
                sanitizer_signals: vec![],
                structural_queries: vec![],
                regex_markers: vec![],
                score: 60,
                reasons: vec![],
            },
        ];
        let selectors = codeql_queries_from_catalog(&catalog, &["python".to_string()]);
        assert_eq!(
            selectors,
            vec!["codeql/python-queries:Security/CWE/CWE-089".to_string()]
        );
    }

    #[test]
    fn codeql_queries_from_catalog_returns_empty_for_unknown_language() {
        let catalog = vec![TaintIrisNextRankedCatalogEntry {
            cwe: "CWE-89".to_string(),
            name: "SQL Injection".to_string(),
            taint_class: "sql-injection".to_string(),
            languages: vec!["fortran".to_string()],
            source_signals: vec![],
            sink_signals: vec![],
            sanitizer_signals: vec![],
            structural_queries: vec![],
            regex_markers: vec![],
            score: 80,
            reasons: vec![],
        }];
        let selectors = codeql_queries_from_catalog(&catalog, &["fortran".to_string()]);
        assert!(selectors.is_empty());
    }

    #[test]
    fn codeql_cwe_folder_pads_three_digits() {
        assert_eq!(codeql_cwe_folder("CWE-89"), Some("CWE-089".to_string()));
        assert_eq!(codeql_cwe_folder("CWE-1078"), Some("CWE-1078".to_string()));
        assert_eq!(codeql_cwe_folder("CWE-22"), Some("CWE-022".to_string()));
        assert!(codeql_cwe_folder("not-a-cwe").is_none());
        assert!(codeql_cwe_folder("CWE-abc").is_none());
    }

    #[test]
    fn codeql_default_query_suite_picks_cpp_for_postgres() {
        assert_eq!(
            codeql_default_query_suite(&["c".to_string(), "cpp".to_string()]),
            "cpp-security-and-quality.qls"
        );
        assert_eq!(
            codeql_default_query_suite(&["python".to_string()]),
            "python-security-and-quality.qls"
        );
        assert_eq!(
            codeql_default_query_suite(&["typescript".to_string()]),
            "javascript-security-and-quality.qls"
        );
        assert_eq!(
            codeql_default_query_suite(&[]),
            "cpp-security-and-quality.qls"
        );
    }
}
