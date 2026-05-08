use super::*;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::OnceLock;

/// Wait for a child process to exit. When `timeout_secs == 0` we block
/// indefinitely (semantic: "no timeout, however long the analysis
/// takes"). When non-zero we poll every 2s and kill on deadline.
pub(in crate::modules) fn wait_with_optional_timeout(
    child: &mut Child,
    timeout_secs: u64,
) -> anyhow::Result<std::process::Output> {
    if timeout_secs == 0 {
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let status = child
            .wait()
            .context("could not wait for child process")?;
        let stdout = read_optional_pipe(stdout);
        let stderr = read_optional_pipe(stderr);
        return Ok(std::process::Output {
            status,
            stdout,
            stderr,
        });
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    anyhow::bail!(
                        "child exceeded {timeout_secs}s timeout; set the relevant *_TIMEOUT_SECS=0 to disable"
                    );
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                anyhow::bail!("could not poll child process: {error}");
            }
        }
    }
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let status = child.wait().context("could not finalise child")?;
    Ok(std::process::Output {
        status,
        stdout: read_optional_pipe(stdout),
        stderr: read_optional_pipe(stderr),
    })
}

fn read_optional_pipe<R: std::io::Read>(pipe: Option<R>) -> Vec<u8> {
    let Some(mut pipe) = pipe else {
        return Vec::new();
    };
    let mut buf = Vec::new();
    let _ = pipe.read_to_end(&mut buf);
    buf
}

/// True iff a usable `codeql` CLI is on PATH (or under `/opt/codeql/`).
pub(in crate::modules) fn codeql_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| codeql_launcher_path().is_some())
}

/// Resolve the CodeQL CLI launcher.
pub(in crate::modules) fn codeql_launcher_path() -> Option<PathBuf> {
    if let Some(env_path) = std::env::var_os("KUZUSHI_CODEQL_BIN") {
        let candidate = PathBuf::from(env_path);
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

/// Standard locations kuzushi expects for an existing CodeQL DB.
pub(in crate::modules) fn codeql_db_path(repo_root: &Path) -> Option<PathBuf> {
    for relative in [".kuzushi/codeql-db", ".codeql/db"] {
        let candidate = repo_root.join(relative);
        if candidate.exists() && candidate.is_dir() {
            return Some(candidate);
        }
    }
    None
}

/// One source-to-sink path discovered by a CodeQL query, distilled from
/// SARIF. Mirrors `JoernFlow` so the rest of the pipeline doesn't care
/// which engine produced the result.
#[derive(Debug, Clone)]
pub(in crate::modules) struct CodeqlFlow {
    pub(in crate::modules) cwe: String,
    pub(in crate::modules) taint_class: String,
    pub(in crate::modules) file_path: String,
    pub(in crate::modules) source_line: u32,
    pub(in crate::modules) sink_line: u32,
    pub(in crate::modules) source_code: String,
    pub(in crate::modules) sink_code: String,
    pub(in crate::modules) steps: Vec<CodeqlStep>,
    pub(in crate::modules) rule_id: String,
    pub(in crate::modules) message: String,
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct CodeqlStep {
    pub(in crate::modules) file: String,
    pub(in crate::modules) line: u32,
    pub(in crate::modules) code: String,
}

/// Run a CodeQL security-and-quality query suite against the DB at
/// `<target>/.kuzushi/codeql-db` and return the resulting source-to-sink
/// flows. Returns `Ok(None)` when CodeQL is unavailable, the DB is
/// missing, or the query suite isn't installed — callers fall back to
/// joern or the heuristic linker without surfacing an error.
pub(in crate::modules) fn run_codeql_flows(
    plan: &TaintIrisNextPlan,
) -> Result<Option<Vec<CodeqlFlow>>> {
    if !codeql_available() {
        return Ok(None);
    }
    let Some(db_path) = codeql_db_path(&plan.scan_root) else {
        return Ok(None);
    };
    let Some(launcher) = codeql_launcher_path() else {
        return Ok(None);
    };

    // Pick what to run. Order of preference:
    //  1. Per-target catalog CWEs -> resolve to specific .ql files inside
    //     the pack so we only run queries the agent considers relevant
    //     to this codebase. Cuts a 179-query suite down to ~12-20 queries
    //     on a typical postgres run.
    //  2. KUZUSHI_CODEQL_QUERY_SUITE env override (a path or `<lang>-...qls`).
    //  3. The default `<lang>-security-and-quality.qls` for the dominant
    //     language.
    let env_override = std::env::var("KUZUSHI_CODEQL_QUERY_SUITE")
        .ok()
        .and_then(|s| {
            let trimmed = s.trim().to_string();
            (!trimmed.is_empty()).then_some(trimmed)
        });
    let catalog_queries =
        filter_existing_codeql_selectors(codeql_queries_from_catalog(&plan.catalog, &plan.languages));
    let queries: Vec<String> = if let Some(override_value) = env_override {
        vec![override_value]
    } else if !catalog_queries.is_empty() {
        catalog_queries
    } else {
        vec![codeql_default_query_suite(&plan.languages)]
    };

    // Default: no wall-clock timeout. CodeQL's cpp-security-and-quality
    // suite has 179 queries covering 79 CWEs and routinely takes hours
    // on a postgres-scale DB; an aggressive timeout silently corrupts
    // results by aborting mid-suite. Operators who need a deadline can
    // set KUZUSHI_CODEQL_TIMEOUT_SECS to a positive number; setting it
    // to 0 (or leaving it unset) means "wait forever."
    let timeout_secs: u64 = std::env::var("KUZUSHI_CODEQL_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let sarif_file = tempfile::NamedTempFile::new()
        .context("could not create codeql sarif tempfile")?;

    let mut command = Command::new(&launcher);
    command
        .arg("database")
        .arg("analyze")
        .arg("--format=sarif-latest")
        .arg("--output")
        .arg(sarif_file.path())
        .arg("--ram=4096")
        .arg("--threads=4")
        .arg(db_path.as_path());
    for query in &queries {
        command.arg(query);
    }
    let output = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("could not invoke codeql at {}", launcher.display()))
        .and_then(|mut child| wait_with_optional_timeout(&mut child, timeout_secs))?;

    if !output.status.success() {
        anyhow::bail!(
            "codeql exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(800)
                .collect::<String>()
        );
    }

    let sarif = std::fs::read_to_string(sarif_file.path())
        .context("could not read codeql SARIF output")?;
    Ok(Some(parse_sarif_flows(&sarif)))
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
    let code_flows = result.get("codeFlows").and_then(Value::as_array)?;
    let first_flow = code_flows.first()?;
    let thread_flows = first_flow.get("threadFlows").and_then(Value::as_array)?;
    let first_thread = thread_flows.first()?;
    let locations = first_thread.get("locations").and_then(Value::as_array)?;
    let steps: Vec<CodeqlStep> = locations
        .iter()
        .filter_map(|location| {
            sarif_location_to_step(location.get("location").unwrap_or(location))
        })
        .collect();
    if steps.is_empty() {
        None
    } else {
        Some(steps)
    }
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
            if let Some(tags) = rule
                .pointer("/properties/tags")
                .and_then(Value::as_array)
            {
                for tag in tags.iter().filter_map(Value::as_str) {
                    if let Some(stripped) = tag.strip_prefix("external/cwe/cwe-") {
                        let normalized = stripped.trim_start_matches('0');
                        return format!("CWE-{}", if normalized.is_empty() { "0" } else { normalized });
                    }
                }
            }
        }
    }
    cwe_from_rule_id(rule_id)
}

fn cwe_from_rule_id(rule_id: &str) -> String {
    let lower = rule_id.to_ascii_lowercase();
    if lower.contains("sql-injection") {
        "CWE-89".to_string()
    } else if lower.contains("path-injection") || lower.contains("path-traversal") {
        "CWE-22".to_string()
    } else if lower.contains("command-injection") || lower.contains("command-line-injection") {
        "CWE-78".to_string()
    } else if lower.contains("xss") || lower.contains("cross-site-scripting") {
        "CWE-79".to_string()
    } else if lower.contains("ssrf") || lower.contains("server-side-request-forgery") {
        "CWE-918".to_string()
    } else if lower.contains("integer-overflow") || lower.contains("arithmetic-overflow") {
        "CWE-190".to_string()
    } else if lower.contains("deserialization") {
        "CWE-502".to_string()
    } else if lower.contains("xxe") || lower.contains("xml-external") {
        "CWE-611".to_string()
    } else if lower.contains("code-injection") {
        "CWE-94".to_string()
    } else if lower.contains("log-injection") {
        "CWE-117".to_string()
    } else if lower.contains("missing-authorization") || lower.contains("missing-auth") {
        "CWE-862".to_string()
    } else {
        "CWE-CODEQL".to_string()
    }
}

fn sarif_rule_to_taint_class(rule_id: &str) -> String {
    let lower = rule_id.to_ascii_lowercase();
    if lower.contains("sql-injection") {
        "sql-injection".to_string()
    } else if lower.contains("path") {
        "path-traversal".to_string()
    } else if lower.contains("command") {
        "os-command-injection".to_string()
    } else if lower.contains("xss") {
        "xss".to_string()
    } else if lower.contains("ssrf") {
        "ssrf".to_string()
    } else if lower.contains("integer") || lower.contains("arithmetic") {
        "integer-overflow".to_string()
    } else {
        "codeql".to_string()
    }
}

pub(in crate::modules) fn codeql_flows_to_linked_stories(
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
            let source_id =
                format!("{}:source:{}:{}", flow.cwe, flow.file_path, flow.source_line);
            let sink_id =
                format!("{}:sink:{}:{}", flow.cwe, flow.file_path, flow.sink_line);
            let trace = flow
                .steps
                .iter()
                .map(|step| {
                    format!(
                        "{}:{} {}",
                        step.file,
                        step.line,
                        truncate(&step.code, 120)
                    )
                })
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
                rationale: format!(
                    "codeql {}: {} | path: {trace}",
                    flow.rule_id, flow.message
                ),
            }
        })
        .collect()
}

pub(in crate::modules) fn codeql_flows_to_candidates(
    flows: &[CodeqlFlow],
) -> Vec<TaintIrisNextCandidate> {
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
                score: 60,
                reasons: vec![],
            },
        ];
        let selectors =
            codeql_queries_from_catalog(&catalog, &["python".to_string()]);
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
            score: 80,
            reasons: vec![],
        }];
        let selectors =
            codeql_queries_from_catalog(&catalog, &["fortran".to_string()]);
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
