use super::*;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// Source-to-sink path discovered by Joern's `reachableByFlows`. Each step
/// is one CPG node visited along the dataflow path; the first step is the
/// source, the last is the sink. Lines are 1-based file lines.
#[derive(Debug, Clone)]
pub(in crate::modules) struct JoernFlow {
    pub(in crate::modules) cwe: String,
    pub(in crate::modules) taint_class: String,
    pub(in crate::modules) file_path: String,
    pub(in crate::modules) source_line: u32,
    pub(in crate::modules) sink_line: u32,
    pub(in crate::modules) source_code: String,
    pub(in crate::modules) sink_code: String,
    pub(in crate::modules) steps: Vec<JoernStep>,
}

#[derive(Debug, Clone)]
pub(in crate::modules) struct JoernStep {
    pub(in crate::modules) file: String,
    pub(in crate::modules) line: u32,
    pub(in crate::modules) code: String,
}

/// True iff a usable `joern` REPL launcher is on PATH (or under
/// `/opt/joern/joern-cli/`). The Scala flow script needs the full
/// REPL — `joern-parse` and `joern-flow` are insufficient.
pub(in crate::modules) fn joern_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| joern_launcher_path().is_some())
}

/// Resolve the absolute path to the Joern REPL launcher.
pub(in crate::modules) fn joern_launcher_path() -> Option<PathBuf> {
    if let Some(env_path) = std::env::var_os("KUZUSHI_JOERN_BIN") {
        let candidate = PathBuf::from(env_path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    for candidate in [
        PathBuf::from("/opt/joern/joern-cli/joern"),
        PathBuf::from("/usr/local/bin/joern"),
        PathBuf::from("/usr/bin/joern"),
    ] {
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// CPG file the Joern adapter expects under a target. Build with
/// `joern-parse <target> --output <target>/.kuzushi/cpg.bin`.
pub(in crate::modules) fn joern_cpg_path(target: &Path) -> PathBuf {
    target.join(".kuzushi").join("cpg.bin")
}

/// Locate the bundled Scala flow script. Same resolution strategy as the
/// pi-agent-core bridge: env override, source_root (via `current_exe`
/// walk-up), then the well-known repo-relative path.
fn flow_script_path() -> Option<PathBuf> {
    if let Some(env_path) = std::env::var_os("KUZUSHI_JOERN_FLOW_SCRIPT") {
        let candidate = PathBuf::from(env_path);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let mut dir = exe.parent()?.to_path_buf();
    for _ in 0..6 {
        let candidate = dir.join("scripts").join("taint_iris_next_flows.sc");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }
    let cwd = std::env::current_dir().ok()?;
    let cwd_candidate = cwd.join("scripts").join("taint_iris_next_flows.sc");
    cwd_candidate.exists().then_some(cwd_candidate)
}

/// Run Joern over the given CPG with one source/sink regex per ranked
/// catalog entry, return the flows it discovered. Returns `Ok(None)`
/// when Joern is unavailable, the CPG is missing, or the flow script
/// can't be located — callers can then fall back to the heuristic
/// linker without surfacing an error.
pub(in crate::modules) fn run_joern_flows(
    plan: &TaintIrisNextPlan,
) -> Result<Option<Vec<JoernFlow>>> {
    if !joern_available() {
        return Ok(None);
    }
    let cpg_path = joern_cpg_path(&plan.scan_root);
    if !cpg_path.exists() {
        return Ok(None);
    }
    let Some(launcher) = joern_launcher_path() else {
        return Ok(None);
    };
    let Some(script) = flow_script_path() else {
        return Ok(None);
    };

    let queries = build_joern_query_payload(&plan.catalog);
    if queries == "[]" {
        return Ok(Some(Vec::new()));
    }

    let queries_file = tempfile::NamedTempFile::new()
        .context("could not create joern queries tempfile")?;
    std::fs::write(queries_file.path(), &queries)
        .context("could not write joern queries tempfile")?;

    // Two-level timeout strategy. The script-level
    // KUZUSHI_JOERN_TIMEOUT_SECS bounds the whole joern invocation
    // (default 0 = wait forever). The script itself enforces a
    // per-CWE budget via KUZUSHI_JOERN_PER_CWE_TIMEOUT_MS (default
    // 60000ms) so one catastrophically broad CWE pattern doesn't
    // deadlock the hunt; that env var is read by the Scala script
    // and propagates naturally through `Command::env_clear`-free
    // spawn below.
    let timeout_secs: u64 = std::env::var("KUZUSHI_JOERN_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let child = Command::new(&launcher)
        .arg("--script")
        .arg(&script)
        .arg("--param")
        .arg(format!("cpgFile={}", cpg_path.display()))
        .arg("--param")
        .arg(format!("queriesFile={}", queries_file.path().display()))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("could not invoke joern at {}", launcher.display()))?;

    let mut child = child;
    let output = wait_with_optional_timeout(&mut child, timeout_secs)?;

    if !output.status.success() {
        anyhow::bail!(
            "joern exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).chars().take(800).collect::<String>()
        );
    }

    Ok(Some(parse_joern_jsonl(&output.stdout)))
}

/// Convert the ranked catalog into the JSON payload that
/// `scripts/taint_iris_next_flows.sc` expects. Each CWE entry becomes
/// one `{cwe, taintClass, sourceRegex, sinkRegex}` record.
fn build_joern_query_payload(catalog: &[TaintIrisNextRankedCatalogEntry]) -> String {
    let records: Vec<String> = catalog
        .iter()
        .filter_map(|entry| {
            let source_regex = patterns_to_substring_regex(&entry.source_signals)?;
            let sink_regex = patterns_to_substring_regex(&entry.sink_signals)?;
            Some(format!(
                "{{\"cwe\":{},\"taintClass\":{},\"sourceRegex\":{},\"sinkRegex\":{}}}",
                json_string(&entry.cwe),
                json_string(&entry.taint_class),
                json_string(&source_regex),
                json_string(&sink_regex),
            ))
        })
        .collect();
    format!("[{}]", records.join(","))
}

/// Build a wildcard-anchored alternation regex from a list of catalog
/// pattern strings. Joern's `cpg.call.code(...)` matches against the full
/// call-expression source text, so we wrap with `.*` to get a substring
/// match. Empty input returns `None` so the caller skips the CWE entirely
/// rather than running the unanchored `.*.*` (which matches every call
/// and explodes flow time).
fn patterns_to_substring_regex(patterns: &[String]) -> Option<String> {
    let alternatives: Vec<String> = patterns
        .iter()
        .filter_map(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return None;
            }
            Some(escape_regex_meta(trimmed))
        })
        .collect();
    if alternatives.is_empty() {
        return None;
    }
    Some(format!(".*({}).*", alternatives.join("|")))
}

fn escape_regex_meta(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if matches!(
            ch,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|'
        ) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

fn json_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    out.push('"');
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Parse the Scala script's JSON-Lines stdout. Lines that aren't valid
/// JSON or that don't carry the expected shape are skipped silently —
/// joern prefixes its run with `[INFO]` log noise when a project is
/// reloaded, and we don't want a single weird line to discard the whole
/// flow set.
fn parse_joern_jsonl(stdout: &[u8]) -> Vec<JoernFlow> {
    let stdout = String::from_utf8_lossy(stdout);
    let mut flows = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
            continue;
        }
        let value: Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let cwe = value.get("cwe").and_then(Value::as_str).unwrap_or("").to_string();
        let taint_class = value
            .get("taintClass")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let file_path = value
            .get("filePath")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let source_line = value
            .get("sourceLine")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32;
        let sink_line = value
            .get("sinkLine")
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32;
        let source_code = value
            .get("sourceCode")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let sink_code = value
            .get("sinkCode")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let steps = value
            .get("steps")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|step| {
                        Some(JoernStep {
                            file: step.get("file").and_then(Value::as_str)?.to_string(),
                            line: step.get("line").and_then(Value::as_u64)? as u32,
                            code: step.get("code").and_then(Value::as_str)?.to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        if cwe.is_empty() || file_path.is_empty() {
            continue;
        }
        flows.push(JoernFlow {
            cwe,
            taint_class,
            file_path,
            source_line,
            sink_line,
            source_code,
            sink_code,
            steps,
        });
    }
    flows
}

/// Adapt Joern flows into the `TaintIrisNextLinkedStory` shape kuzushi
/// already speaks. Each flow becomes one story whose source/sink
/// candidate ids are synthesised from the file:line of its endpoints,
/// `evidenceLevel = "path"` (we have an actual reaching path, not just
/// proximity), and `rationale` carries the full source-to-sink trace.
pub(in crate::modules) fn joern_flows_to_linked_stories(
    flows: &[JoernFlow],
) -> Vec<TaintIrisNextLinkedStory> {
    flows
        .iter()
        // Drop flows that originate or pass through non-production paths
        // (test harnesses, fixtures, tutorial code). See
        // taint_iris_next_line_matches.rs::is_taint_iris_next_non_production_path
        // for the rationale and the recognised path components.
        .filter(|flow| {
            !is_taint_iris_next_non_production_path(&flow.file_path)
                && !flow
                    .steps
                    .iter()
                    .any(|step| is_taint_iris_next_non_production_path(&step.file))
        })
        .map(|flow| {
            let source_id = format!("{}:source:{}:{}", flow.cwe, flow.file_path, flow.source_line);
            let sink_id = format!("{}:sink:{}:{}", flow.cwe, flow.file_path, flow.sink_line);
            let trace = flow
                .steps
                .iter()
                .map(|step| format!("{}:{} {}", step.file, step.line, truncate(&step.code, 120)))
                .collect::<Vec<_>>()
                .join(" -> ");
            TaintIrisNextLinkedStory {
                id: format!(
                    "joern-{}:{}:{}-{}:{}:{}",
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
                rationale: format!("joern reachableByFlows path: {trace}"),
                callees: extract_callees_from_flow_steps(&flow.steps),
            }
        })
        .collect()
}

/// Walk each `JoernStep.code` and pull out identifier-shaped tokens
/// that look like function calls: `identifier(...)`. Filters a small
/// set of control-flow / built-in / memcpy-family keywords that would
/// otherwise be the most common false matches. The resulting list
/// drives Thread B1's body inlining: every callee on the taint path
/// has its body included in the agent prompt so the model can audit
/// the upstream bound-check helpers (e.g. `pgp_mpi_alloc`,
/// `prepare_room`) inline.
fn extract_callees_from_flow_steps(steps: &[JoernStep]) -> Vec<String> {
    use std::collections::BTreeSet;
    static CALLEE_RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = CALLEE_RE
        .get_or_init(|| regex::Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\s*\(").unwrap());
    let skip: &[&str] = &[
        "if", "while", "for", "switch", "sizeof", "return", "case",
        "elog", "ereport", "Assert", "memcpy", "memmove", "memset",
        "strcpy", "strncpy", "strcat", "strncat", "sprintf", "snprintf",
        "palloc", "palloc0", "pfree", "repalloc",
    ];
    let mut out: BTreeSet<String> = BTreeSet::new();
    for step in steps {
        for cap in re.captures_iter(&step.code) {
            if let Some(name) = cap.get(1).map(|m| m.as_str()) {
                if skip.contains(&name) {
                    continue;
                }
                out.insert(name.to_string());
            }
        }
    }
    out.into_iter().collect()
}

/// Mint synthetic TaintIrisNextCandidate rows for each flow endpoint so
/// the agent prompt still sees a populated `candidates` list and the
/// linked-story IDs resolve to real candidate references.
pub(in crate::modules) fn joern_flows_to_candidates(
    flows: &[JoernFlow],
) -> Vec<TaintIrisNextCandidate> {
    let mut out = Vec::new();
    for flow in flows {
        if is_taint_iris_next_non_production_path(&flow.file_path) {
            continue;
        }
        out.push(joern_endpoint_candidate(
            flow,
            flow.source_line,
            &flow.source_code,
            "source",
        ));
        out.push(joern_endpoint_candidate(
            flow,
            flow.sink_line,
            &flow.sink_code,
            "sink",
        ));
    }
    out
}

fn joern_endpoint_candidate(
    flow: &JoernFlow,
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
        pattern: "joern-flow".to_string(),
        file_path: flow.file_path.clone(),
        line,
        snippet: truncate(code, 240),
        language: language_for_path(Path::new(&flow.file_path)),
        confidence: "high".to_string(),
        catalog_signal: format!("{role}: joern-flow"),
        source: "joern".to_string(),
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

    fn entry(cwe: &str, sources: &[&str], sinks: &[&str]) -> TaintIrisNextRankedCatalogEntry {
        TaintIrisNextRankedCatalogEntry {
            cwe: cwe.to_string(),
            name: format!("{cwe} (test)"),
            taint_class: "test".to_string(),
            score: 50,
            languages: vec!["any".to_string()],
            source_signals: sources.iter().map(|s| s.to_string()).collect(),
            sink_signals: sinks.iter().map(|s| s.to_string()).collect(),
            sanitizer_signals: vec![],
            structural_queries: vec![],
            reasons: vec![],
        }
    }

    #[test]
    fn build_joern_query_payload_emits_per_cwe_records() {
        let catalog = vec![
            entry("CWE-89", &["req.query", "request.args"], &[".query(", ".execute("]),
            entry("CWE-22", &["filename"], &["fopen(", ".readFile"]),
        ];
        let payload = build_joern_query_payload(&catalog);
        assert!(payload.contains("\"cwe\":\"CWE-89\""));
        assert!(payload.contains("\"cwe\":\"CWE-22\""));
        // Regex meta-chars are escaped with `\` and then re-escaped for the
        // JSON wrapper, so a `.` in the input becomes `\\.` in the on-disk
        // bytes (Scala's JSON parser will unescape that back to `\.` — a
        // literal dot match in regex).
        assert!(payload.contains(r"req\\.query"));
        assert!(payload.contains(r"request\\.args"));
        assert!(payload.contains(r"\\.query\\("));
        assert!(payload.contains(r"fopen\\("));
    }

    #[test]
    fn build_joern_query_payload_skips_cwes_with_empty_signals() {
        let catalog = vec![
            entry("CWE-NoSrc", &[], &[".execute("]),
            entry("CWE-NoSink", &["req.query"], &[]),
            entry("CWE-Real", &["req.query"], &[".execute("]),
        ];
        let payload = build_joern_query_payload(&catalog);
        assert!(!payload.contains("CWE-NoSrc"));
        assert!(!payload.contains("CWE-NoSink"));
        assert!(payload.contains("CWE-Real"));
    }

    #[test]
    fn parse_joern_jsonl_skips_log_noise_and_keeps_flow_records() {
        let stdout = b"[INFO] loading project\n\
{\"cwe\":\"CWE-89\",\"taintClass\":\"sql-injection\",\"filePath\":\"src/users.ts\",\"sourceLine\":12,\"sinkLine\":13,\"sourceCode\":\"req.query.id\",\"sinkCode\":\"db.query(...)\",\"steps\":[{\"file\":\"src/users.ts\",\"line\":12,\"code\":\"req.query.id\"},{\"file\":\"src/users.ts\",\"line\":13,\"code\":\"db.query(req.query.id)\"}]}\n\
[INFO] writing to storage\n";
        let flows = parse_joern_jsonl(stdout);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].cwe, "CWE-89");
        assert_eq!(flows[0].source_line, 12);
        assert_eq!(flows[0].sink_line, 13);
        assert_eq!(flows[0].steps.len(), 2);
    }

    #[test]
    fn flows_with_path_evidence_become_linked_stories() {
        let flow = JoernFlow {
            cwe: "CWE-89".to_string(),
            taint_class: "sql-injection".to_string(),
            file_path: "src/users.ts".to_string(),
            source_line: 12,
            sink_line: 13,
            source_code: "req.query.id".to_string(),
            sink_code: "db.query(req.query.id)".to_string(),
            steps: vec![
                JoernStep {
                    file: "src/users.ts".to_string(),
                    line: 12,
                    code: "req.query.id".to_string(),
                },
                JoernStep {
                    file: "src/users.ts".to_string(),
                    line: 13,
                    code: "db.query(req.query.id)".to_string(),
                },
            ],
        };
        let stories = joern_flows_to_linked_stories(&[flow]);
        assert_eq!(stories.len(), 1);
        assert_eq!(stories[0].evidence_level, "path");
        assert!(stories[0].rationale.contains("joern reachableByFlows"));
    }

    #[test]
    fn escape_regex_meta_handles_dots_and_parens() {
        assert_eq!(escape_regex_meta("req.query"), "req\\.query");
        assert_eq!(escape_regex_meta(".execute("), "\\.execute\\(");
        assert_eq!(escape_regex_meta("plain"), "plain");
    }

    #[test]
    fn extract_callees_from_flow_steps_picks_function_calls() {
        // Joern's flow steps carry one line of code per step. The
        // extractor should pull identifier-shaped tokens followed by
        // `(` — that's how upstream bound-check helpers like
        // `pgp_mpi_alloc` and `prepare_room` get into the
        // relaxed_names set for Thread B2's body inlining. Built-in
        // / control-flow / memcpy-family names are skipped so we
        // don't waste body-slots on them.
        let steps = vec![
            JoernStep {
                file: "f.c".to_string(),
                line: 10,
                code: "res = pgp_mpi_read(src, &c1);".to_string(),
            },
            JoernStep {
                file: "f.c".to_string(),
                line: 20,
                code: "if (sess_key_len > PGP_MAX_KEY) return 0;".to_string(),
            },
            JoernStep {
                file: "f.c".to_string(),
                line: 30,
                code: "prepare_room(dst, len);".to_string(),
            },
            JoernStep {
                file: "f.c".to_string(),
                line: 40,
                code: "memcpy(ctx->sess_key, msg + 1, sess_key_len);".to_string(),
            },
        ];
        let callees = extract_callees_from_flow_steps(&steps);
        // The two real upstream callees should appear.
        assert!(callees.contains(&"pgp_mpi_read".to_string()), "got {callees:?}");
        assert!(callees.contains(&"prepare_room".to_string()), "got {callees:?}");
        // Skip-list keywords / sinks should NOT appear.
        assert!(!callees.contains(&"if".to_string()));
        assert!(!callees.contains(&"memcpy".to_string()));
    }
}
