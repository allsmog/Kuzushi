//! In-process `cpg_taint_paths` dataflow tool for the deep auditor.
//!
//! `kuzushi_cpg::Project` is `!Send`, but `ToolBox::register` requires a
//! `Send` handler. We resolve this by keeping the projects in a thread-local,
//! single-root cache warmed once (via [`open_cpg_taint_engine`]) before the
//! passes loop; the registered closure captures only a `PathBuf` and an
//! `Option<&TraceHandle>` and runs on the calling thread, so the non-`Send`
//! projects never cross a thread boundary. A bulk `triage:run scope=all` loads
//! the graph once per worker thread, not once per finding.

use super::super::domain::TaintToolPolicy;
use crate::run_artifacts::TraceHandle;
use crate::runtime::{AgentTool, ToolCall, ToolResult};
use anyhow::Result;
use kuzushi_cpg::{
    artifact_langs, detect_buildable_languages, ensure_project_in, harvest_regex_spec,
    has_artifacts, open_project_in, run_taint_query, BuildLimits, BuildScope, Project,
    MAX_FLOWS_PER_QUERY,
};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::path::{Path, PathBuf};

/// Tool spec advertised to the model. Regex examples steer the model toward
/// call-name patterns; the fidelity caveat is stated verbatim so it does not
/// treat an empty result as proof of safety.
pub(crate) fn cpg_taint_paths_tool() -> AgentTool {
    AgentTool {
        name: "cpg_taint_paths".to_string(),
        description: "Query the in-process code property graph for taint flows from a source \
                      call/parameter pattern to a sink call pattern. Both `source` and `sink` are \
                      regexes matched against call names/code, e.g. source `req\\.query` or \
                      `PG_GETARG`, sink `memcpy|strcpy` or `query`. Returns witnessed flows with \
                      steps and any `guard`/`authz` annotation on the path. Fidelity caveat: \
                      cpg-rs taint is name-based (summaries-first), not SSA/IFDS — recall-first, \
                      so a non-empty flow is evidence to verify by reading, and an empty flowCount \
                      is NOT evidence of safety."
            .to_string(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "source": { "type": "string", "description": "Regex for the source call/param, e.g. req\\.query" },
                "sink":   { "type": "string", "description": "Regex for the sink call, e.g. memcpy|strcpy" },
                "patternMode": { "type": "string", "enum": ["regex", "literal"], "default": "regex" },
                "maxPaths": { "type": "integer", "description": "Max flows to return (default 10)." }
            },
            "required": ["source", "sink"]
        }),
    }
}

/// Whether the auditor can be offered dataflow tools, resolved once per audit.
/// Holds no `Project`, so it is `Send`/`Debug` and testable off-graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CpgTaintReadiness {
    /// Policy is `off`; the graph was never touched.
    Disabled,
    /// No usable graph; the auditor stays grep-only.
    Missing { hint: String },
    /// Graph(s) loaded for these languages.
    Ready { languages: Vec<String> },
    /// A build/load attempt failed.
    Failed { reason: String },
}

thread_local! {
    static PROJECTS: RefCell<Option<(PathBuf, Vec<(String, Project)>)>> =
        const { RefCell::new(None) };
    static READINESS_REPORTED: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    /// A load/build attempt that failed for `root`, cached so a persistently
    /// failing graph is resolved once per (root, thread) instead of being
    /// re-attempted for every finding in a bulk triage.
    static FAILED: RefCell<Option<(PathBuf, String)>> = const { RefCell::new(None) };
    /// A resolved "no usable graph" for `root`, cached alongside `Ready`/`Failed`
    /// so the `Build` policy's zero-language branch runs its whole-source-tree
    /// `detect_buildable_languages` walk once per (root, thread), not once per
    /// finding. Caching for the thread's lifetime is acceptable: a genuine
    /// `cpg:build` landing between two calls on the SAME thread is rare (the TUI
    /// spawns a fresh thread per run, which resets this cache), and it matches
    /// how `Ready`/`Failed` are already cached.
    static MISSING: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

// Test-observable count of `detect_buildable_languages` invocations per
// thread, proving the whole-source-tree language walk is gated behind the
// cache and runs at most once per (root, thread) rather than per finding.
#[cfg(test)]
thread_local! {
    static DETECTIONS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

fn record_detection() {
    #[cfg(test)]
    DETECTIONS.with(|cell| cell.set(cell.get() + 1));
}

#[cfg(test)]
fn detection_count() -> u32 {
    DETECTIONS.with(std::cell::Cell::get)
}

/// Resolve readiness once per audit before the passes loop, warming the
/// thread-local cache and emitting a single readiness trace line per root.
pub(crate) fn open_cpg_taint_engine(
    root: &Path,
    policy: TaintToolPolicy,
    trace: Option<&TraceHandle>,
) -> CpgTaintReadiness {
    let readiness = resolve_readiness(root, policy);
    report_readiness_once(trace, root, &readiness);
    readiness
}

fn resolve_readiness(root: &Path, policy: TaintToolPolicy) -> CpgTaintReadiness {
    match policy {
        TaintToolPolicy::Off => CpgTaintReadiness::Disabled,
        TaintToolPolicy::Available => available_readiness(root),
        TaintToolPolicy::Build => build_readiness(root),
    }
}

/// `Available` serves an EXISTING on-disk graph as a hint. It never builds or
/// rebuilds from source — a stale graph is loaded as-is (the auditor treats
/// taint as a recall-first hint, not proof), and only a genuinely missing
/// graph is `Missing`. The freshness-driven rebuild lives in `Build`.
fn available_readiness(root: &Path) -> CpgTaintReadiness {
    if let Some(cached) = cached_readiness(root) {
        return cached;
    }
    if !has_artifacts(root) {
        return store_missing(root);
    }
    load_projects(root, artifact_langs(root))
}

/// `Build` is the only policy allowed to compile a graph from source, so the
/// whole-source-tree language detection walk runs here — but only on a cache
/// miss, so a 500-finding bulk triage detects once per (root, thread), not
/// once per finding.
fn build_readiness(root: &Path) -> CpgTaintReadiness {
    if let Some(cached) = cached_readiness(root) {
        return cached;
    }
    record_detection();
    let langs: Vec<String> = detect_buildable_languages(root)
        .iter()
        .map(|lang| lang.to_string())
        .collect();
    if langs.is_empty() {
        return store_missing(root);
    }
    match build_projects(root, &langs) {
        Ok(projects) => store_projects(root, projects),
        Err(reason) => store_failure(root, reason),
    }
}

fn missing_readiness() -> CpgTaintReadiness {
    CpgTaintReadiness::Missing {
        hint: "no cpg graph; run cpg:build".to_string(),
    }
}

/// Cache a resolved "no usable graph" for `root` and return it, so a repeat
/// resolution on the same thread short-circuits before re-walking the source
/// tree (`Build`) or re-probing the artifact dir (`Available`).
fn store_missing(root: &Path) -> CpgTaintReadiness {
    MISSING.with(|cell| *cell.borrow_mut() = Some(root.to_path_buf()));
    missing_readiness()
}

fn cached_missing(root: &Path) -> bool {
    MISSING.with(|cell| cell.borrow().as_deref() == Some(root))
}

/// Return a `Ready` (warm cache), `Failed` (cached prior failure), or `Missing`
/// (cached "no usable graph") readiness for `root` without re-touching the
/// filesystem. `None` means none is cached and the caller must resolve
/// readiness for the first time.
fn cached_readiness(root: &Path) -> Option<CpgTaintReadiness> {
    if cached_for(root) {
        return Some(CpgTaintReadiness::Ready {
            languages: cached_langs(),
        });
    }
    if let Some(reason) = cached_failure(root) {
        return Some(CpgTaintReadiness::Failed { reason });
    }
    cached_missing(root).then(missing_readiness)
}

/// Load (never build) each language's persisted graph into the thread-local
/// cache. A decode failure is cached as `Failed` so it is not re-attempted.
fn load_projects(root: &Path, langs: Vec<String>) -> CpgTaintReadiness {
    if langs.is_empty() {
        return store_missing(root);
    }
    let scope = BuildScope::whole(root);
    let mut projects = Vec::new();
    for lang in &langs {
        match open_project_in(&scope, lang) {
            Some(project) => projects.push((lang.clone(), project)),
            None => return store_failure(root, format!("cannot load cpg graph for {lang}")),
        }
    }
    store_projects(root, projects)
}

fn cached_failure(root: &Path) -> Option<String> {
    FAILED.with(|cell| {
        cell.borrow()
            .as_ref()
            .and_then(|(cached, reason)| (cached == root).then(|| reason.clone()))
    })
}

fn store_failure(root: &Path, reason: String) -> CpgTaintReadiness {
    FAILED.with(|cell| *cell.borrow_mut() = Some((root.to_path_buf(), reason.clone())));
    CpgTaintReadiness::Failed { reason }
}

fn build_projects(root: &Path, langs: &[String]) -> Result<Vec<(String, Project)>, String> {
    let scope = BuildScope::whole(root);
    let limits = BuildLimits::default();
    let mut projects = Vec::new();
    for lang in langs {
        let (project, _report) = ensure_project_in(&scope, lang, &limits)?;
        projects.push((lang.clone(), project));
    }
    Ok(projects)
}

fn store_projects(root: &Path, projects: Vec<(String, Project)>) -> CpgTaintReadiness {
    let languages = projects.iter().map(|(lang, _)| lang.clone()).collect();
    PROJECTS.with(|cell| *cell.borrow_mut() = Some((root.to_path_buf(), projects)));
    CpgTaintReadiness::Ready { languages }
}

fn cached_for(root: &Path) -> bool {
    PROJECTS.with(|cell| {
        cell.borrow()
            .as_ref()
            .is_some_and(|(cached, _)| cached == root)
    })
}

fn cached_langs() -> Vec<String> {
    PROJECTS.with(|cell| {
        cell.borrow()
            .as_ref()
            .map_or_else(Vec::new, |(_, projects)| {
                projects.iter().map(|(lang, _)| lang.clone()).collect()
            })
    })
}

fn with_projects<T>(root: &Path, f: impl FnOnce(&[(String, Project)]) -> T) -> Option<T> {
    PROJECTS.with(|cell| {
        let borrow = cell.borrow();
        match borrow.as_ref() {
            Some((cached, projects)) if cached == root => Some(f(projects)),
            _ => None,
        }
    })
}

struct TaintPathsArgs {
    source: String,
    sink: String,
    max_paths: usize,
}

/// Dispatch a `cpg_taint_paths` call. Mirrors `read_definition`'s convention:
/// always returns `Ok`, never an `Err` (which would abort the tool loop);
/// failures are structured `is_error: true` results.
pub(crate) fn handle_cpg_taint_paths(
    root: &Path,
    trace: Option<&TraceHandle>,
    call: &ToolCall,
) -> Result<ToolResult> {
    let args = match parse_taint_paths_args(call) {
        Ok(args) => args,
        Err(error) => return Ok(error_result(call, &error.to_string())),
    };
    let Some(envelope) = with_projects(root, |projects| collect_flows(projects, &args)) else {
        return Ok(missing_graph_result(call));
    };
    let envelope = match envelope {
        Ok(envelope) => envelope,
        Err(error) => return Ok(error_result(call, &error.to_string())),
    };
    report_query(trace, &args, &envelope);
    Ok(success_result(call, &args, envelope))
}

fn parse_taint_paths_args(call: &ToolCall) -> Result<TaintPathsArgs> {
    Ok(TaintPathsArgs {
        source: required_pattern(&call.input, "source")?,
        sink: required_pattern(&call.input, "sink")?,
        max_paths: call
            .input
            .get("maxPaths")
            .and_then(Value::as_u64)
            .map(|value| value.clamp(1, MAX_FLOWS_PER_QUERY as u64) as usize)
            .unwrap_or(10),
    })
}

fn required_pattern(input: &Value, key: &str) -> Result<String> {
    let pattern = input
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            anyhow::anyhow!("cpg_taint_paths: `{key}` is required and must be non-empty")
        })?;
    let mode = input.get("patternMode").map_or(Ok("regex"), |value| {
        value
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("patternMode must be a string"))
    })?;
    kuzushi_cpg::compile_query_pattern(&pattern, mode).map_err(anyhow::Error::msg)
}

#[derive(Default)]
struct FlowEnvelope {
    source_calls: usize,
    entry_methods: usize,
    sink_calls: usize,
    /// True when flows or whole languages were dropped at the `max_paths` cap,
    /// so a consumer knows the `sourceCounts`/`sinkCount`/`flows` are partial.
    truncated: bool,
    flows: Vec<Value>,
}

fn collect_flows(projects: &[(String, Project)], args: &TaintPathsArgs) -> Result<FlowEnvelope> {
    let mut envelope = FlowEnvelope::default();
    for (lang, project) in projects {
        collect_language_flows(&mut envelope, lang, project, args)?;
    }
    if envelope.flows.len() > args.max_paths {
        envelope.flows.truncate(args.max_paths);
        envelope.truncated = true;
    }
    Ok(envelope)
}

fn collect_language_flows(
    envelope: &mut FlowEnvelope,
    lang: &str,
    project: &Project,
    args: &TaintPathsArgs,
) -> Result<()> {
    if envelope.flows.len() >= args.max_paths {
        // The flow cap is already full, so this whole language is skipped
        // unexamined — disclose that the result is partial.
        envelope.truncated = true;
        return Ok(());
    }
    let harvested =
        harvest_regex_spec(project, &args.source, &args.sink).map_err(anyhow::Error::msg)?;
    envelope.source_calls += harvested.source_call_matches;
    envelope.entry_methods += harvested.entry_methods.len();
    envelope.sink_calls += harvested.sink_call_matches;
    let (findings, stats) = run_taint_query(project, &harvested);
    envelope.truncated |=
        stats.flow_count_before_cap > findings.len() || !stats.truncated_categories.is_empty();
    for finding in &findings {
        if envelope.flows.len() >= args.max_paths {
            envelope.truncated = true;
            break;
        }
        envelope.flows.push(flow_value(lang, finding));
    }
    Ok(())
}

/// Verbatim copy of the mcp-cpg `flow_json`, keeping `guard`/`authz` — the
/// falsification evidence the auditor and operator must see.
fn flow_value(lang: &str, finding: &kuzushi_cpg::Finding) -> Value {
    let steps: Vec<Value> = finding
        .path
        .iter()
        .map(|step| json!({"code": step.code, "line": step.line, "depth": step.depth}))
        .collect();
    json!({
        "language": lang,
        "method": finding.method,
        "sink": finding.sink,
        "sinkFile": finding.sink_file,
        "sinkLine": finding.sink_line,
        "origin": finding.origin,
        "guard": finding.guard,
        "authz": finding.authz,
        "steps": steps,
    })
}

fn success_result(call: &ToolCall, args: &TaintPathsArgs, envelope: FlowEnvelope) -> ToolResult {
    ToolResult {
        call_id: call.call_id.clone(),
        output: json!({
            "source": args.source,
            "sink": args.sink,
            "engine": "cpg-rs",
            "sourceCounts": {
                "calls": envelope.source_calls,
                "methodParams": envelope.entry_methods,
            },
            "sinkCount": envelope.sink_calls,
            "flowCount": envelope.flows.len(),
            "truncated": envelope.truncated,
            "flows": envelope.flows,
        }),
        is_error: false,
    }
}

fn missing_graph_result(call: &ToolCall) -> ToolResult {
    error_result(call, "no cpg graph; run cpg:build")
}

fn error_result(call: &ToolCall, message: &str) -> ToolResult {
    ToolResult {
        call_id: call.call_id.clone(),
        output: json!({ "error": message }),
        is_error: true,
    }
}

fn report_readiness_once(trace: Option<&TraceHandle>, root: &Path, readiness: &CpgTaintReadiness) {
    let Some(trace) = trace else { return };
    if !mark_reported(root) {
        return;
    }
    emit_readiness_line(trace, readiness);
}

fn mark_reported(root: &Path) -> bool {
    READINESS_REPORTED.with(|cell| {
        let mut borrow = cell.borrow_mut();
        if borrow.as_deref() == Some(root) {
            return false;
        }
        *borrow = Some(root.to_path_buf());
        true
    })
}

fn emit_readiness_line(trace: &TraceHandle, readiness: &CpgTaintReadiness) {
    match readiness {
        CpgTaintReadiness::Ready { languages } => {
            let label = format!("taint tooling · ready ({})", languages.join(", "));
            let _ = trace.step("tool-progress", "run", label).emit();
        }
        CpgTaintReadiness::Disabled => {}
        _ => {
            let _ = trace
                .step(
                    "refused",
                    "run",
                    "taint tooling · unavailable (no cpg graph) · run cpg:build for path evidence",
                )
                .with_severity("warn")
                .emit();
        }
    }
}

fn report_query(trace: Option<&TraceHandle>, args: &TaintPathsArgs, envelope: &FlowEnvelope) {
    let Some(trace) = trace else { return };
    let _ = trace
        .step("tool-progress", "run", query_label(args, envelope))
        .emit();
}

fn query_label(args: &TaintPathsArgs, envelope: &FlowEnvelope) -> String {
    if envelope.flows.is_empty() {
        return format!(
            "queried taint: {} → {} · 0 paths (sources {} / sinks {})",
            args.source, args.sink, envelope.source_calls, envelope.sink_calls
        );
    }
    format!(
        "queried taint: {} → {} · {} paths{}",
        args.source,
        args.sink,
        envelope.flows.len(),
        envelope_guard_note(envelope)
    )
}

fn envelope_guard_note(envelope: &FlowEnvelope) -> String {
    for flow in &envelope.flows {
        if flow.get("guard").is_some_and(|guard| !guard.is_null()) {
            let file = flow.get("sinkFile").and_then(Value::as_str).unwrap_or("?");
            let line = flow.get("sinkLine").and_then(Value::as_u64).unwrap_or(0);
            return format!(" · guard@{file}:{line}");
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_guarded_ts_fixture(root: &Path) {
        std::fs::write(
            root.join("users.ts"),
            "function list(req, res) {\n  const id = req.query.id;\n  if (!authorized(req)) return;\n  db.query(\"SELECT \" + id);\n}\n",
        )
        .unwrap();
    }

    fn call(input: Value) -> ToolCall {
        ToolCall {
            name: "cpg_taint_paths".to_string(),
            input,
            call_id: "call-1".to_string(),
        }
    }

    #[test]
    fn off_policy_never_touches_the_graph() {
        let temp = tempfile::tempdir().unwrap();
        write_guarded_ts_fixture(temp.path());
        // Even with source on disk, `off` never reads or builds.
        let readiness = open_cpg_taint_engine(temp.path(), TaintToolPolicy::Off, None);
        assert_eq!(readiness, CpgTaintReadiness::Disabled);
        assert!(!has_artifacts(temp.path()));
    }

    #[test]
    fn available_policy_without_artifacts_is_missing_not_a_build() {
        let temp = tempfile::tempdir().unwrap();
        write_guarded_ts_fixture(temp.path());
        let readiness = open_cpg_taint_engine(temp.path(), TaintToolPolicy::Available, None);
        assert!(matches!(readiness, CpgTaintReadiness::Missing { .. }));
        // Proves no implicit build happened.
        assert!(!has_artifacts(temp.path()));
    }

    #[test]
    fn missing_graph_tool_call_is_a_non_fatal_structured_error() {
        let temp = tempfile::tempdir().unwrap();
        // Cache is cold for this root: a call must return a structured error,
        // never an Err that would abort the tool loop.
        let result = handle_cpg_taint_paths(
            temp.path(),
            None,
            &call(json!({"source": "a", "sink": "b"})),
        )
        .unwrap();
        assert!(result.is_error);
        assert_eq!(result.output["error"], "no cpg graph; run cpg:build");
    }

    #[test]
    fn empty_or_missing_patterns_are_structured_errors() {
        let temp = tempfile::tempdir().unwrap();
        let result = handle_cpg_taint_paths(
            temp.path(),
            None,
            &call(json!({"source": "  ", "sink": "b"})),
        )
        .unwrap();
        assert!(result.is_error);
    }

    #[test]
    fn build_policy_builds_once_per_root_thread() {
        let temp = tempfile::tempdir().unwrap();
        write_guarded_ts_fixture(temp.path());
        let first = open_cpg_taint_engine(temp.path(), TaintToolPolicy::Build, None);
        assert!(
            matches!(first, CpgTaintReadiness::Ready { .. }),
            "{first:?}"
        );
        let artifact = kuzushi_cpg::artifact_path(temp.path(), "typescript");
        let mtime = std::fs::metadata(&artifact)
            .and_then(|m| m.modified())
            .unwrap();
        assert_eq!(
            detection_count(),
            1,
            "first Build must detect languages once"
        );
        // Second call HITS the thread-local cache: it neither rebuilds the
        // artifact (mtime unchanged) nor re-walks the source tree to re-detect
        // buildable languages (detection count stays 1).
        let second = open_cpg_taint_engine(temp.path(), TaintToolPolicy::Build, None);
        assert!(matches!(second, CpgTaintReadiness::Ready { .. }));
        let mtime2 = std::fs::metadata(&artifact)
            .and_then(|m| m.modified())
            .unwrap();
        assert_eq!(mtime, mtime2, "second Build rebuilt the artifact");
        assert_eq!(
            detection_count(),
            1,
            "second Build re-ran the whole-source-tree language detection walk"
        );
    }

    #[test]
    fn build_policy_zero_languages_detects_once_and_caches_missing() {
        let temp = tempfile::tempdir().unwrap();
        // No buildable source: `detect_buildable_languages` returns empty, so
        // readiness resolves to Missing.
        std::fs::write(temp.path().join("notes.txt"), "prose, not code\n").unwrap();

        let first = open_cpg_taint_engine(temp.path(), TaintToolPolicy::Build, None);
        assert!(
            matches!(first, CpgTaintReadiness::Missing { .. }),
            "{first:?}"
        );
        assert_eq!(detection_count(), 1, "first Build detects languages once");

        // Second call must HIT the cached Missing: no second whole-source-tree
        // detection walk despite the zero-language branch storing no projects.
        let second = open_cpg_taint_engine(temp.path(), TaintToolPolicy::Build, None);
        assert!(
            matches!(second, CpgTaintReadiness::Missing { .. }),
            "{second:?}"
        );
        assert_eq!(
            detection_count(),
            1,
            "a cached Missing must not re-run the language detection walk"
        );
    }

    #[test]
    fn available_serves_a_stale_graph_without_rebuilding_or_walking() {
        let temp = tempfile::tempdir().unwrap();
        write_guarded_ts_fixture(temp.path());
        // Build the graph once so an on-disk artifact exists.
        assert!(matches!(
            open_cpg_taint_engine(temp.path(), TaintToolPolicy::Build, None),
            CpgTaintReadiness::Ready { .. }
        ));
        let artifact = kuzushi_cpg::artifact_path(temp.path(), "typescript");
        let mtime = std::fs::metadata(&artifact)
            .and_then(|m| m.modified())
            .unwrap();
        let detections_after_build = detection_count();

        // Make the graph STALE: push a source mtime past the artifact's.
        let future = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        let file = std::fs::File::options()
            .append(true)
            .open(temp.path().join("users.ts"))
            .unwrap();
        file.set_modified(future).unwrap();
        drop(file);

        // Force Available to resolve from disk again, not the warm cache, by
        // clearing the thread-local as a fresh worker would start.
        PROJECTS.with(|cell| *cell.borrow_mut() = None);
        READINESS_REPORTED.with(|cell| *cell.borrow_mut() = None);

        // Available must serve the stale graph as-is — never a from-source
        // rebuild, and never the Build-only language detection walk.
        let ready = open_cpg_taint_engine(temp.path(), TaintToolPolicy::Available, None);
        assert!(
            matches!(ready, CpgTaintReadiness::Ready { .. }),
            "{ready:?}"
        );
        let mtime2 = std::fs::metadata(&artifact)
            .and_then(|m| m.modified())
            .unwrap();
        assert_eq!(mtime, mtime2, "Available rebuilt a stale graph from source");
        assert_eq!(
            detection_count(),
            detections_after_build,
            "Available ran the Build-only language detection walk"
        );
    }

    #[test]
    fn available_without_a_graph_does_not_detect_languages() {
        let temp = tempfile::tempdir().unwrap();
        write_guarded_ts_fixture(temp.path());
        let readiness = open_cpg_taint_engine(temp.path(), TaintToolPolicy::Available, None);
        assert!(
            matches!(readiness, CpgTaintReadiness::Missing { .. }),
            "{readiness:?}"
        );
        assert_eq!(
            detection_count(),
            0,
            "Available must never run the Build-only detection walk"
        );
    }

    #[test]
    fn taint_flow_serializes_guard_and_authz() {
        let temp = tempfile::tempdir().unwrap();
        write_guarded_ts_fixture(temp.path());
        let readiness = open_cpg_taint_engine(temp.path(), TaintToolPolicy::Build, None);
        assert!(
            matches!(readiness, CpgTaintReadiness::Ready { .. }),
            "{readiness:?}"
        );
        let result = handle_cpg_taint_paths(
            temp.path(),
            None,
            &call(json!({"source": "req\\.query", "sink": "query"})),
        )
        .unwrap();
        assert!(!result.is_error, "{:?}", result.output);
        assert!(
            result.output["flowCount"].as_u64().unwrap() > 0,
            "{}",
            result.output
        );
        // A single witnessed flow is not truncated.
        assert_eq!(result.output["truncated"], serde_json::json!(false));
        let flow = &result.output["flows"][0];
        assert_eq!(flow["language"], "typescript");
        assert!(flow["steps"].as_array().unwrap().len() >= 2);
        // The fixture guards the sink with `if (!authorized(req)) return;` on
        // line 3, so the harvester must annotate a NON-null guard or authz that
        // names the gate (the engine emits e.g. "authz-partial@3") — not merely
        // carry present-but-null keys.
        let guard = flow.get("guard").cloned().unwrap_or(Value::Null);
        let authz = flow.get("authz").cloned().unwrap_or(Value::Null);
        assert!(
            !guard.is_null() || !authz.is_null(),
            "expected a non-null guard/authz falsification annotation, got {flow}"
        );
        let annotation = format!("{guard} {authz}").to_ascii_lowercase();
        assert!(
            annotation.contains("authz") && annotation.contains("@3"),
            "guard/authz annotation should name the authorized() gate at line 3: {annotation}"
        );
    }
}
