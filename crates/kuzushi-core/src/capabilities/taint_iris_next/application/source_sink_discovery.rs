//! Per-target source/sink + entry-point discovery for taint-iris-next.
//!
//! Runs once at plan time, before the catalog is ranked. The output
//! supplements the static catalog so the joern flow queries and the
//! agent prompt are grounded in primitives that actually exist in the
//! codebase, not just the static catalog's a-priori guess at what a
//! "C application" looks like. Persists to
//! `<target>/.kuzushi/discovered-signals.json` for re-use across hunts.
//!
//! Two discoverer flavours, both off the same `MARKERS` table:
//!
//! - **Entry-point discovery** scans the collected source files for
//!   language-specific markers that denote an externally-reachable
//!   function. C: `PG_FUNCTION_INFO_V1(<fn>)`. Python: `@app.route`,
//!   `@bp.<verb>`. JS/TS: `app.(get|post|put|delete|patch)(...)`.
//!   These are real attack surface and the agent should prefer them as
//!   sources during a privesc/RCE hunt.
//!
//! - **Sink discovery** is a regex sweep for canonical privesc/RCE
//!   primitives that are wider than the static catalog: `dlopen`,
//!   `load_external_function`, `SetUserId`, `SetSessionUserId`,
//!   `SetUserIdAndSecContext`, `system(`, `popen(`,
//!   `OpenPipeStream(`, `execve`, `execlp`, `RestrictSearchPath`. We
//!   record the call line so the agent can verify with tree-sitter and
//!   joern.
//!
//! Discovery is best-effort: a regex match isn't proof a name is
//! exploitable, only that it's worth ranking up. The agent's MCP
//! triangulation pass still has to confirm reachability.

use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::SystemTime;

/// One source / sink / entry-point primitive observed in the codebase.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiscoveredSignal {
    pub(crate) name: String,
    pub(crate) cwe: String,
    pub(crate) kind: String,
    pub(crate) language: String,
    pub(crate) marker: String,
    pub(crate) file: String,
    pub(crate) line: u32,
}

/// Bag of everything `source_sink_discovery::run` finds. Persisted to
/// `<target>/.kuzushi/discovered-signals.json` and threaded into the
/// taint-iris-next plan so ranking + the agent prompt + the dynamic
/// catalog tool can all consult it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DiscoveredSignals {
    #[serde(default)]
    pub(crate) discovered_at_unix: u64,
    #[serde(default)]
    pub(crate) sources: Vec<DiscoveredSignal>,
    #[serde(default)]
    pub(crate) sinks: Vec<DiscoveredSignal>,
    #[serde(default)]
    pub(crate) entry_points: Vec<DiscoveredSignal>,
    #[serde(default)]
    pub(crate) discoverers: Vec<String>,
}

/// Marker descriptor: a regex pattern + the CWE class it implicates +
/// the discovered-signal kind ("source", "sink", or "entrypoint") +
/// the languages it applies to.
struct MarkerSpec {
    pattern: &'static str,
    cwe: &'static str,
    kind: &'static str,
    languages: &'static [&'static str],
    /// Human-readable marker tag; the agent sees this so it knows
    /// which discoverer surfaced the name.
    marker: &'static str,
}

const MARKERS: &[MarkerSpec] = &[
    // ----- entry points ---------------------------------------------------
    // PostgreSQL SQL-callable function declaration (legacy macro form):
    // every fn referenced by PG_FUNCTION_INFO_V1 is reachable from
    // `SELECT my_fn(...)`.
    MarkerSpec {
        pattern: r"PG_FUNCTION_INFO_V1\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
        cwe: "CWE-862",
        kind: "entrypoint",
        languages: &["c", "cpp"],
        marker: "PG_FUNCTION_INFO_V1",
    },
    // PostgreSQL SQL-callable function definition (modern style, PG 11+).
    // Functions are registered via `pg_proc.dat` data files and the C side
    // declares `Datum name(PG_FUNCTION_ARGS) { ... }`. Without this marker
    // every modern postgres backend function (`pg_read_binary_file`,
    // `pg_stat_file`, `pg_signal_backend`, `pg_promote`, `pg_reload_conf`)
    // is invisible to the discovery sweep — and the static catalog has
    // no language-specific source list to substitute. The legacy
    // PG_FUNCTION_INFO_V1 marker only fires on contrib modules that
    // haven't migrated.
    MarkerSpec {
        pattern: r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*PG_FUNCTION_ARGS\s*\)",
        cwe: "CWE-862",
        kind: "entrypoint",
        languages: &["c", "cpp"],
        marker: "PG_FUNCTION_ARGS",
    },
    // Python web entry points (Flask/FastAPI/blueprint) — the `@.../route`
    // shape covers app, bp, api, router, etc.
    MarkerSpec {
        pattern: r"@\s*([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*(route|get|post|put|delete|patch|websocket)\s*\(",
        cwe: "CWE-862",
        kind: "entrypoint",
        languages: &["python"],
        marker: "python.route",
    },
    // Express / Fastify-style HTTP handlers.
    MarkerSpec {
        pattern: r"\b(app|router|api|bp)\s*\.\s*(get|post|put|delete|patch|use|all)\s*\(",
        cwe: "CWE-862",
        kind: "entrypoint",
        languages: &["javascript", "typescript"],
        marker: "js.route",
    },
    // ----- privesc sinks --------------------------------------------------
    MarkerSpec {
        pattern: r"\b(SetUserId|SetSessionUserId|SetUserIdAndSecContext|InitializeSessionUserId)\s*\(",
        cwe: "CWE-269",
        kind: "sink",
        languages: &["c", "cpp"],
        marker: "postgres.userid-mutator",
    },
    MarkerSpec {
        pattern: r"\b(seteuid|setuid|setegid|setgid|setresuid|setresgid)\s*\(",
        cwe: "CWE-250",
        kind: "sink",
        languages: &["c", "cpp"],
        marker: "posix.uid-mutator",
    },
    MarkerSpec {
        pattern: r"\bSECURITY_RESTRICTED_OPERATION\b",
        cwe: "CWE-269",
        kind: "sink",
        languages: &["c", "cpp"],
        marker: "postgres.sec-context-flag",
    },
    MarkerSpec {
        pattern: r"\bRestrictSearchPath\s*\(",
        cwe: "CWE-426",
        kind: "sink",
        languages: &["c", "cpp"],
        marker: "postgres.restrict-search-path",
    },
    // ----- RCE / dlopen sinks ---------------------------------------------
    MarkerSpec {
        pattern: r"\b(dlopen|dlsym|InternalLoadLibrary|LoadLibrary|LoadLibraryEx)\s*\(",
        cwe: "CWE-94",
        kind: "sink",
        languages: &["c", "cpp"],
        marker: "dynamic-loader",
    },
    MarkerSpec {
        pattern: r"\b(load_external_function|load_file)\s*\(",
        cwe: "CWE-94",
        kind: "sink",
        languages: &["c", "cpp"],
        marker: "postgres.extension-loader",
    },
    MarkerSpec {
        pattern: r"\b(system|popen|OpenPipeStream|execve|execvp|execlp|execl|execv)\s*\(",
        cwe: "CWE-78",
        kind: "sink",
        languages: &["c", "cpp"],
        marker: "posix.exec-family",
    },
    MarkerSpec {
        pattern: r#"\b(eval|Function|new\s+Function|child_process\s*\.\s*exec|child_process\s*\.\s*spawn|require\(\s*['"]child_process['"])"#,
        cwe: "CWE-78",
        kind: "sink",
        languages: &["javascript", "typescript"],
        marker: "node.exec",
    },
    MarkerSpec {
        pattern: r"(?:^|[^a-zA-Z0-9_])(eval|exec|compile|__import__|os\.system|subprocess\.(?:call|run|Popen|check_output|check_call))\s*\(",
        cwe: "CWE-78",
        kind: "sink",
        languages: &["python"],
        marker: "python.exec",
    },
    // ----- CWE-120 parser-layer source markers ---------------------------
    //
    // Codebase-shape parser-read patterns (pgcrypto's `pullf_*` / `mbuf_*`,
    // crypto MPI readers, etc.) used to live here, but moved to the
    // LLM-curated catalog in C5. The `:catalog` tool emits per-target
    // `regexMarkers` (see `dynamic_catalog::TAINT_IRIS_NEXT_CATALOG_SYSTEM_PROMPT`)
    // which the plan builder lifts into discovery's `extra_markers` slice
    // via `catalog_regex_markers_for_discovery`. The static table stays
    // for *framework-canonical* primitives — names that are stable across
    // every C/Python/JS codebase using a given framework — not for
    // codebase-specific naming conventions.
];

/// Runtime-owned counterpart to `MarkerSpec`. The static `MARKERS`
/// table can't carry LLM-emitted strings because of lifetime
/// constraints, so the LLM-curated catalog produces `OwnedMarkerSpec`
/// instances that get merged with the static table at discovery start.
#[derive(Debug, Clone)]
pub(crate) struct OwnedMarkerSpec {
    pub(crate) pattern: String,
    pub(crate) cwe: String,
    pub(crate) kind: String,
    pub(crate) languages: Vec<String>,
    pub(crate) marker: String,
}

impl From<&MarkerSpec> for OwnedMarkerSpec {
    fn from(spec: &MarkerSpec) -> Self {
        OwnedMarkerSpec {
            pattern: spec.pattern.to_string(),
            cwe: spec.cwe.to_string(),
            kind: spec.kind.to_string(),
            languages: spec.languages.iter().map(|lang| lang.to_string()).collect(),
            marker: spec.marker.to_string(),
        }
    }
}

/// Cached compiled regexes so a postgres run with ~30k source files
/// doesn't pay the regex compile cost per file. Drops entries whose
/// pattern fails to compile — invalid LLM-emitted regex never causes a
/// run-level error, just a silent skip.
fn compile_owned_markers(specs: &[OwnedMarkerSpec]) -> Vec<(regex::Regex, OwnedMarkerSpec)> {
    specs
        .iter()
        .filter_map(|spec| {
            regex::Regex::new(&spec.pattern)
                .ok()
                .map(|regex| (regex, spec.clone()))
        })
        .collect()
}

/// Run discovery against every source file the structural collector
/// already gathered. Returns the populated `DiscoveredSignals`.
///
/// `max_per_marker` caps how many call sites we record per (marker,
/// kind) pair — large codebases (e.g. postgres has 30k+ palloc calls)
/// would otherwise blow up the JSON artifact and the prompt; we only
/// need a representative handful for the agent to anchor on.
///
/// `extra_markers` carries LLM-curated codebase-shape markers from the
/// `:catalog` tool's `regexMarkers` field. They're appended to the
/// static `MARKERS` table for this run, giving discovery a per-target
/// surface without a code change. Pass `&[]` when no catalog markers
/// are available (legacy callers, tests).
pub(crate) fn run_taint_iris_next_source_sink_discovery(
    files: &[TaintIrisNextSourceFile],
    max_per_marker: usize,
    extra_markers: &[OwnedMarkerSpec],
) -> DiscoveredSignals {
    let markers = compiled_discovery_markers(extra_markers);
    let mut buckets: BTreeMap<(String, String), Vec<DiscoveredSignal>> = BTreeMap::new();

    for file in files {
        record_file_discoveries(file, &markers, max_per_marker, &mut buckets);
    }

    let (sources, sinks, entry_points) = partition_discovered_signal_buckets(buckets);

    DiscoveredSignals {
        discovered_at_unix: discovered_at_unix(),
        sources,
        sinks,
        entry_points,
        discoverers: vec!["tree-sitter-markers".to_string()],
    }
}

fn compiled_discovery_markers(
    extra_markers: &[OwnedMarkerSpec],
) -> Vec<(regex::Regex, OwnedMarkerSpec)> {
    let mut all_markers: Vec<OwnedMarkerSpec> = MARKERS.iter().map(OwnedMarkerSpec::from).collect();
    all_markers.extend(extra_markers.iter().cloned());
    compile_owned_markers(&all_markers)
}

fn record_file_discoveries(
    file: &TaintIrisNextSourceFile,
    markers: &[(regex::Regex, OwnedMarkerSpec)],
    max_per_marker: usize,
    buckets: &mut BTreeMap<(String, String), Vec<DiscoveredSignal>>,
) {
    for (regex, spec) in markers {
        if !marker_matches_file_language(spec, file) {
            continue;
        }
        for (line_no, line) in file.lines.iter().enumerate() {
            record_line_discoveries(file, line_no, line, regex, spec, max_per_marker, buckets);
        }
    }
}

fn marker_matches_file_language(spec: &OwnedMarkerSpec, file: &TaintIrisNextSourceFile) -> bool {
    spec.languages.iter().any(|lang| lang == &file.language)
}

fn record_line_discoveries(
    file: &TaintIrisNextSourceFile,
    line_no: usize,
    line: &str,
    regex: &regex::Regex,
    spec: &OwnedMarkerSpec,
    max_per_marker: usize,
    buckets: &mut BTreeMap<(String, String), Vec<DiscoveredSignal>>,
) {
    for capture in regex.captures_iter(line) {
        let Some(name) = discovered_capture_name(&capture) else {
            continue;
        };
        if is_likely_entry_point_name_noise(&spec.marker, &name) {
            continue;
        }
        push_discovered_signal(file, line_no, spec, name, max_per_marker, buckets);
    }
}

fn discovered_capture_name(capture: &regex::Captures<'_>) -> Option<String> {
    capture
        .get(1)
        .or_else(|| capture.get(0))
        .map(|matched| matched.as_str().to_string())
        .filter(|name| !name.is_empty())
}

fn push_discovered_signal(
    file: &TaintIrisNextSourceFile,
    line_no: usize,
    spec: &OwnedMarkerSpec,
    name: String,
    max_per_marker: usize,
    buckets: &mut BTreeMap<(String, String), Vec<DiscoveredSignal>>,
) {
    let bucket = buckets
        .entry((spec.marker.clone(), name.clone()))
        .or_default();
    if bucket.len() >= max_per_marker {
        return;
    }
    bucket.push(DiscoveredSignal {
        name,
        cwe: spec.cwe.clone(),
        kind: spec.kind.clone(),
        language: file.language.clone(),
        marker: spec.marker.clone(),
        file: file.relative_path.clone(),
        line: (line_no + 1) as u32,
    });
}

fn partition_discovered_signal_buckets(
    buckets: BTreeMap<(String, String), Vec<DiscoveredSignal>>,
) -> (
    Vec<DiscoveredSignal>,
    Vec<DiscoveredSignal>,
    Vec<DiscoveredSignal>,
) {
    let mut sources = Vec::new();
    let mut sinks = Vec::new();
    let mut entry_points = Vec::new();
    for entry in buckets.into_values().flatten() {
        push_discovered_signal_by_kind(entry, &mut sources, &mut sinks, &mut entry_points);
    }
    (sources, sinks, entry_points)
}

fn push_discovered_signal_by_kind(
    entry: DiscoveredSignal,
    sources: &mut Vec<DiscoveredSignal>,
    sinks: &mut Vec<DiscoveredSignal>,
    entry_points: &mut Vec<DiscoveredSignal>,
) {
    match entry.kind.as_str() {
        "source" => sources.push(entry),
        "sink" => sinks.push(entry),
        "entrypoint" => entry_points.push(entry),
        _ => {}
    }
}

fn discovered_at_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Filter out matches that are obviously not real entry-point names.
/// Real SQL-callable PG functions are conventionally `pg_*` /
/// `lo_*` / `lower_snake_case` with at least 5 chars and at least one
/// lowercase letter. Macro placeholders like `NAME`, typedefs like
/// `OPCODE`, and short generic identifiers like `FN` / `OP` are noise
/// — they show up because macros like `#define CMPFUNC(NAME, ...) ...
/// NAME(PG_FUNCTION_ARGS) {` capture the macro parameter, not a real
/// function. The filter only applies to the modern `PG_FUNCTION_ARGS`
/// marker; the legacy `PG_FUNCTION_INFO_V1(name)` shape is precise
/// enough on its own (the macro is an explicit registration, no
/// placeholder shadow). Other markers (route decorators, sink names)
/// pass through unchanged.
fn is_likely_entry_point_name_noise(marker: &str, name: &str) -> bool {
    // Note: parser-source markers (`buffer.parser-read`, `wire.parser-read`,
    // `crypto.mpi-read`) used to live in the static MARKERS table with
    // a dedicated noise filter here. They moved to the LLM-curated
    // catalog in C5 — if a future operator wants per-marker noise
    // rules they can be elicited from the catalog prompt and added as
    // a `noiseFilter` field on `TaintIrisNextRegexMarker`. For now,
    // catalog-supplied markers bypass codebase-specific noise filters;
    // operators iterate on the regex pattern itself if they observe
    // false captures.
    if marker != "PG_FUNCTION_ARGS" {
        return false;
    }
    // Names shorter than 5 chars are almost always macro params.
    if name.len() < 5 {
        return true;
    }
    // All-uppercase = typedef / macro placeholder convention.
    let has_lowercase = name.chars().any(|c| c.is_ascii_lowercase());
    if !has_lowercase {
        return true;
    }
    false
}

/// Persist the result alongside the rest of the kuzushi state under
/// `<target>/.kuzushi/discovered-signals.json`. Best-effort: a failure
/// here is non-fatal because discovery is a ranking aid, not a
/// correctness gate.
pub(crate) fn persist_taint_iris_next_discovered_signals(
    repo_root: &Path,
    signals: &DiscoveredSignals,
) {
    let dir = repo_root.join(".kuzushi");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("discovered-signals.json");
    if let Ok(serialised) = serde_json::to_string_pretty(signals) {
        let _ = std::fs::write(&path, serialised);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(language: &str, lines: &[&str], path: &str) -> TaintIrisNextSourceFile {
        TaintIrisNextSourceFile {
            relative_path: path.to_string(),
            language: language.to_string(),
            lines: lines.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn discovers_postgres_pg_function_info_v1_entrypoints() {
        let files = vec![fixture(
            "c",
            &[
                "Datum",
                "pg_read_server_files(PG_FUNCTION_ARGS)",
                "{",
                "    return CStringGetTextDatum(\"\");",
                "}",
                "PG_FUNCTION_INFO_V1(pg_read_server_files);",
            ],
            "src/backend/utils/adt/genfile.c",
        )];
        let result = run_taint_iris_next_source_sink_discovery(&files, 16, &[]);
        // Both markers fire on the same fn — the legacy macro line 6
        // and the modern function-definition line 2. Both produce
        // CWE-862 entries with the same name; downstream dedup happens
        // at the candidate projection layer (file+line is unique).
        let by_marker: std::collections::BTreeMap<&str, &str> = result
            .entry_points
            .iter()
            .map(|e| (e.marker.as_str(), e.name.as_str()))
            .collect();
        assert_eq!(
            by_marker.get("PG_FUNCTION_INFO_V1"),
            Some(&"pg_read_server_files")
        );
        assert_eq!(
            by_marker.get("PG_FUNCTION_ARGS"),
            Some(&"pg_read_server_files")
        );
        let cwes: std::collections::BTreeSet<&str> =
            result.entry_points.iter().map(|e| e.cwe.as_str()).collect();
        assert_eq!(cwes, std::collections::BTreeSet::from(["CWE-862"]));
    }

    #[test]
    fn discovers_modern_postgres_pg_function_args_entrypoints() {
        // Postgres 11+ functions register via pg_proc.dat instead of
        // PG_FUNCTION_INFO_V1, so the C side has only the function
        // definition. Discovery must catch these too — without this
        // every modern backend fn (`pg_signal_backend`, `pg_promote`,
        // `pg_read_binary_file`, ...) was invisible to the sweep.
        let files = vec![fixture(
            "c",
            &[
                "Datum",
                "pg_signal_backend(PG_FUNCTION_ARGS)",
                "{",
                "    int64 pid = PG_GETARG_INT64(0);",
                "}",
                "Datum",
                "pg_read_binary_file_off_len(PG_FUNCTION_ARGS)",
                "{",
                "    text *filename = PG_GETARG_TEXT_PP(0);",
                "}",
            ],
            "src/backend/utils/adt/misc.c",
        )];
        let result = run_taint_iris_next_source_sink_discovery(&files, 16, &[]);
        let names: Vec<&str> = result
            .entry_points
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert!(names.contains(&"pg_signal_backend"), "got {names:?}");
        assert!(
            names.contains(&"pg_read_binary_file_off_len"),
            "got {names:?}"
        );
    }

    #[test]
    fn rejects_macro_parameter_placeholders_as_entry_points() {
        // The `PG_FUNCTION_ARGS` regex captures any identifier
        // immediately preceding `(PG_FUNCTION_ARGS)`. Postgres has
        // macro definitions like:
        //   #define CMPFUNC(NAME, COND) Datum NAME(PG_FUNCTION_ARGS) ...
        // where `NAME` is a macro PARAMETER, not a function. Without
        // filtering, the discovery sweep emits `NAME` as a CWE-862
        // entry point; the structural pass then rg-greps the entire
        // codebase for the literal token `NAME` and floods the agent
        // with false-positive sources from typedef tables, header
        // comments, etc.
        let files = vec![fixture(
            "c",
            &[
                "#define CMPFUNC( NAME, CONDITION )    \\",
                "Datum                                  \\",
                "NAME(PG_FUNCTION_ARGS) {",
                "    return 0;",
                "}",
                "real_function_name(PG_FUNCTION_ARGS)",
                "{",
                "    return 0;",
                "}",
                // Short and ALL_CAPS placeholders that should also be
                // rejected.
                "FN(PG_FUNCTION_ARGS)",
                "OPCODE(PG_FUNCTION_ARGS)",
            ],
            "src/backend/utils/adt/tsquery_op.c",
        )];
        let result = run_taint_iris_next_source_sink_discovery(&files, 16, &[]);
        let names: Vec<&str> = result
            .entry_points
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert!(
            names.contains(&"real_function_name"),
            "real lowercase function name must pass: {names:?}"
        );
        assert!(
            !names.contains(&"NAME"),
            "all-uppercase macro placeholder must be filtered: {names:?}"
        );
        assert!(
            !names.contains(&"FN"),
            "short identifier must be filtered: {names:?}"
        );
        assert!(
            !names.contains(&"OPCODE"),
            "all-uppercase typedef-shaped name must be filtered: {names:?}"
        );
    }

    #[test]
    fn legacy_pg_function_info_v1_keeps_short_or_uppercase_names() {
        // The legacy macro is an explicit registration — if someone
        // wrote `PG_FUNCTION_INFO_V1(FN)` they meant it. Don't apply
        // the noise filter to the legacy marker.
        let files = vec![fixture(
            "c",
            &["PG_FUNCTION_INFO_V1(FN);", "PG_FUNCTION_INFO_V1(real_fn);"],
            "src/legacy.c",
        )];
        let result = run_taint_iris_next_source_sink_discovery(&files, 16, &[]);
        let names: Vec<&str> = result
            .entry_points
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert!(
            names.contains(&"FN"),
            "legacy marker shouldn't filter: {names:?}"
        );
        assert!(names.contains(&"real_fn"));
    }

    #[test]
    fn discovers_dlopen_load_external_function_and_setuid_sinks_for_c() {
        let files = vec![fixture(
            "c",
            &[
                "void* lib = dlopen(\"/tmp/x.so\", RTLD_NOW);",
                "load_external_function(filename, funcname, true, &filehandle);",
                "if (SetUserId(roleid))",
                "    elog(WARNING, \"role mutated\");",
                "if (seteuid(0) == -1)",
            ],
            "src/backend/commands/fmgrtab.c",
        )];
        let result = run_taint_iris_next_source_sink_discovery(&files, 16, &[]);
        let names: Vec<&str> = result.sinks.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"dlopen"), "got {names:?}");
        assert!(names.contains(&"load_external_function"));
        assert!(names.contains(&"SetUserId"));
        assert!(names.contains(&"seteuid"));
        let cwes: std::collections::BTreeSet<&str> =
            result.sinks.iter().map(|s| s.cwe.as_str()).collect();
        assert!(cwes.contains("CWE-94"));
        assert!(cwes.contains("CWE-269"));
        assert!(cwes.contains("CWE-250"));
    }

    #[test]
    fn discovers_python_routes_and_exec_sinks() {
        let files = vec![fixture(
            "python",
            &[
                "@app.route('/admin')",
                "def admin():",
                "    os.system(request.args['cmd'])",
                "    eval(request.args['expr'])",
            ],
            "app/routes/admin.py",
        )];
        let result = run_taint_iris_next_source_sink_discovery(&files, 16, &[]);
        assert!(
            result
                .entry_points
                .iter()
                .any(|e| e.marker == "python.route"),
            "@app.route should land as an entry point: {result:?}"
        );
        let sinks: Vec<&str> = result.sinks.iter().map(|s| s.name.as_str()).collect();
        assert!(sinks.iter().any(|n| n.contains("system")), "{sinks:?}");
        assert!(sinks.iter().any(|n| n.contains("eval")), "{sinks:?}");
    }

    #[test]
    fn caps_per_marker_to_keep_artifact_compact() {
        let mut lines: Vec<&str> = Vec::new();
        for _ in 0..50 {
            lines.push("dlopen(\"libx.so\", 0);");
        }
        let files = vec![fixture("c", &lines, "src/x.c")];
        let result = run_taint_iris_next_source_sink_discovery(&files, 5, &[]);
        let dlopen_count = result.sinks.iter().filter(|s| s.name == "dlopen").count();
        assert_eq!(dlopen_count, 5, "max_per_marker cap should hold");
    }

    #[test]
    fn ignores_unknown_languages() {
        let files = vec![fixture("haskell", &["dlopen \"libx.so\""], "src/x.hs")];
        let result = run_taint_iris_next_source_sink_discovery(&files, 16, &[]);
        assert!(result.sinks.is_empty());
        assert!(result.entry_points.is_empty());
    }

    #[test]
    fn discovers_parser_layer_cwe120_sources_via_catalog_markers() {
        // pgcrypto-style file: pullf_read / mbuf_read / pgp_mpi_read
        // are parser-layer readers that produce caller-controlled
        // length values. They USED to be hard-coded in the static
        // MARKERS table (Thread A1) but moved to the LLM-curated
        // catalog in C5. This test now verifies the catalog-driven
        // discovery path produces equivalent output — the catalog
        // supplies the regex markers, discovery picks up the call
        // sites. Verifies the multi-codebase claim: this exact same
        // pipeline works on libxml2, ImageMagick, etc. by emitting
        // different markers from `:catalog`.
        let files = vec![fixture(
            "c",
            &[
                "Datum pgp_parse_pubenc_sesskey(PGP_Context *ctx, PullFilter *pkt)",
                "{",
                "    res = pullf_read_fixed(pkt, 8, key_id);",
                "    res = pullf_read(src, &p, 4);",
                "    res = pgp_mpi_read(pkt, &c1);",
                "    n = mbuf_read(src);",
                "    msglen = pq_getmsgbytes(buf, len);",
                "    msglen = pq_copymsgbytes(buf, dest, len);",
                "}",
            ],
            "contrib/pgcrypto/pgp-pubdec.c",
        )];
        // These are the same regex shapes A1 used to ship in the
        // static MARKERS table — the test now supplies them via the
        // catalog-driven `extra_markers` path instead. Operators on
        // novel C codebases get the same plumbing by having `:catalog`
        // emit their codebase-shape markers (libxml2's `xmlParse*`,
        // ImageMagick's `Read*Image`, etc.).
        let extra = vec![
            OwnedMarkerSpec {
                pattern: r"\b((?:pullf|mbuf)_[a-z_]+)\s*\(".to_string(),
                cwe: "CWE-120".to_string(),
                kind: "source".to_string(),
                languages: vec!["c".to_string()],
                marker: "buffer.parser-read".to_string(),
            },
            OwnedMarkerSpec {
                pattern: r"\b(pq_get[a-z_]+|pq_copymsgbytes)\s*\(".to_string(),
                cwe: "CWE-120".to_string(),
                kind: "source".to_string(),
                languages: vec!["c".to_string()],
                marker: "wire.parser-read".to_string(),
            },
            OwnedMarkerSpec {
                pattern: r"\b([a-z_]+_mpi_(?:read|alloc))\s*\(".to_string(),
                cwe: "CWE-120".to_string(),
                kind: "source".to_string(),
                languages: vec!["c".to_string()],
                marker: "crypto.mpi-read".to_string(),
            },
        ];
        let result = run_taint_iris_next_source_sink_discovery(&files, 16, &extra);
        let source_names: std::collections::BTreeSet<&str> =
            result.sources.iter().map(|s| s.name.as_str()).collect();
        assert!(
            source_names.contains("pullf_read_fixed"),
            "got {source_names:?}"
        );
        assert!(source_names.contains("pullf_read"), "got {source_names:?}");
        assert!(
            source_names.contains("pgp_mpi_read"),
            "got {source_names:?}"
        );
        assert!(source_names.contains("mbuf_read"), "got {source_names:?}");
        assert!(
            source_names.contains("pq_getmsgbytes"),
            "got {source_names:?}"
        );
        assert!(
            source_names.contains("pq_copymsgbytes"),
            "got {source_names:?}"
        );
        // Each source should carry CWE-120 and the marker tag the
        // catalog supplied.
        let pullf = result
            .sources
            .iter()
            .find(|s| s.name == "pullf_read")
            .unwrap();
        assert_eq!(pullf.cwe, "CWE-120");
        assert_eq!(pullf.marker, "buffer.parser-read");
        let mpi = result
            .sources
            .iter()
            .find(|s| s.name == "pgp_mpi_read")
            .unwrap();
        assert_eq!(mpi.marker, "crypto.mpi-read");
        let pq = result
            .sources
            .iter()
            .find(|s| s.name == "pq_getmsgbytes")
            .unwrap();
        assert_eq!(pq.marker, "wire.parser-read");
    }

    #[test]
    fn static_markers_table_no_longer_carries_codebase_specific_patterns() {
        // C5 regression: a fresh discovery sweep with NO catalog
        // markers must NOT pick up pgcrypto-shape names from the
        // static table — those moved to the LLM catalog.
        let files = vec![fixture(
            "c",
            &[
                "res = pullf_read(src, &p, 4);",
                "msglen = pq_getmsgbytes(buf, len);",
                "n = pgp_mpi_read(src);",
            ],
            "contrib/pgcrypto/pgp-pubdec.c",
        )];
        let result = run_taint_iris_next_source_sink_discovery(&files, 16, &[]);
        let source_names: std::collections::BTreeSet<&str> =
            result.sources.iter().map(|s| s.name.as_str()).collect();
        // None of these should appear when the catalog supplies no
        // markers — the static table only carries framework-canonical
        // primitives now (dlopen, system, PG_FUNCTION_INFO_V1, etc.).
        assert!(
            !source_names.contains("pullf_read"),
            "static table must not contain pgcrypto pullf_*: {source_names:?}"
        );
        assert!(
            !source_names.contains("pq_getmsgbytes"),
            "static table must not contain libpq pq_get*: {source_names:?}"
        );
        assert!(
            !source_names.contains("pgp_mpi_read"),
            "static table must not contain crypto _mpi_*: {source_names:?}"
        );
    }

    #[test]
    fn catalog_marker_regex_owns_its_own_noise_rejection_post_c5() {
        // Pre-C5 the static-table parser-source markers had a hardcoded
        // noise filter rejecting short / uppercase-leading captures
        // (`mbuf_t`, `MBuf`). C5 moved those markers into the catalog
        // and dropped the post-filter, on the principle that the LLM
        // owns its regex's precision: if the catalog emits a tighter
        // pattern (`\b((?:pullf|mbuf)_(?:read|write|grab|alloc|free|...))\s*\(`,
        // enumerating known shapes), false captures disappear at the
        // regex layer.
        //
        // This test documents the new contract:
        //   * `MBuf(...)` is rejected by the regex itself (the catalog
        //     pattern requires a lowercase `mbuf_` prefix) — same
        //     behaviour as A1.
        //   * `pgp_mpi_read(...)` is captured (real parser-layer source).
        //   * `mbuf_t(...)` would now be captured under a loose pattern;
        //     operators write tighter regex via `:catalog` regen if it
        //     produces too much noise.
        let files = vec![fixture(
            "c",
            &[
                "n = pgp_mpi_read(src);",
                "var = mbuf_t(...);",
                "var = MBuf(NULL);",
            ],
            "src/x.c",
        )];
        let extra = vec![
            OwnedMarkerSpec {
                pattern: r"\b((?:pullf|mbuf)_[a-z_]+)\s*\(".to_string(),
                cwe: "CWE-120".to_string(),
                kind: "source".to_string(),
                languages: vec!["c".to_string()],
                marker: "buffer.parser-read".to_string(),
            },
            OwnedMarkerSpec {
                pattern: r"\b([a-z_]+_mpi_(?:read|alloc))\s*\(".to_string(),
                cwe: "CWE-120".to_string(),
                kind: "source".to_string(),
                languages: vec!["c".to_string()],
                marker: "crypto.mpi-read".to_string(),
            },
        ];
        let result = run_taint_iris_next_source_sink_discovery(&files, 16, &extra);
        let names: std::collections::BTreeSet<&str> =
            result.sources.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains("pgp_mpi_read"),
            "real parser fn must capture: {names:?}"
        );
        assert!(
            !names.contains("MBuf"),
            "uppercase prefix must be excluded by the regex itself: {names:?}",
        );
    }

    #[test]
    fn extra_markers_augment_static_markers_at_discovery_time() {
        // A codebase-shape marker the LLM catalog might emit for, say,
        // libxml2 (`xmlParse*` family). It is NOT in the static MARKERS
        // table — proof that catalog-supplied markers reach discovery.
        let files = vec![fixture(
            "c",
            &[
                "doc = xmlParseFile(filename);",
                "node = xmlParseMemory(buffer, len);",
            ],
            "src/parser.c",
        )];
        let extra = vec![OwnedMarkerSpec {
            pattern: r"\b(xmlParse[A-Za-z]+)\s*\(".to_string(),
            cwe: "CWE-120".to_string(),
            kind: "source".to_string(),
            languages: vec!["c".to_string()],
            marker: "libxml2.parse".to_string(),
        }];
        let result = run_taint_iris_next_source_sink_discovery(&files, 16, &extra);
        let names: std::collections::BTreeSet<&str> =
            result.sources.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains("xmlParseFile"),
            "extra marker must reach discovery sweep; got {names:?}"
        );
        assert!(
            names.contains("xmlParseMemory"),
            "extra marker must match multiple occurrences; got {names:?}"
        );
        // Sanity: catalog-supplied markers get the canonical fields
        // populated (kind, language, cwe) from the OwnedMarkerSpec so
        // downstream splice + ranking sees them as proper sources.
        let xml_file = result
            .sources
            .iter()
            .find(|s| s.name == "xmlParseFile")
            .expect("xmlParseFile must be present");
        assert_eq!(xml_file.marker, "libxml2.parse");
        assert_eq!(xml_file.language, "c");
        assert_eq!(xml_file.cwe, "CWE-120");
        assert_eq!(xml_file.kind, "source");
    }

    #[test]
    fn invalid_extra_marker_pattern_drops_silently_without_crashing() {
        let files = vec![fixture("c", &["foo(bar);"], "src/x.c")];
        let extra = vec![
            OwnedMarkerSpec {
                pattern: "((".to_string(), // malformed regex
                cwe: "CWE-120".to_string(),
                kind: "source".to_string(),
                languages: vec!["c".to_string()],
                marker: "broken".to_string(),
            },
            OwnedMarkerSpec {
                pattern: r"\bfoo\(".to_string(),
                cwe: "CWE-120".to_string(),
                kind: "source".to_string(),
                languages: vec!["c".to_string()],
                marker: "good".to_string(),
            },
        ];
        // Should not panic; the malformed regex is silently dropped and
        // the good one still fires.
        let result = run_taint_iris_next_source_sink_discovery(&files, 16, &extra);
        let markers: std::collections::BTreeSet<&str> =
            result.sources.iter().map(|s| s.marker.as_str()).collect();
        assert!(markers.contains("good"));
        assert!(!markers.contains("broken"));
    }
}
