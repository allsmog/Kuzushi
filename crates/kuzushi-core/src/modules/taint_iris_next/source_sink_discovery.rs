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
pub(in crate::modules) struct DiscoveredSignal {
    pub(in crate::modules) name: String,
    pub(in crate::modules) cwe: String,
    pub(in crate::modules) kind: String,
    pub(in crate::modules) language: String,
    pub(in crate::modules) marker: String,
    pub(in crate::modules) file: String,
    pub(in crate::modules) line: u32,
}

/// Bag of everything `source_sink_discovery::run` finds. Persisted to
/// `<target>/.kuzushi/discovered-signals.json` and threaded into the
/// taint-iris-next plan so ranking + the agent prompt + the dynamic
/// catalog tool can all consult it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::modules) struct DiscoveredSignals {
    #[serde(default)]
    pub(in crate::modules) discovered_at_unix: u64,
    #[serde(default)]
    pub(in crate::modules) sources: Vec<DiscoveredSignal>,
    #[serde(default)]
    pub(in crate::modules) sinks: Vec<DiscoveredSignal>,
    #[serde(default)]
    pub(in crate::modules) entry_points: Vec<DiscoveredSignal>,
    #[serde(default)]
    pub(in crate::modules) discoverers: Vec<String>,
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
];

/// Cached compiled regexes so a postgres run with ~30k source files
/// doesn't pay the regex compile cost per file.
fn compiled_markers() -> Vec<(regex::Regex, &'static MarkerSpec)> {
    MARKERS
        .iter()
        .filter_map(|spec| {
            regex::Regex::new(spec.pattern)
                .ok()
                .map(|regex| (regex, spec))
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
pub(in crate::modules) fn run_taint_iris_next_source_sink_discovery(
    files: &[TaintIrisNextSourceFile],
    max_per_marker: usize,
) -> DiscoveredSignals {
    let markers = compiled_markers();
    let mut buckets: BTreeMap<(String, String), Vec<DiscoveredSignal>> = BTreeMap::new();

    for file in files {
        for (regex, spec) in &markers {
            if !spec.languages.contains(&file.language.as_str()) {
                continue;
            }
            for (line_no, line) in file.lines.iter().enumerate() {
                for capture in regex.captures_iter(line) {
                    let name = match capture.get(1) {
                        Some(m) => m.as_str().to_string(),
                        None => capture
                            .get(0)
                            .map(|m| m.as_str().to_string())
                            .unwrap_or_default(),
                    };
                    if name.is_empty() {
                        continue;
                    }
                    // Filter out matches that are obviously macro
                    // parameters or typedefs masquerading as function
                    // names. The PG_FUNCTION_ARGS regex captures the
                    // text immediately before `(PG_FUNCTION_ARGS)` —
                    // which is usually a real SQL-callable C function,
                    // but `#define CMPFUNC(NAME, ...) Datum
                    // NAME(PG_FUNCTION_ARGS) {` makes the macro
                    // parameter `NAME` look like a function. Real PG
                    // functions are conventionally lowercase
                    // snake_case (`pg_signal_backend`, `lo_import`)
                    // or at minimum mixed case with a meaningful
                    // length; `NAME`, `FN`, `OP` are noise.
                    if is_likely_entry_point_name_noise(spec.marker, &name) {
                        continue;
                    }
                    let bucket_key = (spec.marker.to_string(), name.clone());
                    let bucket = buckets.entry(bucket_key).or_default();
                    if bucket.len() >= max_per_marker {
                        continue;
                    }
                    bucket.push(DiscoveredSignal {
                        name,
                        cwe: spec.cwe.to_string(),
                        kind: spec.kind.to_string(),
                        language: file.language.clone(),
                        marker: spec.marker.to_string(),
                        file: file.relative_path.clone(),
                        line: (line_no + 1) as u32,
                    });
                }
            }
        }
    }

    let mut sources = Vec::new();
    let mut sinks = Vec::new();
    let mut entry_points = Vec::new();
    for ((_, _), entries) in buckets.into_iter() {
        for entry in entries {
            match entry.kind.as_str() {
                "source" => sources.push(entry),
                "sink" => sinks.push(entry),
                "entrypoint" => entry_points.push(entry),
                _ => {}
            }
        }
    }

    DiscoveredSignals {
        discovered_at_unix: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        sources,
        sinks,
        entry_points,
        discoverers: vec!["tree-sitter-markers".to_string()],
    }
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
pub(in crate::modules) fn persist_taint_iris_next_discovered_signals(
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
        let result = run_taint_iris_next_source_sink_discovery(&files, 16);
        // Both markers fire on the same fn — the legacy macro line 6
        // and the modern function-definition line 2. Both produce
        // CWE-862 entries with the same name; downstream dedup happens
        // at the candidate projection layer (file+line is unique).
        let by_marker: std::collections::BTreeMap<&str, &str> = result
            .entry_points
            .iter()
            .map(|e| (e.marker.as_str(), e.name.as_str()))
            .collect();
        assert_eq!(by_marker.get("PG_FUNCTION_INFO_V1"), Some(&"pg_read_server_files"));
        assert_eq!(by_marker.get("PG_FUNCTION_ARGS"), Some(&"pg_read_server_files"));
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
        let result = run_taint_iris_next_source_sink_discovery(&files, 16);
        let names: Vec<&str> = result
            .entry_points
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert!(names.contains(&"pg_signal_backend"), "got {names:?}");
        assert!(names.contains(&"pg_read_binary_file_off_len"), "got {names:?}");
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
        let result = run_taint_iris_next_source_sink_discovery(&files, 16);
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
            &[
                "PG_FUNCTION_INFO_V1(FN);",
                "PG_FUNCTION_INFO_V1(real_fn);",
            ],
            "src/legacy.c",
        )];
        let result = run_taint_iris_next_source_sink_discovery(&files, 16);
        let names: Vec<&str> = result
            .entry_points
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert!(names.contains(&"FN"), "legacy marker shouldn't filter: {names:?}");
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
        let result = run_taint_iris_next_source_sink_discovery(&files, 16);
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
        let result = run_taint_iris_next_source_sink_discovery(&files, 16);
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
        let result = run_taint_iris_next_source_sink_discovery(&files, 5);
        let dlopen_count = result
            .sinks
            .iter()
            .filter(|s| s.name == "dlopen")
            .count();
        assert_eq!(dlopen_count, 5, "max_per_marker cap should hold");
    }

    #[test]
    fn ignores_unknown_languages() {
        let files = vec![fixture(
            "haskell",
            &["dlopen \"libx.so\""],
            "src/x.hs",
        )];
        let result = run_taint_iris_next_source_sink_discovery(&files, 16);
        assert!(result.sinks.is_empty());
        assert!(result.entry_points.is_empty());
    }
}
