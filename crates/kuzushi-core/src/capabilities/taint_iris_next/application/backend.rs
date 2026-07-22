use super::*;

pub(crate) fn choose_taint_iris_next_backend(
    requested: &str,
    repo_root: &Path,
    languages: &[String],
) -> TaintIrisNextBackendChoice {
    let codeql_db = super::codeql_db_path(repo_root);
    let availability = TaintIrisNextBackendAvailability {
        codeql_db_present: codeql_db.is_some(),
        codeql_runnable: codeql_db.is_some() && super::codeql_available(),
        // No artifact-existence precondition: graphs build implicitly in
        // seconds, so a supported language is the only requirement.
        cpgrs_runnable: !super::cpgrs_plan_languages(languages).is_empty(),
    };
    let mut warnings = Vec::new();
    let selected = select_taint_iris_next_backend(requested, &availability, &mut warnings);
    TaintIrisNextBackendChoice {
        requested: requested.to_string(),
        selected: selected.to_string(),
        codeql_db_path: codeql_db.as_ref().map(|path| path.display().to_string()),
        corroborate_with_codeql: codeql_db.as_ref().map(|_| true),
        structural_tool: detect_structural_tool().to_string(),
        warnings,
    }
}

struct TaintIrisNextBackendAvailability {
    codeql_db_present: bool,
    codeql_runnable: bool,
    cpgrs_runnable: bool,
}

fn select_taint_iris_next_backend(
    requested: &str,
    availability: &TaintIrisNextBackendAvailability,
    warnings: &mut Vec<String>,
) -> &'static str {
    let spec = backend_request_spec(requested);
    (spec.selector)(requested, availability, warnings)
}

#[derive(Clone, Copy)]
struct BackendRequestSpec {
    name: &'static str,
    selector: BackendSelector,
}

type BackendSelector =
    fn(&str, &TaintIrisNextBackendAvailability, &mut Vec<String>) -> &'static str;

fn backend_request_spec(requested: &str) -> BackendRequestSpec {
    const STRUCTURAL: BackendRequestSpec = BackendRequestSpec {
        name: "",
        selector: select_structural_backend,
    };
    const REQUESTS: &[BackendRequestSpec] = &[
        BackendRequestSpec {
            name: "cpg-rs",
            selector: select_cpgrs_backend,
        },
        BackendRequestSpec {
            name: "cpg",
            selector: select_cpgrs_backend,
        },
        BackendRequestSpec {
            name: "codeql",
            selector: select_codeql_backend,
        },
        BackendRequestSpec {
            name: "auto",
            selector: select_auto_backend,
        },
        BackendRequestSpec {
            name: "joern",
            selector: select_retired_joern_backend,
        },
        BackendRequestSpec {
            name: "semgrep",
            selector: select_deprecated_backend,
        },
        BackendRequestSpec {
            name: "language",
            selector: select_deprecated_backend,
        },
    ];
    REQUESTS
        .iter()
        .find(|spec| spec.name == requested)
        .copied()
        .unwrap_or(STRUCTURAL)
}

fn select_cpgrs_backend(
    _requested: &str,
    availability: &TaintIrisNextBackendAvailability,
    warnings: &mut Vec<String>,
) -> &'static str {
    if availability.cpgrs_runnable {
        return "cpg-rs";
    }
    warnings.push(
        "backend=cpg-rs requested, but no detected language has a cpg-rs frontend \
         (supported: c, cpp, go, java, javascript, python, ruby, rust, scala, typescript). \
         Using structural evidence."
            .to_string(),
    );
    "structural"
}

fn select_codeql_backend(
    _requested: &str,
    availability: &TaintIrisNextBackendAvailability,
    warnings: &mut Vec<String>,
) -> &'static str {
    if availability.codeql_runnable {
        return "codeql";
    }
    warnings.push(codeql_unavailable_warning(availability).to_string());
    "structural"
}

fn codeql_unavailable_warning(availability: &TaintIrisNextBackendAvailability) -> &'static str {
    if !availability.codeql_db_present {
        return "backend=codeql requested, but no existing CodeQL DB was found; build with `codeql database create --language=<lang> --source-root=<repo> <repo>/.kuzushi/codeql-db` then rerun. Using structural evidence.";
    }
    "backend=codeql requested, but the codeql launcher was not found on PATH (set KUZUSHI_CODEQL_BIN or install the CodeQL CLI bundle). Using structural evidence."
}

/// The JVM Joern backend is retired: the in-process cpg-rs engine replaced
/// it. Honour the old name by routing to cpg-rs when it can run, so
/// `backend=joern` in saved configs keeps producing CPG evidence.
fn select_retired_joern_backend(
    _requested: &str,
    availability: &TaintIrisNextBackendAvailability,
    warnings: &mut Vec<String>,
) -> &'static str {
    if availability.cpgrs_runnable {
        warnings.push(
            "backend=joern is retired; the in-process cpg-rs engine replaced JVM Joern. \
             Using backend=cpg-rs (rename your config to backend=cpg-rs)."
                .to_string(),
        );
        return "cpg-rs";
    }
    warnings.push(
        "backend=joern is retired and no detected language has a cpg-rs frontend. \
         Using structural evidence."
            .to_string(),
    );
    "structural"
}

fn select_auto_backend(
    _requested: &str,
    availability: &TaintIrisNextBackendAvailability,
    _warnings: &mut Vec<String>,
) -> &'static str {
    // cpg-rs first: it needs no install, no prebuilt artifact, and builds
    // its graphs implicitly — the out-of-the-box path for fresh checkouts.
    if availability.cpgrs_runnable {
        return "cpg-rs";
    }
    if availability.codeql_runnable {
        return "codeql";
    }
    "structural"
}

fn select_deprecated_backend(
    requested: &str,
    _availability: &TaintIrisNextBackendAvailability,
    warnings: &mut Vec<String>,
) -> &'static str {
    warnings.push(format!(
        "backend={requested} is not a Rust execution backend in this cutover; using structural evidence"
    ));
    "structural"
}

fn select_structural_backend(
    _requested: &str,
    _availability: &TaintIrisNextBackendAvailability,
    _warnings: &mut Vec<String>,
) -> &'static str {
    "structural"
}

/// Reports the actual structural matcher Kuzushi will use, not a hardcoded
/// label. Returns `"rg"` when ripgrep is on PATH, otherwise `"inproc"` for
/// the pure-Rust line walker. Surfaced in run results so operators can tell
/// at a glance whether rg accelerated the candidate collection.
fn detect_structural_tool() -> &'static str {
    if super::rg_available() {
        "rg"
    } else {
        "inproc"
    }
}

pub(crate) fn taint_iris_next_has_required_context(plan: &TaintIrisNextPlan) -> bool {
    plan.context_status.ok || !plan.languages.is_empty()
}

pub(crate) fn render_taint_iris_next_missing_context(plan: &TaintIrisNextPlan) -> String {
    [
        "Taint IRIS Next needs usable Kuzushi context or a source-file inventory before it hunts."
            .to_string(),
        format!(
            "context: {} ({})",
            if plan.context_status.ok { "loaded" } else { "missing" },
            plan.context_status.reason
        ),
        format!(
            "file inventory languages: {}",
            if plan.languages.is_empty() {
                "none detected".to_string()
            } else {
                plan.languages.join(", ")
            }
        ),
        format!(
            "threat model: {} ({}) (warning only)",
            if plan.threat_model_status.ok {
                "loaded"
            } else {
                "warning"
            },
            plan.threat_model_status.reason
        ),
        String::new(),
        "Run context:build, then rerun taint-iris-next. A threat model improves ranking but is not a hard blocker.".to_string(),
    ]
    .join("\n")
}
