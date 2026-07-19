use super::*;

pub(crate) fn choose_taint_iris_next_backend(
    requested: &str,
    repo_root: &Path,
) -> Result<TaintIrisNextBackendChoice> {
    let codeql_db = super::codeql_db_path(repo_root)?;
    let availability = TaintIrisNextBackendAvailability {
        codeql_db_present: codeql_db.is_some(),
        codeql_runnable: codeql_db.is_some() && super::codeql_available(),
        joern_cpg: super::resolve_joern_cpg_path(repo_root),
        joern_runnable: false,
    };
    let availability = availability.with_joern_status();
    let mut warnings = Vec::new();
    let selected = select_taint_iris_next_backend(requested, &availability, &mut warnings);
    Ok(TaintIrisNextBackendChoice {
        requested: requested.to_string(),
        selected: selected.to_string(),
        codeql_db_path: codeql_db.as_ref().map(|path| path.display().to_string()),
        corroborate_with_codeql: codeql_db.as_ref().map(|_| true),
        structural_tool: detect_structural_tool().to_string(),
        warnings,
    })
}

struct TaintIrisNextBackendAvailability {
    codeql_db_present: bool,
    codeql_runnable: bool,
    joern_cpg: std::path::PathBuf,
    joern_runnable: bool,
}

impl TaintIrisNextBackendAvailability {
    fn with_joern_status(mut self) -> Self {
        self.joern_runnable = self.joern_cpg.exists() && super::joern_available();
        self
    }
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
            name: "codeql",
            selector: select_codeql_backend,
        },
        BackendRequestSpec {
            name: "joern",
            selector: select_joern_backend,
        },
        BackendRequestSpec {
            name: "auto",
            selector: select_auto_backend,
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

fn select_joern_backend(
    _requested: &str,
    availability: &TaintIrisNextBackendAvailability,
    warnings: &mut Vec<String>,
) -> &'static str {
    if availability.joern_runnable {
        return "joern";
    }
    warnings.push(joern_unavailable_warning(availability));
    "structural"
}

fn joern_unavailable_warning(availability: &TaintIrisNextBackendAvailability) -> String {
    if !availability.joern_cpg.exists() {
        return format!(
            "backend=joern requested, but no CPG was found at {}; build with `joern-parse <target> --output {}` then rerun. Using structural evidence.",
            availability.joern_cpg.display(),
            availability.joern_cpg.display(),
        );
    }
    "backend=joern requested, but the joern launcher was not found on PATH (set KUZUSHI_JOERN_BIN or install Joern). Using structural evidence."
        .to_string()
}

fn select_auto_backend(
    _requested: &str,
    availability: &TaintIrisNextBackendAvailability,
    _warnings: &mut Vec<String>,
) -> &'static str {
    if availability.codeql_runnable {
        return "codeql";
    }
    if availability.joern_runnable {
        return "joern";
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
