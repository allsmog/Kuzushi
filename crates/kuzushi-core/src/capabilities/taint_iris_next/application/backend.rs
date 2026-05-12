use super::*;

pub(crate) fn choose_taint_iris_next_backend(
    requested: &str,
    repo_root: &Path,
) -> TaintIrisNextBackendChoice {
    let codeql_db = super::codeql_db_path(repo_root);
    let codeql_runnable = codeql_db.is_some() && super::codeql_available();
    let joern_cpg = super::resolve_joern_cpg_path(repo_root);
    let joern_cpg_present = joern_cpg.exists();
    let joern_runnable = joern_cpg_present && super::joern_available();
    let mut warnings = Vec::new();
    let selected = match requested {
        "codeql" if codeql_runnable => "codeql",
        "codeql" if codeql_db.is_none() => {
            warnings.push(
                "backend=codeql requested, but no existing CodeQL DB was found; build with `codeql database create --language=<lang> --source-root=<repo> <repo>/.kuzushi/codeql-db` then rerun. Using structural evidence."
                    .to_string(),
            );
            "structural"
        }
        "codeql" => {
            warnings.push(
                "backend=codeql requested, but the codeql launcher was not found on PATH (set KUZUSHI_CODEQL_BIN or install the CodeQL CLI bundle). Using structural evidence."
                    .to_string(),
            );
            "structural"
        }
        "joern" if joern_runnable => "joern",
        "joern" if !joern_cpg_present => {
            warnings.push(format!(
                "backend=joern requested, but no CPG was found at {}; build with `joern-parse <target> --output {}` then rerun. Using structural evidence.",
                joern_cpg.display(),
                joern_cpg.display(),
            ));
            "structural"
        }
        "joern" => {
            warnings.push(
                "backend=joern requested, but the joern launcher was not found on PATH (set KUZUSHI_JOERN_BIN or install Joern). Using structural evidence."
                    .to_string(),
            );
            "structural"
        }
        // `auto` prefers codeql > joern > structural when each tier's
        // tooling is available. CodeQL ranks first because it ships
        // mature security query packs that already encode source/sink
        // semantics, so we don't have to round-trip catalog patterns
        // through `cpg.call.code(...)` regex matching. Fallback flow:
        // codeql -> joern -> structural. No warning when auto upgrades.
        "auto" if codeql_runnable => "codeql",
        "auto" if joern_runnable => "joern",
        "semgrep" | "language" => {
            warnings.push(format!(
                "backend={requested} is not a Rust execution backend in this cutover; using structural evidence"
            ));
            "structural"
        }
        _ => "structural",
    };
    TaintIrisNextBackendChoice {
        requested: requested.to_string(),
        selected: selected.to_string(),
        codeql_db_path: codeql_db.as_ref().map(|path| path.display().to_string()),
        corroborate_with_codeql: codeql_db.as_ref().map(|_| true),
        structural_tool: detect_structural_tool().to_string(),
        warnings,
    }
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
