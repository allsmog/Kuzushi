use super::*;

pub(crate) fn choose_taint_iris_next_backend(
    requested: &str,
    repo_root: &Path,
) -> TaintIrisNextBackendChoice {
    let codeql_db = [
        repo_root.join(".kuzushi").join("codeql-db"),
        repo_root.join(".codeql").join("db"),
    ]
    .into_iter()
    .find(|path| path.exists());
    let mut warnings = Vec::new();
    let selected = match requested {
        "codeql" if codeql_db.is_some() => "codeql",
        "codeql" => {
            warnings.push(
                "backend=codeql requested, but no existing CodeQL DB was found; using structural evidence"
                    .to_string(),
            );
            "structural"
        }
        "semgrep" | "joern" | "language" => {
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
        structural_tool: "rg".to_string(),
        warnings,
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
