use super::*;

pub(crate) fn taint_cwe_selection_schema() -> Value {
    json!({
        "type": "object",
        "required": ["cwes"],
        "additionalProperties": true,
        "properties": {
            "cwes": {
                "type": "array",
                "items": {
                    "oneOf": [
                        {"type": "string"},
                        {
                            "type": "object",
                            "required": ["id"],
                            "additionalProperties": true,
                            "properties": {
                                "id": {"type": "string"},
                                "name": {"type": "string"},
                                "reason": {"type": "string"}
                            }
                        }
                    ]
                }
            }
        }
    })
}

pub(crate) fn build_taint_cwe_select_prompt(
    target: &Path,
    inventory: &[(String, String)],
) -> String {
    let mut prompt = vec![
        "Select the CWE classes that deserve IRIS-style taint analysis for this repository."
            .to_string(),
        format!("Target: {}", target.display()),
        "Prefer source-to-sink classes such as injection, traversal, SSRF, deserialization, and unsafe code execution when the snippets support them.".to_string(),
    ];
    append_inventory(&mut prompt, inventory);
    prompt.join("\n")
}

pub(crate) fn build_taint_iris_prompt(
    target: &Path,
    cwes: &[TaintCweSelection],
    inventory: &[(String, String)],
    codeql_db: Option<&Path>,
    options: &TaintIrisInput,
) -> String {
    let mut prompt = vec![
        "Run bounded IRIS-style taint analysis over this repository.".to_string(),
        format!("Target: {}", target.display()),
        "Trace attacker-controlled sources to dangerous sinks. Use CodeQL reasoning where possible, but only report vulnerabilities supported by source evidence.".to_string(),
        String::new(),
        "CWE classes to analyze:".to_string(),
    ];
    append_cwe_selection(&mut prompt, cwes);
    prompt.push(String::new());
    prompt.push(codeql_context_line(codeql_db));
    append_budget_cap(&mut prompt, options.max_budget_usd);
    append_prompt_override(&mut prompt, options.prompt_override.as_deref());
    append_inventory(&mut prompt, inventory);
    prompt.join("\n")
}

fn append_cwe_selection(prompt: &mut Vec<String>, cwes: &[TaintCweSelection]) {
    prompt.extend(
        cwes.iter()
            .map(|cwe| format!("- {}: {} ({})", cwe.id, cwe.name, cwe.reason)),
    );
}

fn codeql_context_line(codeql_db: Option<&Path>) -> String {
    match codeql_db {
        Some(path) => format!(
            "A CodeQL database appears to be available at {}. Generated query artifacts, if any, should stay under .kuzushi/v3/runs/<run-id>/taint-iris.",
            path.display()
        ),
        None => "No CodeQL database was found under .kuzushi/codeql-db or .codeql/db; use grep/manual source tracing inside the target only."
            .to_string(),
    }
}

fn append_budget_cap(prompt: &mut Vec<String>, max_budget_usd: Option<f64>) {
    if let Some(max_budget_usd) = max_budget_usd {
        prompt.push(format!(
            "Operator budget cap: ${max_budget_usd:.2}. Keep the analysis focused."
        ));
    }
}

fn append_prompt_override(prompt: &mut Vec<String>, prompt_override: Option<&str>) {
    let Some(prompt_override) = prompt_override else {
        return;
    };
    prompt.push(String::new());
    prompt.push("Operator prompt override:".to_string());
    prompt.push(prompt_override.to_string());
}

fn append_inventory(prompt: &mut Vec<String>, inventory: &[(String, String)]) {
    prompt.push(String::new());
    prompt.push("Repository inventory and snippets:".to_string());
    if inventory.is_empty() {
        prompt.push("(no readable source snippets found)".to_string());
    }
    for (path, snippet) in inventory {
        prompt.push(format!("\n--- {path} ---\n{snippet}"));
    }
}

pub(crate) fn resolve_taint_codeql_db_path(
    target: &Path,
    workspace_root: Option<&Path>,
) -> Option<PathBuf> {
    taint_codeql_roots(target, workspace_root)
        .into_iter()
        .flat_map(|root| taint_codeql_db_candidates(&root))
        .find(|candidate| candidate.exists())
}

fn taint_codeql_roots(target: &Path, workspace_root: Option<&Path>) -> Vec<PathBuf> {
    let mut roots = vec![target.to_path_buf()];
    if let Some(workspace_root) = workspace_root {
        roots.push(workspace_root.to_path_buf());
    }
    roots.sort();
    roots.dedup();
    roots
}

fn taint_codeql_db_candidates(root: &Path) -> [PathBuf; 2] {
    [
        crate::workspace::workspace_codeql_db_path(root),
        crate::workspace::legacy_codeql_db_path(root),
    ]
}
