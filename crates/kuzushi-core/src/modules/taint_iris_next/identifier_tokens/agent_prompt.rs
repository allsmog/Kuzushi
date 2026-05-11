use super::*;

pub(in crate::modules::taint_iris_next) fn build_taint_iris_next_agent_prompt(
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) -> String {
    let mut lines = vec![
        "Taint IRIS Next".to_string(),
        "IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities".to_string(),
        String::new(),
        "You are Kuzushi's Taint IRIS Next agent. This is an agent-forward adaptation inspired by the IRIS paper, not the original implementation.".to_string(),
        String::new(),
        "## Objective".to_string(),
        "Use the deterministic context, threat model, CWE catalog, candidates, typed specs, and evidence bundles below to select relevant CWE themes and report only defensible findings.".to_string(),
        format!("minimum finding evidence level: {}", plan.caps.min_evidence_level),
        String::new(),
        "## Backend".to_string(),
        format!("requested: {}", plan.backend.requested),
        format!("selected: {}", plan.backend.selected),
        format!("structural engine: {}", evidence.structural_engine),
        format!("evidence tool: {}", evidence.tool),
        format!(
            "CodeQL corroboration: {}",
            if plan.backend.corroborate_with_codeql.unwrap_or(false) {
                "enabled"
            } else {
                "disabled"
            }
        ),
        plan.backend
            .codeql_db_path
            .as_ref()
            .map(|path| format!("existing CodeQL DB: {path}"))
            .unwrap_or_else(|| "existing CodeQL DB: none".to_string()),
        String::new(),
        "## Context Summary".to_string(),
        format!("languages: {}", plan.languages.join(", ")),
        format!("context artifact: {}", plan.context_status.reason),
        String::new(),
        "## Threat Model Summary".to_string(),
        format!("threat model artifact: {}", plan.threat_model_status.reason),
        String::new(),
        plan.prompt_catalog.clone(),
        String::new(),
    ];
    if !plan.cwe_focus.is_empty() {
        lines.push("## CWE Focus".to_string());
        lines.push(format!(
            "The operator restricted this hunt to {}. Choose only from these CWEs (the catalog has already been filtered to match) and use customCweRationale only if you discover a clearly different vulnerability class.",
            plan.cwe_focus.join(", ")
        ));
        lines.push(String::new());
    }
    append_discovered_signals_section(&mut lines, &plan.discovered_signals);
    lines.extend(vec![
        "## Candidate And Spec Counts".to_string(),
        format!("candidateCounts: {}", json!(evidence.candidate_counts)),
        format!("labeledSpecCounts: {}", json!(evidence.labeled_spec_counts)),
        String::new(),
        "## Evidence Bundles".to_string(),
    ]);
    for item in evidence.evidence.iter().take(40) {
        lines.push(format!(
            "- {} {} {}:{} [{}] {}",
            item.cwe, item.role, item.file_path, item.line, item.evidence_level, item.snippet
        ));
    }
    lines.push(String::new());
    lines.push("## Linked Stories".to_string());
    for story in evidence.linked_stories.iter().take(20) {
        lines.push(format!(
            "- {} {}:{} -> {} ({})",
            story.cwe, story.file_path, story.source_line, story.sink_line, story.rationale
        ));
    }
    append_sanitizer_bodies_section(&mut lines, plan, evidence);
    lines.push(String::new());
    lines.push("## False-Positive Patterns (apply BEFORE promoting to finding)".to_string());
    lines.push(
        "Some apparent source→sink flows are by-design APIs, not vulnerabilities. \
         Recognise these patterns dynamically and downgrade to candidate or rejected \
         (with rationale) instead of promoting to finding:".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "**Documented passthrough SQL execution.** A function whose contract IS \
         \"execute the SQL the caller provides\" is not SQL injection — SPI / \
         exec / eval respects the caller's privileges. Signals: a `text` / `string` \
         parameter named like `sql`, `sqlquery`, `query`, `select_query`, `cmd`, \
         `script`, `expression` is passed AS THE ENTIRE INPUT to SPI_execute / \
         SPI_prepare / eval / Function() / exec() / Runtime.exec — no \
         concatenation, no format string. Examples: postgres `crosstab(text)`, \
         `ts_rewrite(query, select_query)`, `ts_stat(sqlquery)`, `dblink_exec`; \
         JS `vm.runInNewContext(userScript)`; Python `pandas.eval(expr)`. \
         **Real injection** requires the user input to be CONCATENATED into a \
         SQL/command string (e.g. `appendStringInfo(buf, \"SELECT * FROM %s\", \
         user_text)` then `SPI_execute(buf)`); the user controls a FRAGMENT, not \
         the whole query.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "**Role-gated privileged primitives.** `dlopen` / `system` / file I/O \
         reachable only after a `has_privs_of_role(...)` / `superuser()` / role \
         membership check is documented privileged functionality, not a \
         vulnerability. The check restricts WHO can call the API; reaching the \
         sink from a SQL session means the operator already granted that role.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "**Configuration GUCs / superuser-only settings.** `archive_command`, \
         `restore_command`, `shell_archive_command`, and other superuser-only \
         GUCs are documented as shell-executing settings configurable only by \
         the operator. Reaching `system()` / `OpenPipeStream()` from a GUC is \
         not injection.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "**Build tools / offline binaries.** Code under `src/tools/`, \
         `src/bin/pg_upgrade/`, `pg_bsd_indent/`, build scripts, and CLI \
         utilities that accept `argv` is not part of the server's runtime \
         attack surface. argv-derived filenames in CLI tools are not SQL-\
         reachable sources.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "**String-literal arguments to risky sinks.** Tree-sitter confirms the \
         argument is a string literal (e.g. `system(\"locale -a\")`, \
         `LoadLibrary(\"netmsg.dll\")`) → not attacker-controlled.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "**Do NOT trust function names as sanitizers — MANDATORY VERIFICATION.** \
         A function named `get_safe_path`, `is_safe`, `check_locality`, \
         `sanitize_input`, `validate_*`, `check_*` may CLAIM to be a sanitizer \
         but the bug can be INSIDE the sanitizer (skipped branch, incomplete \
         check, post-canonicalisation bypass).\n\n\
         When a joern-confirmed flow passes through a sanitizer-named \
         function, you MUST do all of the following before rejecting the \
         flow as 'sanitised':\n\
         1. Call `joern.method_at` (or `tree_sitter:node_at`) on the \
            sanitizer's DEFINITION line (use `joern.callers_of` first to \
            locate it). Reading the CALL SITE alone is not enough — bugs \
            live in the function body.\n\
         2. Look for these bypass patterns in the body:\n\
            - A `check = false` (or skip-flag) branch — e.g. \
              `if (location_came_from_trusted_table) skip_check = true;`\n\
            - A check applied to the input BEFORE concatenation but not \
              after — e.g. `validate(prefix); fullname = prefix + '/' + \
              user_input; (no validate(fullname));`\n\
            - Canonicalisation that resolves `..` after the check, so the \
              check sees a pre-canonical form.\n\
            - Whitelist by prefix only (`strncmp(path, allowed, n) == 0`) \
              without verifying the suffix doesn't escape via `..` after \
              canonicalisation.\n\
            - Locality / privilege check skipped on a 'trusted' branch \
              that processes user-supplied filename / path / SQL fragment.\n\
         3. If you find any of these patterns, the flow IS exploitable — \
            promote to finding with a customCweRationale explaining the \
            exact bypass and the line numbers of the missing check.\n\
         4. If you DON'T inspect the sanitizer body, default to keeping \
            the candidate at evidence_level=candidate (not 'rejected') so \
            an operator reviewer can audit. 'Sanitizer name looks right' \
            is NOT sufficient evidence to reject — it is sufficient \
            evidence to investigate.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "For each candidate that LOOKS like a textbook injection / privesc \
         flow, run through these patterns before promoting. Use \
         `tree_sitter:node_at` to read the function signature (parameter \
         names) and `joern.callers_of` to see who invokes the function. \
         A finding requires the flow to NOT match any of these by-design \
         patterns.".to_string(),
    );
    lines.push(String::new());
    lines.push("## Contract".to_string());
    lines.push(
        "- Return strict JSON matching { selectedCwes, findings, triage, notes }.".to_string(),
    );
    lines.push(format!(
        "- Return at most {} findings.",
        plan.caps.max_agent_findings
    ));
    lines.push("- Cite catalogSignals for every selected CWE and every finding.".to_string());
    lines.join("\n")
}

/// Render a "## Discovered Signals" section for the agent prompt.
/// Lists, per CWE, the entry-points / sources / sinks the discovery
/// pass found in the actual codebase. The model gets concrete names
/// it can pass to `joern.taint_paths` and `tree_sitter:callers`
/// without having to guess. We cap the per-CWE list aggressively (8
/// entries) so the prompt stays compact even on a postgres-scale
/// discovery sweep — the artifact at .kuzushi/discovered-signals.json
/// has the full set when the agent wants to drill deeper.
fn append_discovered_signals_section(
    lines: &mut Vec<String>,
    signals: &DiscoveredSignals,
) {
    if signals.entry_points.is_empty()
        && signals.sources.is_empty()
        && signals.sinks.is_empty()
    {
        return;
    }
    lines.push("## Discovered Signals".to_string());
    lines.push(format!(
        "Per-target regex sweep found {} entry-point(s), {} source(s), and {} sink(s) in the codebase. Use these names directly with `joern.taint_paths`, `tree_sitter:callers`, and `codeql:flows_for_cwe` — they are real call/method names this repo actually contains, not catalog guesses.",
        signals.entry_points.len(),
        signals.sources.len(),
        signals.sinks.len()
    ));
    if !signals.entry_points.is_empty() {
        lines.push(String::new());
        lines.push("### Entry points".to_string());
        for entry in signals.entry_points.iter().take(20) {
            lines.push(format!(
                "- {} ({}) {}:{}    [{}]",
                entry.name, entry.cwe, entry.file, entry.line, entry.marker
            ));
        }
    }
    if !signals.sinks.is_empty() {
        lines.push(String::new());
        lines.push("### Privesc / RCE sinks".to_string());
        let mut by_cwe: std::collections::BTreeMap<&str, Vec<&DiscoveredSignal>> =
            std::collections::BTreeMap::new();
        for sink in &signals.sinks {
            by_cwe
                .entry(sink.cwe.as_str())
                .or_default()
                .push(sink);
        }
        for (cwe, entries) in by_cwe {
            let names: std::collections::BTreeSet<&str> =
                entries.iter().map(|e| e.name.as_str()).collect();
            let head: Vec<&str> = names.into_iter().take(8).collect();
            let example = entries.first().map(|e| format!("{}:{}", e.file, e.line));
            lines.push(format!(
                "- {cwe}: {}{}",
                head.join(", "),
                example
                    .map(|loc| format!(" (e.g. {loc})"))
                    .unwrap_or_default(),
            ));
        }
    }
    lines.push(String::new());
}

/// Read source files referenced in linked stories and extract the
/// bodies of any functions whose names match sanitizer-shaped
/// patterns (`check_*`, `validate_*`, `safe_*`, `*_safe_*`,
/// `is_safe`, `sanitize_*`). Include them verbatim in the agent
/// prompt so the agent can audit the sanitizer body without spending
/// MCP-call budget — the bypass usually lives in a single function
/// (e.g. orafce `get_safe_path` setting `check_locality = false` on
/// the named-location branch).
///
/// Capped per-body (60 lines), capped total (8 bodies / ~2KB worst
/// case) so the prompt stays compact on large hunts. Files that
/// don't open are silently skipped; this is best-effort, not a
/// correctness gate.
pub(in crate::modules::taint_iris_next) fn append_sanitizer_bodies_section(
    lines: &mut Vec<String>,
    plan: &TaintIrisNextPlan,
    evidence: &TaintIrisNextEvidenceResult,
) {
    let mut files_to_scan: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for story in evidence.linked_stories.iter() {
        files_to_scan.insert(story.file_path.clone());
    }
    for evidence_row in evidence.evidence.iter() {
        files_to_scan.insert(evidence_row.file_path.clone());
    }
    if files_to_scan.is_empty() {
        return;
    }
    let mut bodies: Vec<(String, String, u32, String)> = Vec::new();
    for relative_path in files_to_scan.iter().take(20) {
        let abs = plan.scan_root.join(relative_path);
        let Ok(content) = std::fs::read_to_string(&abs) else {
            continue;
        };
        for (name, start_line, body) in extract_sanitizer_function_bodies(&content) {
            bodies.push((
                relative_path.clone(),
                name,
                start_line,
                body,
            ));
            if bodies.len() >= 8 {
                break;
            }
        }
        if bodies.len() >= 8 {
            break;
        }
    }
    if bodies.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push("## Sanitizer Function Bodies (audit for bypass)".to_string());
    lines.push(
        "Functions in linked-story files whose names suggest sanitization. \
         Bugs hide INSIDE these — `check_locality = false` skip-branches, \
         pre-concatenation-only validation, prefix whitelists vs canonical \
         paths, etc. Read each body and check whether every flow to a sink \
         goes through the sanitizer AND whether the sanitizer is applied to \
         the FINAL value used at the sink. If a sanitizer's body contains \
         a skip-branch that bypasses the check on a 'trusted' input, the \
         flow that hits the skip-branch is exploitable — promote to finding."
            .to_string(),
    );
    for (path, name, start_line, body) in &bodies {
        lines.push(String::new());
        lines.push(format!("### {name} at {path}:{start_line}"));
        lines.push("```c".to_string());
        lines.push(body.clone());
        lines.push("```".to_string());
    }
    lines.push(String::new());
}

/// Extract function bodies whose names look like sanitizers. Returns
/// `(name, start_line, body)` for each match.
///
/// Heuristic parser: find a line that starts with an identifier (the
/// return type or a continuation), where the NEXT non-comment line
/// has the function name followed by `(`. Then track brace depth from
/// the first `{` until depth returns to 0.
///
/// Caps each body at 60 lines so we never include a huge function.
/// Skips static-prototype-only declarations (`fn(...)` with `;`).
fn extract_sanitizer_function_bodies(content: &str) -> Vec<(String, u32, String)> {
    let lines: Vec<&str> = content.lines().collect();
    let mut out: Vec<(String, u32, String)> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim_start();
        // Look for `name(args)` definition lines (no leading whitespace
        // for the return type two lines above is typical postgres
        // style: `static char *\nget_safe_path(text *...)`).
        if let Some(name) = function_name_from_def_line(trimmed) {
            if is_sanitizer_shaped_name(&name) {
                // Find the opening brace (search forward up to 8 lines).
                let mut brace_line: Option<usize> = None;
                for j in i..lines.len().min(i + 8) {
                    if lines[j].contains('{') {
                        brace_line = Some(j);
                        break;
                    }
                    if lines[j].trim_end().ends_with(';') {
                        // Prototype, not definition.
                        break;
                    }
                }
                if let Some(brace_start) = brace_line {
                    // Track brace depth.
                    let mut depth: i32 = 0;
                    let mut started = false;
                    let mut end_line = brace_start;
                    for j in brace_start..lines.len() {
                        for ch in lines[j].chars() {
                            match ch {
                                '{' => {
                                    depth += 1;
                                    started = true;
                                }
                                '}' => depth -= 1,
                                _ => {}
                            }
                        }
                        if started && depth <= 0 {
                            end_line = j;
                            break;
                        }
                    }
                    // Include up to 60 lines starting from the
                    // declaration (i) to the closing brace.
                    let span_end = end_line.min(i + 60);
                    let body: String = lines[i..=span_end].join("\n");
                    out.push((name, (i + 1) as u32, body));
                    if out.len() >= 8 {
                        return out;
                    }
                    i = end_line + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// Match a line of the shape `name(args)` (with optional return-type
/// prefix on the same line) and return `name` if the next char after
/// the name is `(`. Returns None for if/while/for/switch etc.
fn function_name_from_def_line(line: &str) -> Option<String> {
    // The function name is the identifier immediately preceding `(`.
    let paren = line.find('(')?;
    if paren == 0 {
        return None;
    }
    let before = &line[..paren];
    // Trim trailing whitespace.
    let trimmed = before.trim_end();
    // Walk backward to find the start of the identifier.
    let bytes = trimmed.as_bytes();
    let mut end = bytes.len();
    while end > 0 {
        let b = bytes[end - 1];
        if b.is_ascii_alphanumeric() || b == b'_' {
            end -= 1;
        } else {
            break;
        }
    }
    let name = &trimmed[end..];
    if name.is_empty() {
        return None;
    }
    // Reject C keywords that look like calls.
    if matches!(
        name,
        "if" | "while"
            | "for"
            | "switch"
            | "return"
            | "sizeof"
            | "elog"
            | "ereport"
            | "Assert"
            | "DEBUG"
            | "ERROR"
            | "FATAL"
            | "WARNING"
            | "NOTICE"
    ) {
        return None;
    }
    Some(name.to_string())
}

fn is_sanitizer_shaped_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("check_")
        || lower.starts_with("validate_")
        || lower.starts_with("verify_")
        || lower.starts_with("safe_")
        || lower.starts_with("sanitize_")
        || lower.starts_with("escape_")
        || lower.starts_with("quote_")
        || lower.starts_with("canonicalize_")
    {
        return true;
    }
    matches!(
        lower.as_str(),
        "is_safe" | "is_valid" | "is_safe_path" | "is_authorized"
    ) || lower.contains("_safe_")
        || lower.contains("_safer_")
        || lower.contains("get_safe")
        || lower.contains("ensure_")
}

#[cfg(test)]
mod sanitizer_body_tests {
    use super::*;

    #[test]
    fn extracts_sanitizer_body_from_orafce_style_source() {
        let src = r#"
static char *
get_safe_path(text *location, text *filename)
{
    char *fullname;
    bool check_locality;
    if (safe_named_location(location))
    {
        fullname = build(location, filename);
        check_locality = false;
    }
    else
    {
        fullname = build(location, filename);
        check_locality = true;
    }
    canonicalize_path(fullname);
    if (check_locality)
        check_secure_locality(fullname);
    return fullname;
}

static void
other_fn(int x)
{
    return;
}
"#;
        let bodies = extract_sanitizer_function_bodies(src);
        assert!(
            bodies.iter().any(|(n, _, _)| n == "get_safe_path"),
            "get_safe_path should be extracted: {:?}",
            bodies.iter().map(|(n, _, _)| n).collect::<Vec<_>>()
        );
        let body = &bodies
            .iter()
            .find(|(n, _, _)| n == "get_safe_path")
            .unwrap()
            .2;
        // The body should include the skip-branch.
        assert!(body.contains("check_locality = false"), "got body:\n{body}");
        assert!(body.contains("canonicalize_path"));
        // Non-sanitizer function not extracted.
        assert!(!bodies.iter().any(|(n, _, _)| n == "other_fn"));
    }

    #[test]
    fn name_classification_only_flags_sanitizer_shapes() {
        assert!(is_sanitizer_shaped_name("check_locality"));
        assert!(is_sanitizer_shaped_name("get_safe_path"));
        assert!(is_sanitizer_shaped_name("safe_named_location"));
        assert!(is_sanitizer_shaped_name("validate_filename"));
        assert!(is_sanitizer_shaped_name("escape_string"));
        assert!(is_sanitizer_shaped_name("quote_identifier"));
        assert!(is_sanitizer_shaped_name("canonicalize_path"));
        assert!(is_sanitizer_shaped_name("ensure_directory_exists"));
        // Negative cases.
        assert!(!is_sanitizer_shaped_name("utl_file_fopen"));
        assert!(!is_sanitizer_shaped_name("strcpy"));
        assert!(!is_sanitizer_shaped_name("appendStringInfo"));
        assert!(!is_sanitizer_shaped_name("PG_GETARG_TEXT_PP"));
    }
}
