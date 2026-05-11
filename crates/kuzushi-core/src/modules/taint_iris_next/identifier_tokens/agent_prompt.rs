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
