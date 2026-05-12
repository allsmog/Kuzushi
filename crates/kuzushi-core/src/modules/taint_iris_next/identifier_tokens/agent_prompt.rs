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
    lines.push(
        "## Mandatory Call-Site + Entry-Point Audit (apply BEFORE every verdict)".to_string(),
    );
    lines.push(
        "Reading a memcpy / palloc / system / dlopen site in isolation is \
         not enough to decide promote vs reject. The deterministic pipeline \
         hands you joern-confirmed source→sink flows but joern alone does \
         not tell you whether the flow is **reachable from an attacker-\
         supplied entry point**. Without that, a 'caller-contract' \
         rejection is speculation and a promotion is hand-waving. The \
         following audit is REQUIRED for every candidate you are about to \
         either promote or reject:".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "1. **Identify the enclosing function.** For every candidate \
            (source line, sink line, or both), call `tree_sitter:node_at` \
            on the candidate line to confirm it sits inside a function \
            definition, and capture the function name. The deterministic \
            pipeline pre-inlines source-enclosing and sink-enclosing \
            bodies under '## Sanitizer Function Bodies' — use those when \
            present, fall back to a fresh tree-sitter call for sites that \
            didn't make the inline slot budget.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "2. **Walk callers back to an entry point.** Call \
            `joern.callers_of` on the enclosing function (limit=10, \
            maxDepth=6 by default). For each immediate caller, recurse \
            until you hit one of:\n\
            - A SQL-callable entry point: a `PG_FUNCTION_INFO_V1(...)` \
              registration or a `Datum name(PG_FUNCTION_ARGS) { ... }` \
              definition. These are reachable from any SQL session.\n\
            - A network handler / web route: anything pattern-matching \
              `@app.route`, `app.{get,post,...}`, `router.{...}`, or a \
              language-specific HTTP handler.\n\
            - A CLI / argv handler: a `main(int argc, char **argv)` that \
              the caller chain reaches without role/superuser gating.\n\
            - A protocol parser entry: `RecvBackup`, `ProcessStartupPacket`, \
              `pq_getmessage`, OpenSSL `BIO_read`, libxml2 `xmlReadFile`, \
              etc. — any externally-fed bytes-in / message-in primitive.\n\
            Cap recursion at depth 6; if you hit the cap without finding \
            an entry point, treat the candidate as unreachable from \
            attacker-controlled input (downgrade to candidate, not \
            rejected — reviewer audit).".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "3. **For each caller, inspect what it passes.** Use \
            `tree_sitter:node_at` on the call site to read the actual \
            argument expressions. A 'caller-contract' rejection \
            (\"caller must allocate enough\") is ONLY valid when EVERY \
            entry-point-reachable caller passes a compile-time-constant \
            size (e.g. `pullf_read_fixed(src, 4, hash)` with a fixed-size \
            local buffer for a 4-byte SHA tag). If ANY entry-point-\
            reachable caller passes an attacker-influenced length \
            (`packet_len`, `n & 0xff`, `header.size`, `msg[0]`, anything \
            joern's reachableByFlows tagged), the candidate IS exploitable \
            — promote with a customCweRationale citing the specific caller \
            line and argument.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "4. **Treat inline VULN- / FIXME- / XXX- / TODO- comments as \
            priority breadcrumbs.** Use `tree_sitter:query` with \
            `(comment) @comment` against the candidate's file and \
            inspect comments within ±10 lines of the sink. Comments \
            shaped like `//VULN-`, `//FIXME(bounds)`, `//XXX: skipped \
            check`, `/* TODO: validate len */` are explicit human \
            signals that a guard was disabled or never written. Treat \
            them as PROMOTE-priority evidence and verify the missing \
            check via the call-site walk above. Do not silently ignore \
            these.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "5. **Cite the audit in your verdict.** Every `findings[]` entry \
            and every `triage[]` rejection MUST include the call-chain \
            you walked (or note 'depth cap reached, no entry point'), the \
            argument shapes you observed at the boundary, and any \
            VULN-/FIXME- breadcrumbs you found or confirmed absent. \
            Verdicts without this audit trail are not defensible.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "## Realistic Exploit Patterns (privilege-boundary crossing)".to_string(),
    );
    lines.push(
        "A SQL-injection / command-injection / path-traversal finding is \
         interesting only when it crosses a privilege boundary that an \
         operator-controlled threat model cares about. When promoting a \
         finding, NAME the realistic application pattern that creates the \
         boundary. Without a named pattern, the finding is a candidate, \
         not a finding.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "Common postgres-shaped patterns to look for:".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "- **SECURITY DEFINER wrapper**: an admin-created function calls \
         the vulnerable primitive (`dblink_open`, `dblink_close`, \
         `dblink_fetch`, `SPI_execute`, dynamic-SQL `appendStringInfo` \
         sites, etc.) using `dblink_connect_u` or stored credentials. \
         The wrapper is GRANTed EXECUTE to less-privileged roles. The \
         injection runs as the wrapper's identity, not the caller's. The \
         privilege boundary is *admin role* → *unprivileged role*; the \
         injection crosses it. This is the dblink CVE shape: cursor-name \
         injection in `dblink_close('cur; DROP TABLE x; --')` reached via \
         `app_close_remote_cursor` becomes arbitrary SQL on the remote \
         server with the wrapper's identity.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "- **GRANT EXECUTE asymmetry**: an admin grants EXECUTE on only \
         the 'safe-sounding' subset of an extension's functions (cursor \
         management, build_sql helpers) while withholding the 'obviously \
         dangerous' ones (`dblink_exec`, `dblink_send_query`). An \
         identifier-injection in the 'safe' subset escalates to the \
         capability the admin intended to withhold.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "- **Foreign user mapping** (postgres_fdw / dblink): a CREATE \
         SERVER + CREATE USER MAPPING authenticates the local caller as a \
         more-privileged remote role. An injection in any function that \
         emits SQL through the foreign connection runs on the remote with \
         the foreign role's privileges, which may exceed everything the \
         local caller has access to.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "- **Trigger-driven**: a row-level trigger calls the vulnerable \
         primitive when an unprivileged user INSERTs / UPDATEs a watched \
         table. The injection runs in the trigger's owner's identity \
         (usually the schema owner / table owner, which is elevated \
         relative to the modifier).".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "Common framework-shaped patterns (non-postgres):".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "- **Java reflection gadgets** (Spring / Jackson): an injection \
         point that picks a class name lets the attacker reach \
         `ProcessBuilder` / `Runtime.exec` via deserialisation or \
         dependency-injection lookup.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "- **Python `__subclasses__` / `__globals__` chains**: a template \
         injection (Jinja / Mako / Django) reaches \
         `{}.__class__.__bases__[0].__subclasses__()` → \
         `subprocess.Popen`.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "- **Node `child_process.spawnSync`** reachable from an \
         `eval`-shaped sink (vm.runInNewContext, Function ctor) or a \
         `require` whose path is user-influenced.".to_string(),
    );
    lines.push(String::new());
    lines.push(
        "**Required**: cite the named pattern in your finding's \
         `customCweRationale` or `reason`. A finding without a named \
         privilege-boundary-crossing pattern stays at the `candidate` \
         level for operator audit.".to_string(),
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
    // Collect candidate function names from two sources:
    // 1. The catalog's `sanitizer_signals` for the focused CWEs — these
    //    are the names the static / per-target catalog deems
    //    sanitizer-relevant for this hunt.
    // 2. Function names that appear as text inside any linked-story
    //    rationale or candidate `catalog_signal` with role=sanitizer.
    // Without this filter, the extractor catches every postgres
    // `check_*` / `verify_*` function (amcheck consistency checkers,
    // tree-builders, parser helpers) and bloats the prompt to 30KB+
    // with code unrelated to the candidate flows.
    let mut sanitizer_names: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for entry in &plan.catalog {
        for name in &entry.sanitizer_signals {
            sanitize_function_name_for_body_lookup(name, &mut sanitizer_names);
        }
    }
    // Pull sanitizer names referenced in evidence bundles (the rg
    // pass surfaced them as sanitizer-role hits).
    for ev in &evidence.evidence {
        if ev.role == "sanitizer" {
            sanitize_function_name_for_body_lookup(&ev.pattern, &mut sanitizer_names);
        }
    }
    if sanitizer_names.is_empty() {
        return;
    }
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
    // Walk each linked story's source / sink line UP to the enclosing
    // function definition. Add the enclosing function's name to a
    // `relaxed_names` set so the extractor pulls its body even if the
    // name isn't sanitizer-shaped. This catches upstream bound-check
    // helpers like postgres `pgp_mpi_alloc` (enforces `bits > 0xFFFF`)
    // and `prepare_room` (allocates the right size) that ARE named
    // like neutral allocators / setup helpers, not sanitizers — but
    // their bodies tell the agent the flow is bounded.
    const RELAXED_BODY_MAX_LINES: usize = 30;
    const RELAXED_BODY_SLOTS: usize = 2;
    let mut relaxed_names: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    // Thread B1: every callee on each joern flow becomes a relaxed
    // body-lookup candidate — that's how `pgp_mpi_alloc` /
    // `prepare_room` style upstream bound-check helpers land inline.
    for story in evidence.linked_stories.iter() {
        for callee in &story.callees {
            relaxed_names.insert(callee.clone());
        }
    }
    let mut file_line_pairs: Vec<(String, u32)> = Vec::new();
    for story in evidence.linked_stories.iter() {
        file_line_pairs.push((story.file_path.clone(), story.source_line));
        file_line_pairs.push((story.file_path.clone(), story.sink_line));
    }
    file_line_pairs.sort();
    file_line_pairs.dedup();
    for (relative_path, line) in &file_line_pairs {
        let abs = plan.scan_root.join(relative_path);
        let Ok(content) = std::fs::read_to_string(&abs) else {
            continue;
        };
        if let Some(name) = enclosing_function_name(&content, *line) {
            relaxed_names.insert(name);
        }
    }
    let mut bodies: Vec<(String, String, u32, String)> = Vec::new();
    let mut seen_bodies: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for relative_path in files_to_scan.iter().take(40) {
        let abs = plan.scan_root.join(relative_path);
        let Ok(content) = std::fs::read_to_string(&abs) else {
            continue;
        };
        for (name, start_line, body) in extract_sanitizer_function_bodies(&content) {
            // Filter: only include if the body's function name OR a
            // close lexical variant appears in the catalog/evidence
            // sanitizer set.
            if !sanitizer_names.contains(&name)
                && !sanitizer_names
                    .iter()
                    .any(|s| name.contains(s) || s.contains(&name))
            {
                continue;
            }
            // Dedup across files (e.g. multiple postgres copies of
            // canonicalize_path in different binaries).
            let dedup_key = format!("{name}:{}", body.len());
            if !seen_bodies.insert(dedup_key) {
                continue;
            }
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
    // Pass 2: relaxed-name extraction for enclosing functions of
    // linked-story source/sink lines. Cap relaxed bodies at
    // RELAXED_BODY_SLOTS (2) of the 8 total slots and 30 lines per
    // body — they're noisier and we don't want them to crowd out the
    // sanitizer-named bodies that the agent should prioritise.
    if !relaxed_names.is_empty() && bodies.len() < 8 {
        let relaxed_quota = 8usize.saturating_sub(bodies.len()).min(RELAXED_BODY_SLOTS);
        let mut relaxed_added = 0usize;
        'relaxed_files: for relative_path in files_to_scan.iter().take(40) {
            let abs = plan.scan_root.join(relative_path);
            let Ok(content) = std::fs::read_to_string(&abs) else {
                continue;
            };
            for (name, start_line, body) in
                extract_named_function_bodies(&content, &relaxed_names, RELAXED_BODY_MAX_LINES)
            {
                let dedup_key = format!("{name}:{}", body.len());
                if !seen_bodies.insert(dedup_key) {
                    continue;
                }
                bodies.push((relative_path.clone(), name, start_line, body));
                relaxed_added += 1;
                if relaxed_added >= relaxed_quota || bodies.len() >= 8 {
                    break 'relaxed_files;
                }
            }
        }
    }
    if bodies.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push("## Sanitizer Function Bodies (audit for bypass)".to_string());
    lines.push(
        "Functions in linked-story files whose names match the catalog's \
         sanitizer signals for the focused CWE(s). Bugs hide INSIDE these — \
         `check_locality = false` skip-branches, pre-concatenation-only \
         validation, prefix whitelists vs canonical paths, etc. Read each \
         body and check whether every flow to a sink goes through the \
         sanitizer AND whether the sanitizer is applied to the FINAL value \
         used at the sink. If a sanitizer's body contains a skip-branch \
         that bypasses the check on a 'trusted' input, the flow that hits \
         the skip-branch is exploitable — promote to finding."
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

/// Normalise a catalog sanitizer pattern string into the bare
/// function name we'd see in a definition line. The catalog often
/// stores patterns with trailing `(` (e.g. `quote_literal(`) or
/// argument hints (e.g. `superuser()`). Strip those down to the
/// identifier so the body-extractor can match by exact name.
fn sanitize_function_name_for_body_lookup(
    pattern: &str,
    out: &mut std::collections::BTreeSet<String>,
) {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return;
    }
    // Strip parens and arguments: `superuser()` -> `superuser`.
    let stripped = trimmed.split('(').next().unwrap_or(trimmed);
    // Drop spaces / non-identifier suffixes.
    let identifier: String = stripped
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if !identifier.is_empty() && identifier.len() >= 4 {
        out.insert(identifier);
    }
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

/// Variant of `extract_sanitizer_function_bodies` that accepts an
/// arbitrary allow-list of function names (NOT restricted to
/// sanitizer-shaped). Used for the enclosing-function pass: linked
/// stories' source/sink lines walk UP to their enclosing fn, and
/// that fn's body lands in the agent prompt even if the name is a
/// neutral allocator / setup helper like `pgp_mpi_alloc` or
/// `prepare_room`. Bodies cap at `max_lines` rows so we don't bloat
/// the prompt on a long function.
fn extract_named_function_bodies(
    content: &str,
    accept: &std::collections::BTreeSet<String>,
    max_lines: usize,
) -> Vec<(String, u32, String)> {
    let lines: Vec<&str> = content.lines().collect();
    let mut out: Vec<(String, u32, String)> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim_start();
        if let Some(name) = function_name_from_def_line(trimmed) {
            if accept.contains(&name) {
                let mut brace_line: Option<usize> = None;
                for j in i..lines.len().min(i + 8) {
                    if lines[j].contains('{') {
                        brace_line = Some(j);
                        break;
                    }
                    if lines[j].trim_end().ends_with(';') {
                        break;
                    }
                }
                if let Some(brace_start) = brace_line {
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
                    let span_end = end_line.min(i + max_lines);
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

/// Walk backward from `target_line` (1-indexed) until we find a
/// function-definition line (per `function_name_from_def_line`)
/// whose `{` lies between the def line and target_line. Used by
/// Thread B2 to find the enclosing function of a linked-story
/// source/sink line so its body can be inlined for upstream-bound-
/// check audit.
pub(in crate::modules::taint_iris_next) fn enclosing_function_name(
    content: &str,
    target_line: u32,
) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    if (target_line as usize) == 0 || (target_line as usize) > lines.len() {
        return None;
    }
    let target_idx = (target_line as usize) - 1;
    let mut i = target_idx;
    loop {
        let trimmed = lines[i].trim_start();
        if let Some(name) = function_name_from_def_line(trimmed) {
            // Confirm there's a `{` within ~8 lines AFTER the
            // def header (definitions, not prototypes), AND the
            // body's closing `}` lies at or after target_idx.
            // Without this we'd match prototypes / forward-decls,
            // or attribute a target to a sibling function whose
            // body sits entirely before the target line.
            let mut brace_line: Option<usize> = None;
            for j in i..lines.len().min(i + 8) {
                if lines[j].contains('{') {
                    brace_line = Some(j);
                    break;
                }
                if lines[j].trim_end().ends_with(';') {
                    break; // prototype
                }
            }
            if let Some(brace_start) = brace_line {
                let mut depth: i32 = 0;
                let mut started = false;
                let mut end_idx = brace_start;
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
                        end_idx = j;
                        break;
                    }
                }
                if target_idx <= end_idx {
                    return Some(name);
                }
            }
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
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

    #[test]
    fn enclosing_function_walks_up_to_definition() {
        // Source / sink line in linked story points INSIDE a function;
        // we need to walk up to the definition header to get the
        // function's name.
        let src = r#"
static int
pgp_mpi_alloc(int bits, PGP_MPI **mpi)
{
    int len = (bits + 7) / 8;
    if (bits < 0 || bits > 0xFFFF)
    {
        return PXE_PGP_CORRUPT_DATA;
    }
    n = palloc(sizeof(*n) + len);  /* sink line — line ~9 of body */
    return 0;
}
"#;
        // Target the palloc line.
        let palloc_line = src
            .lines()
            .enumerate()
            .find(|(_, l)| l.contains("palloc(sizeof"))
            .map(|(i, _)| (i + 1) as u32)
            .unwrap();
        let name = enclosing_function_name(src, palloc_line);
        assert_eq!(name.as_deref(), Some("pgp_mpi_alloc"));
    }

    #[test]
    fn enclosing_function_handles_target_at_def_line() {
        // The walk should also succeed when the target line IS the
        // function's def line — useful for source-line candidates
        // that land at the macro PG_FUNCTION_INFO_V1 / function
        // header itself.
        let src = "static int\nfoo(int x)\n{\n    return x;\n}\n";
        // Line 2 = the def line.
        let name = enclosing_function_name(src, 2);
        assert_eq!(name.as_deref(), Some("foo"));
    }

    #[test]
    fn extract_named_function_bodies_includes_non_sanitizer_helper() {
        // `prepare_room` is named like an allocator helper, NOT a
        // sanitizer (it doesn't start with `check_`, `safe_`, etc.).
        // The B2 relaxed-pass extractor must accept it when its name
        // is in the allow-set so the agent can audit the upstream
        // bound check inline.
        let src = r#"
static void
prepare_room(MBuf *dst, int len)
{
    if (dst->buf_end - dst->data_end < len)
    {
        realloc_mbuf(dst, len);
    }
}
"#;
        let mut accept = std::collections::BTreeSet::new();
        accept.insert("prepare_room".to_string());
        let bodies = extract_named_function_bodies(src, &accept, 30);
        let names: Vec<&str> = bodies.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(names, vec!["prepare_room"]);
        let body = &bodies[0].2;
        assert!(
            body.contains("realloc_mbuf"),
            "body should include the function body content: {body}"
        );
    }
}

#[cfg(test)]
mod mandatory_audit_section_tests {
    use super::*;

    fn minimal_plan() -> TaintIrisNextPlan {
        TaintIrisNextPlan {
            target: std::path::PathBuf::from("/tmp/x"),
            scan_root: std::path::PathBuf::from("/tmp/x"),
            repo_root: std::path::PathBuf::from("/tmp/x"),
            mode: TaintIrisNextMode::Hunt,
            caps: TaintIrisNextCaps {
                max_catalog_entries: 12,
                max_candidates_per_cwe: 8,
                max_evidence_per_cwe: 8,
                max_files_per_query: 200,
                max_specs_per_cwe: 8,
                max_agent_findings: 20,
                codeql_analyze_timeout_ms: 600_000,
                min_evidence_level: "linked".to_string(),
            },
            languages: vec!["c".to_string()],
            context_status: TaintIrisNextArtifactStatus {
                ok: false,
                path: None,
                reason: "test".to_string(),
            },
            threat_model_status: TaintIrisNextArtifactStatus {
                ok: false,
                path: None,
                reason: "test".to_string(),
            },
            repo_context: None,
            threat_model: None,
            catalog: Vec::new(),
            structural_queries: Vec::new(),
            prompt_catalog: String::new(),
            backend: TaintIrisNextBackendChoice {
                requested: "structural".to_string(),
                selected: "structural".to_string(),
                codeql_db_path: None,
                corroborate_with_codeql: None,
                structural_tool: "rg".to_string(),
                warnings: Vec::new(),
            },
            max_budget_usd: None,
            cwe_focus: Vec::new(),
            discovered_signals: DiscoveredSignals::default(),
        }
    }

    fn empty_evidence() -> TaintIrisNextEvidenceResult {
        TaintIrisNextEvidenceResult {
            backend: "structural".to_string(),
            tool: "rg".to_string(),
            evidence: Vec::new(),
            candidates: Vec::new(),
            linked_stories: Vec::new(),
            labeled_specs: Vec::new(),
            query_count: 0,
            candidate_counts: Default::default(),
            labeled_spec_counts: Default::default(),
            linked_story_count: 0,
            backend_path_count: 0,
            structural_engine: "rg".to_string(),
            triage_summary: serde_json::json!({}),
            outcome: "test".to_string(),
            warnings: Vec::new(),
            artifacts: serde_json::json!({}),
        }
    }

    #[test]
    fn prompt_demands_call_site_walk_and_entry_point_resolution() {
        let prompt = build_taint_iris_next_agent_prompt(&minimal_plan(), &empty_evidence());
        // Thread D: a verdict on a candidate must be backed by a
        // call-site → entry-point audit. These phrases are the
        // load-bearing instructions; the test locks them in so a
        // future refactor doesn't silently drop them.
        assert!(
            prompt.contains("Mandatory Call-Site + Entry-Point Audit"),
            "prompt must include the mandatory audit section"
        );
        assert!(
            prompt.contains("joern.callers_of"),
            "audit section must instruct the agent to use joern.callers_of"
        );
        assert!(
            prompt.contains("PG_FUNCTION_INFO_V1") || prompt.contains("PG_FUNCTION_ARGS"),
            "audit section must enumerate known entry-point shapes"
        );
        assert!(
            prompt.contains("caller-contract"),
            "audit section must explicitly cover the 'caller-contract' rejection pitfall"
        );
        assert!(
            prompt.contains("VULN-") && prompt.contains("FIXME-"),
            "audit section must teach the agent to treat VULN-/FIXME- comments as breadcrumbs"
        );
        assert!(
            prompt.contains("Cite the audit in your verdict"),
            "audit section must demand the call-chain be cited in every verdict"
        );
    }

    #[test]
    fn audit_section_lands_after_false_positives_and_before_contract() {
        let prompt = build_taint_iris_next_agent_prompt(&minimal_plan(), &empty_evidence());
        let fp_idx = prompt
            .find("## False-Positive Patterns")
            .expect("false-positive section must exist");
        let audit_idx = prompt
            .find("## Mandatory Call-Site + Entry-Point Audit")
            .expect("audit section must exist");
        let contract_idx = prompt
            .find("## Contract")
            .expect("contract section must exist");
        assert!(
            fp_idx < audit_idx,
            "audit must come after false-positive patterns so the agent has them in mind"
        );
        assert!(
            audit_idx < contract_idx,
            "audit must come before the contract so the contract sees it as a prerequisite"
        );
    }

    #[test]
    fn prompt_names_privilege_boundary_patterns() {
        // E3: the prompt must teach the agent to name a
        // privilege-boundary-crossing application pattern when
        // promoting any injection finding. Without this, the agent
        // surfaces the dblink cursor-name injection as a generic
        // CWE-89 and misses the SECURITY DEFINER privesc framing
        // that turns it from "by-design caller-trusted" into a CVE.
        let prompt = build_taint_iris_next_agent_prompt(&minimal_plan(), &empty_evidence());
        assert!(
            prompt.contains("Realistic Exploit Patterns"),
            "prompt must include the realistic-exploit framing section",
        );
        assert!(
            prompt.contains("SECURITY DEFINER wrapper"),
            "prompt must name the SECURITY DEFINER wrapper privesc pattern",
        );
        assert!(
            prompt.contains("GRANT EXECUTE asymmetry"),
            "prompt must name the GRANT EXECUTE asymmetry pattern",
        );
        assert!(
            prompt.contains("Foreign user mapping"),
            "prompt must name the postgres_fdw / dblink user-mapping pattern",
        );
        // Non-postgres patterns are listed for generalization.
        assert!(
            prompt.contains("Java reflection gadgets")
                && prompt.contains("__subclasses__")
                && prompt.contains("child_process.spawnSync"),
            "prompt must name common framework gadget patterns",
        );
        // The "must name a pattern" requirement is explicit.
        assert!(
            prompt.contains("customCweRationale") || prompt.contains("Required"),
            "prompt must require the named pattern in the rationale field",
        );
    }

    #[test]
    fn realistic_exploit_section_lands_between_audit_and_contract() {
        let prompt = build_taint_iris_next_agent_prompt(&minimal_plan(), &empty_evidence());
        let audit_idx = prompt
            .find("## Mandatory Call-Site + Entry-Point Audit")
            .expect("audit section must exist");
        let realistic_idx = prompt
            .find("## Realistic Exploit Patterns")
            .expect("realistic-exploit section must exist");
        let contract_idx = prompt
            .find("## Contract")
            .expect("contract section must exist");
        assert!(
            audit_idx < realistic_idx,
            "realistic-exploit framing must come after the call-site audit",
        );
        assert!(
            realistic_idx < contract_idx,
            "realistic-exploit framing must come before the contract",
        );
    }
}
