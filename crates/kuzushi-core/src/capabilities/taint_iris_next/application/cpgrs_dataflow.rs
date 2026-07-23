use super::*;
use std::sync::OnceLock;

/// Source-to-sink path discovered by the in-process cpg-rs engine. Same
/// contract the retired Joern batch pass spoke: the first step is the source, the
/// last is the sink, lines are 1-based file lines.
#[derive(Debug, Clone)]
pub(crate) struct CpgrsFlow {
    pub(crate) cwe: String,
    pub(crate) taint_class: String,
    pub(crate) file_path: String,
    pub(crate) source_line: u32,
    pub(crate) sink_line: u32,
    pub(crate) source_code: String,
    pub(crate) sink_code: String,
    pub(crate) steps: Vec<CpgrsStep>,
    /// Advisory triage evidence from the engine (`guarded@<line>`,
    /// `authz-dominated@<line>`); carried into the story rationale.
    pub(crate) guard: Option<String>,
    pub(crate) authz: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct CpgrsStep {
    /// KNOWN APPROXIMATION: the engine's witness steps carry no per-step
    /// file yet, so every step reports the sink's file. Cross-file hops on
    /// the trace therefore display the sink file until cpg-rs grows
    /// `Step.file` (upstream follow-up).
    pub(crate) file: String,
    pub(crate) line: u32,
    pub(crate) code: String,
}

/// Run the in-process cpg-rs taint query for every ranked catalog entry.
/// Graphs build implicitly (seconds) when missing or stale — no operator
/// prebuild step. Returns `Ok(None)` when no plan language has a cpg-rs
/// frontend, so callers fall back to the heuristic linker.
pub(crate) fn run_cpgrs_flows(plan: &TaintIrisNextPlan) -> Result<Option<Vec<CpgrsFlow>>> {
    let languages = cpgrs_plan_languages(&plan.languages);
    if languages.is_empty() {
        return Ok(None);
    }
    let mut flows = Vec::new();
    for lang in languages {
        flows.extend(run_cpgrs_language_flows(plan, lang)?);
    }
    Ok(Some(flows))
}

/// Plan languages that have a cpg-rs frontend, deduped, detection order kept.
pub(crate) fn cpgrs_plan_languages(languages: &[String]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for language in languages {
        if let Some(lang) = kuzushi_cpg::canonical_language(language) {
            if !out.contains(&lang) {
                out.push(lang);
            }
        }
    }
    out
}

fn run_cpgrs_language_flows(plan: &TaintIrisNextPlan, lang: &str) -> Result<Vec<CpgrsFlow>> {
    let scope = cpgrs_build_scope(plan)?;
    let limits = kuzushi_cpg::BuildLimits {
        max_source_files: plan.caps.max_cpg_source_files,
    };
    let (project, _report) = kuzushi_cpg::ensure_project_in(&scope, lang, &limits)
        .map_err(|error| anyhow::anyhow!("cpg-rs {lang} graph build failed: {error}"))?;
    let scan_root = plan.scan_root.display().to_string();
    let mut flows = Vec::new();
    for entry in &plan.catalog {
        flows.extend(run_cpgrs_catalog_entry(&project, entry, &scan_root));
    }
    Ok(flows)
}

/// Artifacts always land under the workspace root's `.kuzushi`, even for
/// `targetSubdir` hunts — a scan must never create state inside the scanned
/// subtree. Plans whose scan root is unrelated to the repo root (test
/// fixtures, ad-hoc paths) scope on the scan root itself, preserving the
/// old placement for exactly the cases that have no workspace root.
fn cpgrs_build_scope(plan: &TaintIrisNextPlan) -> Result<kuzushi_cpg::BuildScope> {
    if plan.scan_root == plan.repo_root {
        return Ok(kuzushi_cpg::BuildScope::whole(&plan.repo_root));
    }
    match plan.scan_root.strip_prefix(&plan.repo_root) {
        Ok(subdir) => kuzushi_cpg::BuildScope::subtree(&plan.repo_root, subdir)
            .map_err(|error| anyhow::anyhow!("cpg-rs build scope: {error}")),
        Err(_) => Ok(kuzushi_cpg::BuildScope::whole(&plan.scan_root)),
    }
}

fn run_cpgrs_catalog_entry(
    project: &kuzushi_cpg::Project,
    entry: &TaintIrisNextRankedCatalogEntry,
    scan_root: &str,
) -> Vec<CpgrsFlow> {
    if entry.source_signals.is_empty() || entry.sink_signals.is_empty() {
        return Vec::new();
    }
    let signals = kuzushi_cpg::SignalSpec {
        sources: &entry.source_signals,
        sinks: &entry.sink_signals,
        sanitizers: &entry.sanitizer_signals,
    };
    let harvested = kuzushi_cpg::harvest_spec(project, &signals);
    let (findings, _stats) = kuzushi_cpg::run_taint_query(project, &harvested);
    findings
        .iter()
        .filter_map(|finding| cpgrs_finding_to_flow(finding, entry, scan_root))
        .collect()
}

fn cpgrs_finding_to_flow(
    finding: &kuzushi_cpg::Finding,
    entry: &TaintIrisNextRankedCatalogEntry,
    scan_root: &str,
) -> Option<CpgrsFlow> {
    let file_path = relative_to_scan_root(finding.sink_file.as_deref()?, scan_root);
    let sink_line = finding.sink_line.unwrap_or(0);
    let source_line = finding
        .path
        .first()
        .and_then(|step| step.line)
        .unwrap_or(sink_line);
    let source_code = finding
        .path
        .first()
        .map(|step| step.code.clone())
        .unwrap_or_else(|| finding.origin.clone());
    let sink_code = finding
        .path
        .last()
        .map(|step| step.code.clone())
        .unwrap_or_else(|| finding.sink.clone());
    Some(CpgrsFlow {
        cwe: entry.cwe.clone(),
        taint_class: entry.taint_class.clone(),
        steps: cpgrs_witness_steps(finding, &file_path),
        file_path,
        source_line,
        sink_line,
        source_code,
        sink_code,
        guard: finding.guard.clone(),
        authz: finding.authz.clone(),
    })
}

fn cpgrs_witness_steps(finding: &kuzushi_cpg::Finding, file_path: &str) -> Vec<CpgrsStep> {
    finding
        .path
        .iter()
        .map(|step| CpgrsStep {
            file: file_path.to_string(),
            line: step.line.unwrap_or(0),
            code: step.code.clone(),
        })
        .collect()
}

fn relative_to_scan_root(path: &str, scan_root: &str) -> String {
    path.strip_prefix(scan_root)
        .map(|rest| rest.trim_start_matches('/'))
        .filter(|rest| !rest.is_empty())
        .unwrap_or(path)
        .to_string()
}

/// Adapt cpg-rs flows into `TaintIrisNextLinkedStory` rows. Each flow has a
/// real interprocedural witness path, so `evidenceLevel = "path"` — the same
/// deterministic tier CPG-witnessed paths earn — with `cpgrs-` id provenance
/// and the engine's guard/authz annotations appended to the rationale.
pub(crate) fn cpgrs_flows_to_linked_stories(flows: &[CpgrsFlow]) -> Vec<TaintIrisNextLinkedStory> {
    flows
        .iter()
        .filter(|flow| {
            !is_taint_iris_next_non_production_path(&flow.file_path)
                && !flow
                    .steps
                    .iter()
                    .any(|step| is_taint_iris_next_non_production_path(&step.file))
        })
        .map(cpgrs_flow_to_linked_story)
        .collect()
}

fn cpgrs_flow_to_linked_story(flow: &CpgrsFlow) -> TaintIrisNextLinkedStory {
    let source_id = format!("{}:source:{}:{}", flow.cwe, flow.file_path, flow.source_line);
    let sink_id = format!("{}:sink:{}:{}", flow.cwe, flow.file_path, flow.sink_line);
    TaintIrisNextLinkedStory {
        id: format!(
            "cpgrs-{}:{}:{}-{}:{}:{}",
            flow.cwe, flow.file_path, flow.source_line, flow.cwe, flow.file_path, flow.sink_line
        ),
        cwe: flow.cwe.clone(),
        taint_class: flow.taint_class.clone(),
        track: "taint".to_string(),
        evidence_level: "path".to_string(),
        file_path: flow.file_path.clone(),
        language: language_for_path(Path::new(&flow.file_path)),
        source_candidate_id: source_id,
        sink_candidate_id: sink_id,
        source_line: flow.source_line,
        sink_line: flow.sink_line,
        shared_tokens: Vec::new(),
        rationale: cpgrs_flow_rationale(flow),
        callees: extract_callees_from_cpgrs_steps(&flow.steps),
    }
}

fn cpgrs_flow_rationale(flow: &CpgrsFlow) -> String {
    let trace = flow
        .steps
        .iter()
        .map(|step| format!("{}:{} {}", step.file, step.line, truncate(&step.code, 120)))
        .collect::<Vec<_>>()
        .join(" -> ");
    let mut rationale = format!("cpg-rs taint path: {trace}");
    for annotation in [&flow.guard, &flow.authz].into_iter().flatten() {
        rationale.push_str(&format!(" [{annotation}]"));
    }
    rationale
}

/// Identifier-shaped call tokens along the witness path, for Thread B1's
/// body inlining (upstream bound-check helpers get audited inline).
fn extract_callees_from_cpgrs_steps(steps: &[CpgrsStep]) -> Vec<String> {
    use std::collections::BTreeSet;
    static CALLEE_RE: OnceLock<regex::Regex> = OnceLock::new();
    let re =
        CALLEE_RE.get_or_init(|| regex::Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\s*\(").unwrap());
    let skip: &[&str] = &[
        "if", "while", "for", "switch", "sizeof", "return", "case", "elog", "ereport", "Assert",
        "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat", "sprintf",
        "snprintf", "palloc", "palloc0", "pfree", "repalloc",
    ];
    let mut out: BTreeSet<String> = BTreeSet::new();
    for step in steps {
        for cap in re.captures_iter(&step.code) {
            if let Some(name) = cap.get(1).map(|m| m.as_str()) {
                if !skip.contains(&name) {
                    out.insert(name.to_string());
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Mint synthetic candidate rows for each flow endpoint so the agent prompt
/// sees a populated `candidates` list and story IDs resolve.
pub(crate) fn cpgrs_flows_to_candidates(flows: &[CpgrsFlow]) -> Vec<TaintIrisNextCandidate> {
    let mut out = Vec::new();
    for flow in flows {
        if is_taint_iris_next_non_production_path(&flow.file_path) {
            continue;
        }
        out.push(cpgrs_endpoint_candidate(
            flow,
            flow.source_line,
            &flow.source_code,
            "source",
        ));
        out.push(cpgrs_endpoint_candidate(
            flow,
            flow.sink_line,
            &flow.sink_code,
            "sink",
        ));
    }
    out
}

fn cpgrs_endpoint_candidate(
    flow: &CpgrsFlow,
    line: u32,
    code: &str,
    role: &str,
) -> TaintIrisNextCandidate {
    TaintIrisNextCandidate {
        id: format!("{}:{}:{}:{}", flow.cwe, role, flow.file_path, line),
        cwe: flow.cwe.clone(),
        taint_class: flow.taint_class.clone(),
        track: "taint".to_string(),
        role: role.to_string(),
        kind: taint_iris_next_kind_for_role(role).to_string(),
        pattern: "cpg-rs-flow".to_string(),
        file_path: flow.file_path.clone(),
        line,
        snippet: truncate(code, 240),
        language: language_for_path(Path::new(&flow.file_path)),
        confidence: "high".to_string(),
        catalog_signal: format!("{role}: cpg-rs-flow"),
        source: "cpg-rs".to_string(),
    }
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max_chars).collect();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn entry(cwe: &str, sources: &[&str], sinks: &[&str]) -> TaintIrisNextRankedCatalogEntry {
        TaintIrisNextRankedCatalogEntry {
            cwe: cwe.to_string(),
            name: format!("{cwe} (test)"),
            taint_class: "sql-injection".to_string(),
            score: 50,
            languages: vec!["any".to_string()],
            source_signals: sources.iter().map(|s| s.to_string()).collect(),
            sink_signals: sinks.iter().map(|s| s.to_string()).collect(),
            sanitizer_signals: vec![],
            structural_queries: vec![],
            regex_markers: vec![],
            reasons: vec![],
        }
    }

    fn cpgrs_test_plan(scan_root: PathBuf, languages: Vec<String>) -> TaintIrisNextPlan {
        TaintIrisNextPlan {
            target: scan_root.clone(),
            scan_root,
            repo_root: PathBuf::from("."),
            source_paths: std::sync::Arc::from([]),
            mode: TaintIrisNextMode::Hunt,
            caps: cpgrs_test_caps(),
            languages,
            context_status: TaintIrisNextArtifactStatus {
                ok: true,
                path: None,
                reason: "test".to_string(),
            },
            threat_model_status: TaintIrisNextArtifactStatus {
                ok: true,
                path: None,
                reason: "test".to_string(),
            },
            repo_context: None,
            threat_model: None,
            catalog: vec![entry("CWE-89", &["req.query"], &[".query("])],
            structural_queries: Vec::new(),
            prompt_catalog: String::new(),
            backend: TaintIrisNextBackendChoice {
                requested: "cpg-rs".to_string(),
                selected: "cpg-rs".to_string(),
                codeql_db_path: None,
                corroborate_with_codeql: None,
                structural_tool: "test".to_string(),
                warnings: Vec::new(),
            },
            max_budget_usd: None,
            allow_deterministic_fallback: false,
            system_prompt: taint_iris_next_system_prompt(),
            cwe_focus: Vec::new(),
            discovered_signals: DiscoveredSignals::default(),
        }
    }

    fn cpgrs_test_caps() -> TaintIrisNextCaps {
        TaintIrisNextCaps {
            max_catalog_entries: 1,
            max_candidates_per_cwe: 10,
            max_evidence_per_cwe: 10,
            max_files_per_query: 10,
            max_specs_per_cwe: 10,
            max_agent_findings: 10,
            max_cpg_source_files: kuzushi_cpg::DEFAULT_MAX_SOURCE_FILES,
            codeql_analyze_timeout_ms: 1000,
            min_evidence_level: "candidate".to_string(),
        }
    }

    #[test]
    fn unsupported_languages_return_none_for_heuristic_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let plan = cpgrs_test_plan(temp.path().to_path_buf(), vec!["php".to_string()]);
        assert!(run_cpgrs_flows(&plan).unwrap().is_none());
    }

    #[test]
    fn finds_flows_with_implicit_build_and_no_prebuilt_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("users.ts"),
            "function list(req, res) {\n  const id = req.query.id;\n  db.query(\"SELECT \" + id);\n}\n",
        )
        .unwrap();
        let plan = cpgrs_test_plan(temp.path().to_path_buf(), vec!["typescript".to_string()]);

        let flows = run_cpgrs_flows(&plan).unwrap().expect("supported language");

        assert!(!flows.is_empty(), "expected a req.query -> db.query flow");
        let flow = &flows[0];
        assert_eq!(flow.cwe, "CWE-89");
        assert_eq!(flow.file_path, "users.ts", "paths must be scan-root relative");
        assert!(!flow.steps.is_empty());
        // The implicit build must have persisted the artifact for reuse.
        assert!(kuzushi_cpg::has_artifacts(temp.path()));
    }

    #[test]
    fn subdir_hunts_keep_artifacts_under_the_repo_root() {
        let temp = tempfile::tempdir().unwrap();
        let subtree = temp.path().join("svc");
        std::fs::create_dir_all(&subtree).unwrap();
        std::fs::write(
            subtree.join("users.ts"),
            "function list(req, res) {\n  const id = req.query.id;\n  db.query(\"SELECT \" + id);\n}\n",
        )
        .unwrap();
        let mut plan = cpgrs_test_plan(subtree.clone(), vec!["typescript".to_string()]);
        plan.repo_root = temp.path().to_path_buf();

        let flows = run_cpgrs_flows(&plan).unwrap().expect("supported language");

        assert!(!flows.is_empty(), "expected a req.query -> db.query flow");
        assert!(
            !subtree.join(".kuzushi").exists(),
            "a targetSubdir hunt must never write state into the scanned subtree"
        );
        let scoped = temp.path().join(".kuzushi/cpg-rs/scoped/svc");
        assert!(scoped.is_dir(), "scoped artifact dir missing: {}", scoped.display());
    }

    #[test]
    fn oversized_corpus_refusal_names_the_overrides() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("a.ts"), "const a = 1;\n").unwrap();
        std::fs::write(temp.path().join("b.ts"), "const b = 2;\n").unwrap();
        let mut plan = cpgrs_test_plan(temp.path().to_path_buf(), vec!["typescript".to_string()]);
        plan.repo_root = temp.path().to_path_buf();
        plan.caps.max_cpg_source_files = 1;

        let error = run_cpgrs_flows(&plan).unwrap_err().to_string();
        assert!(error.contains("build cap"), "{error}");
        assert!(error.contains("targetSubdir"), "{error}");
    }

    #[test]
    fn flows_become_path_level_stories_with_cpgrs_provenance() {
        let flow = CpgrsFlow {
            cwe: "CWE-89".to_string(),
            taint_class: "sql-injection".to_string(),
            file_path: "src/users.ts".to_string(),
            source_line: 2,
            sink_line: 3,
            source_code: "req.query.id".to_string(),
            sink_code: "db.query(req.query.id)".to_string(),
            steps: vec![
                CpgrsStep {
                    file: "src/users.ts".to_string(),
                    line: 2,
                    code: "req.query.id".to_string(),
                },
                CpgrsStep {
                    file: "src/users.ts".to_string(),
                    line: 3,
                    code: "db.query(req.query.id)".to_string(),
                },
            ],
            guard: None,
            authz: Some("authz-partial@1".to_string()),
        };
        let stories = cpgrs_flows_to_linked_stories(&[flow.clone()]);
        assert_eq!(stories.len(), 1);
        assert_eq!(stories[0].evidence_level, "path");
        assert!(stories[0].id.starts_with("cpgrs-"));
        assert!(stories[0].rationale.contains("cpg-rs taint path"));
        assert!(stories[0].rationale.contains("authz-partial@1"));

        let candidates = cpgrs_flows_to_candidates(&[flow]);
        assert_eq!(candidates.len(), 2);
        assert!(candidates.iter().all(|c| c.source == "cpg-rs"));
    }

    #[test]
    fn non_production_paths_are_filtered() {
        let flow = CpgrsFlow {
            cwe: "CWE-89".to_string(),
            taint_class: "sql-injection".to_string(),
            file_path: "tests/fixtures/users.ts".to_string(),
            source_line: 1,
            sink_line: 2,
            source_code: "req.query.id".to_string(),
            sink_code: "db.query(x)".to_string(),
            steps: Vec::new(),
            guard: None,
            authz: None,
        };
        assert!(cpgrs_flows_to_linked_stories(&[flow.clone()]).is_empty());
        assert!(cpgrs_flows_to_candidates(&[flow]).is_empty());
    }

    #[test]
    fn plan_language_mapping_filters_and_dedupes() {
        let languages = vec![
            "typescript".to_string(),
            "ts".to_string(),
            "php".to_string(),
            "go".to_string(),
        ];
        assert_eq!(cpgrs_plan_languages(&languages), vec!["typescript", "go"]);
    }
}
