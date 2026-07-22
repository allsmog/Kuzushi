//! Catalog-signal → TaintSpec translation.
//!
//! Kuzushi's catalog speaks literal substrings matched against call source
//! text (`req.query`, `.execute(`) — the contract the Joern backend ran as
//! `cpg.call.code(regex)`. cpg-rs's [`TaintSpec`] is name-keyed, so the
//! adapter harvests the NAMES of graph calls whose code matches a signal in
//! one linear scan, then lets the engine's summaries-first propagation do
//! the interprocedural work.

use cpg_analysis::{find_flows, Finding, TaintSpec};
use cpg_core::Query;
use cpg_incremental::Project;
use std::collections::BTreeSet;

/// Per-name harvest cap, mirroring the Joern flow script's 200-source ×
/// 200-sink bound so one catastrophically broad signal cannot explode the
/// propagation set.
pub const MAX_HARVESTED_NAMES: usize = 200;
/// Flows kept per query (per CWE), mirroring the Joern script's 25-flow cap.
pub const MAX_FLOWS_PER_QUERY: usize = 25;

/// One CWE's literal signals, straight from the ranked catalog entry.
#[derive(Debug, Clone, Copy)]
pub struct SignalSpec<'a> {
    pub sources: &'a [String],
    pub sinks: &'a [String],
    pub sanitizers: &'a [String],
}

/// Names harvested from the graph for one [`SignalSpec`], plus the match
/// counts that make a "0 flows" outcome diagnosable (source matched nothing
/// vs no source→sink path — the silent-empty failure the Joern integration
/// had to grow an envelope for).
#[derive(Debug, Clone, Default)]
pub struct HarvestedSpec {
    pub source_names: Vec<String>,
    pub sink_names: Vec<String>,
    pub sanitizer_names: Vec<String>,
    /// Framework-global roots (`req`, `request`) from member-read signals.
    pub source_idents: Vec<String>,
    /// Methods whose parameters are attacker-controlled (name matched a
    /// source signal) — the RPC/handler entry-point model.
    pub entry_methods: Vec<String>,
    pub source_call_matches: usize,
    pub sink_call_matches: usize,
}

/// Outcome counts for the query envelope.
#[derive(Debug, Clone)]
pub struct CpgFlowQueryStats {
    pub source_names: usize,
    pub sink_names: usize,
    pub source_call_matches: usize,
    pub sink_call_matches: usize,
    pub flow_count: usize,
}

/// One linear scan over the graph's calls and methods, harvesting the names
/// behind every signal match.
pub fn harvest_spec(project: &Project, signals: &SignalSpec) -> HarvestedSpec {
    let mut harvest = CallHarvest::default();
    scan_calls(project, signals, &mut harvest);
    let entry_methods = harvest_entry_methods(project, signals.sources);
    HarvestedSpec {
        source_names: capped(harvest.source_names),
        sink_names: capped(harvest.sink_names),
        sanitizer_names: capped(harvest.sanitizer_names),
        source_idents: source_idents_from_signals(signals.sources),
        entry_methods,
        source_call_matches: harvest.source_call_matches,
        sink_call_matches: harvest.sink_call_matches,
    }
}

#[derive(Default)]
struct CallHarvest {
    source_names: BTreeSet<String>,
    sink_names: BTreeSet<String>,
    sanitizer_names: BTreeSet<String>,
    source_call_matches: usize,
    sink_call_matches: usize,
}

fn scan_calls(project: &Project, signals: &SignalSpec, harvest: &mut CallHarvest) {
    let cpg = &project.cpg;
    for call in cpg.calls() {
        let (Some(code), Some(name)) = (cpg.code_of(call), cpg.name_of(call)) else {
            continue;
        };
        if harvest_name(code, name, signals.sources, &mut harvest.source_names) {
            harvest.source_call_matches += 1;
        }
        if harvest_name(code, name, signals.sinks, &mut harvest.sink_names) {
            harvest.sink_call_matches += 1;
        }
        harvest_name(code, name, signals.sanitizers, &mut harvest.sanitizer_names);
    }
}

/// Record `name` when the call's code matches a signal AND the name itself
/// relates to the matching signal. The second gate keeps enclosing statement
/// calls (the `=` assignment whose code merely CONTAINS `req.query`) from
/// turning every assignment in the program into a source — the inner
/// member-read call carries the relatable name.
fn harvest_name(code: &str, name: &str, signals: &[String], into: &mut BTreeSet<String>) -> bool {
    let matched = signals
        .iter()
        .any(|signal| code.contains(signal.as_str()) && name_relates_to_signal(name, signal));
    if matched {
        into.insert(name.to_string());
    }
    matched
}

/// `.execute(` relates to `execute`; `req.query` relates to `query`;
/// `PG_GETARG` relates to `PG_GETARG_TEXT_PP`. `=` relates to nothing.
fn name_relates_to_signal(name: &str, signal: &str) -> bool {
    let core = signal.trim_matches(|c: char| !(c.is_alphanumeric() || c == '_' || c == '.'));
    if core.is_empty() || name.is_empty() {
        return false;
    }
    core == name || core.ends_with(&format!(".{name}")) || name.contains(core)
}

/// Member-read signals without a call shape (`req.query`, `request.args`)
/// also seed the engine's framework-global model with their root identifier.
fn source_idents_from_signals(sources: &[String]) -> Vec<String> {
    let idents: BTreeSet<String> = sources
        .iter()
        .filter(|signal| !signal.contains('(') && signal.contains('.'))
        .filter_map(|signal| signal.split('.').next())
        .filter(|root| !root.is_empty() && root.chars().all(|c| c.is_alphanumeric() || c == '_'))
        .map(str::to_string)
        .collect();
    idents.into_iter().collect()
}

fn harvest_entry_methods(project: &Project, sources: &[String]) -> Vec<String> {
    let cpg = &project.cpg;
    let names: BTreeSet<String> = cpg
        .methods()
        .into_iter()
        .filter_map(|method| cpg.name_of(method))
        .filter(|name| {
            sources
                .iter()
                .any(|signal| name_relates_to_signal(name, signal) && name.contains(signal.trim()))
        })
        .map(str::to_string)
        .collect();
    capped(names)
}

fn capped(names: BTreeSet<String>) -> Vec<String> {
    names.into_iter().take(MAX_HARVESTED_NAMES).collect()
}

/// Harvest a spec from REGEX source/sink patterns (the agent-facing
/// `taint_paths` contract). A pattern that fails to compile is treated as a
/// literal substring. A call's name is harvested when the pattern matches
/// the name itself, or matches the call's code while the name is
/// identifier-like (keeping enclosing `=` statement calls out, same as the
/// literal harvest).
pub fn harvest_regex_spec(
    project: &Project,
    source_pattern: &str,
    sink_pattern: &str,
) -> HarvestedSpec {
    let source = PatternMatcher::new(source_pattern);
    let sink = PatternMatcher::new(sink_pattern);
    let cpg = &project.cpg;
    let mut harvest = CallHarvest::default();
    for call in cpg.calls() {
        let (Some(code), Some(name)) = (cpg.code_of(call), cpg.name_of(call)) else {
            continue;
        };
        if harvest_regex_name(&source, code, name, &mut harvest.source_names) {
            harvest.source_call_matches += 1;
        }
        if harvest_regex_name(&sink, code, name, &mut harvest.sink_names) {
            harvest.sink_call_matches += 1;
        }
    }
    let entry_methods: BTreeSet<String> = cpg
        .methods()
        .into_iter()
        .filter_map(|method| cpg.name_of(method))
        .filter(|name| source.matches(name))
        .map(str::to_string)
        .collect();
    HarvestedSpec {
        source_names: capped(harvest.source_names),
        sink_names: capped(harvest.sink_names),
        sanitizer_names: Vec::new(),
        source_idents: Vec::new(),
        entry_methods: capped(entry_methods),
        source_call_matches: harvest.source_call_matches,
        sink_call_matches: harvest.sink_call_matches,
    }
}

fn harvest_regex_name(
    matcher: &PatternMatcher,
    code: &str,
    name: &str,
    into: &mut BTreeSet<String>,
) -> bool {
    let matched = matcher.matches(name) || (matcher.matches(code) && is_identifier_like(name));
    if matched {
        into.insert(name.to_string());
    }
    matched
}

fn is_identifier_like(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
}

enum PatternMatcher {
    Regex(regex::Regex),
    Literal(String),
}

impl PatternMatcher {
    fn new(pattern: &str) -> Self {
        match regex::Regex::new(pattern) {
            Ok(re) => Self::Regex(re),
            Err(_) => Self::Literal(pattern.to_string()),
        }
    }

    fn matches(&self, text: &str) -> bool {
        match self {
            Self::Regex(re) => re.is_match(text),
            Self::Literal(literal) => text.contains(literal),
        }
    }
}

/// Run the engine's interprocedural taint query for one harvested spec, with
/// guard and authz annotations attached, capped and deterministically
/// ordered. An empty harvest short-circuits to no flows (mirrors the Joern
/// path skipping CWEs with empty signals).
pub fn run_taint_query(
    project: &Project,
    harvested: &HarvestedSpec,
) -> (Vec<Finding>, CpgFlowQueryStats) {
    let mut findings = query_findings(project, harvested);
    findings.sort_by(|a, b| {
        (&a.sink_file, a.sink_line, &a.method).cmp(&(&b.sink_file, b.sink_line, &b.method))
    });
    findings.truncate(MAX_FLOWS_PER_QUERY);
    let stats = CpgFlowQueryStats {
        source_names: harvested.source_names.len(),
        sink_names: harvested.sink_names.len(),
        source_call_matches: harvested.source_call_matches,
        sink_call_matches: harvested.sink_call_matches,
        flow_count: findings.len(),
    };
    (findings, stats)
}

fn query_findings(project: &Project, harvested: &HarvestedSpec) -> Vec<Finding> {
    let has_source_model = !harvested.source_names.is_empty()
        || !harvested.source_idents.is_empty()
        || !harvested.entry_methods.is_empty();
    if !has_source_model || harvested.sink_names.is_empty() {
        return Vec::new();
    }
    let spec = build_taint_spec(harvested);
    let mut findings = find_flows(&project.cpg, &project.summaries, &spec);
    cpg_analysis::taint::annotate_guards(&project.cpg, &mut findings);
    cpg_analysis::annotate_authz(&project.cpg, &spec, &mut findings);
    findings
}

fn build_taint_spec(harvested: &HarvestedSpec) -> TaintSpec {
    let mut spec = TaintSpec::with_sanitizers(
        &as_refs(&harvested.source_names),
        &as_refs(&harvested.sink_names),
        &as_refs(&harvested.sanitizer_names),
    );
    spec.source_methods = harvested.entry_methods.iter().cloned().collect();
    spec.source_idents = harvested.source_idents.iter().cloned().collect();
    spec
}

fn as_refs(names: &[String]) -> Vec<&str> {
    names.iter().map(String::as_str).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn ts_fixture_project(dir: &Path) -> Project {
        std::fs::write(
            dir.join("users.ts"),
            "function list(req, res) {\n  const id = req.query.id;\n  db.query(\"SELECT \" + id);\n}\n",
        )
        .unwrap();
        let (project, _) = crate::engine::ensure_project(dir, "typescript")
            .map(|(p, _)| (p, ()))
            .unwrap();
        project
    }

    fn signals<'a>(
        sources: &'a [String],
        sinks: &'a [String],
        sanitizers: &'a [String],
    ) -> SignalSpec<'a> {
        SignalSpec {
            sources,
            sinks,
            sanitizers,
        }
    }

    #[test]
    fn harvests_names_behind_literal_signals() {
        let temp = tempfile::tempdir().unwrap();
        let project = ts_fixture_project(temp.path());
        let sources = vec!["req.query".to_string()];
        let sinks = vec![".query(".to_string()];
        let harvested = harvest_spec(&project, &signals(&sources, &sinks, &[]));

        assert!(
            harvested.source_call_matches > 0,
            "source signal must match the member read: {harvested:?}"
        );
        assert!(harvested.sink_call_matches > 0, "{harvested:?}");
        assert!(harvested.sink_names.iter().any(|n| n == "query"));
        assert_eq!(harvested.source_idents, vec!["req".to_string()]);
        // The enclosing `const id = ...` assignment must NOT be harvested.
        assert!(!harvested.source_names.iter().any(|n| n == "="));
    }

    #[test]
    fn finds_a_flow_from_request_to_query() {
        let temp = tempfile::tempdir().unwrap();
        let project = ts_fixture_project(temp.path());
        let sources = vec!["req.query".to_string()];
        let sinks = vec![".query(".to_string()];
        let harvested = harvest_spec(&project, &signals(&sources, &sinks, &[]));
        let (findings, stats) = run_taint_query(&project, &harvested);

        assert!(stats.flow_count > 0, "expected a flow; stats {stats:?}");
        let flow = &findings[0];
        assert!(flow
            .sink_file
            .as_deref()
            .is_some_and(|f| f.ends_with("users.ts")));
        assert!(!flow.path.is_empty());
    }

    #[test]
    fn empty_signals_short_circuit() {
        let temp = tempfile::tempdir().unwrap();
        let project = ts_fixture_project(temp.path());
        let harvested = harvest_spec(&project, &signals(&[], &[], &[]));
        let (findings, stats) = run_taint_query(&project, &harvested);
        assert!(findings.is_empty());
        assert_eq!(stats.flow_count, 0);
    }

    #[test]
    fn name_relation_rejects_operators_and_accepts_affixes() {
        assert!(name_relates_to_signal("execute", ".execute("));
        assert!(name_relates_to_signal("query", "req.query"));
        assert!(name_relates_to_signal("PG_GETARG_TEXT_PP", "PG_GETARG"));
        assert!(!name_relates_to_signal("=", "req.query"));
        assert!(!name_relates_to_signal("run", ".execute("));
    }
}
