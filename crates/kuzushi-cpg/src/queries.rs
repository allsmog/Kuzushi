//! Graph query primitives behind the agent-facing MCP tools: callers,
//! callees, definitions, method-at-position, reaching definitions, backward
//! slices, and graph stats. Kept here (not in the MCP crate) so the logic
//! sits next to the engine deps and stays unit-testable without a server.

use cpg_analysis::reaching_def_flows;
use cpg_core::{EdgeKind, NodeKind, Query};
use cpg_incremental::Project;
use std::collections::BTreeSet;

/// One method, projected for tool output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRecord {
    pub name: String,
    pub full_name: Option<String>,
    pub signature: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

/// True when `graph_path` (as stored in the graph) refers to the
/// user-supplied `file` argument — exact, or suffix at a path boundary so
/// relative arguments match absolute stored paths.
pub fn file_matches(graph_path: &str, file: &str) -> bool {
    if graph_path == file {
        return true;
    }
    graph_path
        .strip_suffix(file)
        .is_some_and(|prefix| prefix.ends_with('/'))
}

fn method_record(project: &Project, method: cpg_core::NodeId) -> MethodRecord {
    let cpg = &project.cpg;
    MethodRecord {
        name: cpg.name_of(method).unwrap_or_default().to_string(),
        full_name: cpg.full_name_of(method).map(str::to_string),
        signature: cpg.signature_of(method).map(str::to_string),
        file: cpg.path_of(cpg.file_of(method)).map(str::to_string),
        line: cpg.line_of(method),
    }
}

/// Exact-name method definitions.
pub fn methods_named(project: &Project, name: &str) -> Vec<MethodRecord> {
    project
        .cpg
        .method_named(name)
        .into_iter()
        .map(|m| method_record(project, m))
        .collect()
}

/// Methods containing a call to `name`, deduped.
pub fn callers_of(project: &Project, name: &str) -> Vec<MethodRecord> {
    let cpg = &project.cpg;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for call in cpg.calls_named(name) {
        let Some(method) = enclosing_method(project, call) else {
            continue;
        };
        let record = method_record(project, method);
        if seen.insert((record.name.clone(), record.file.clone(), record.line)) {
            out.push(record);
        }
    }
    out
}

fn enclosing_method(project: &Project, node: cpg_core::NodeId) -> Option<cpg_core::NodeId> {
    let cpg = &project.cpg;
    let mut current = node;
    for _ in 0..1024 {
        if cpg.kind_of(current) == NodeKind::Method {
            return Some(current);
        }
        current = cpg.in_kind(current, EdgeKind::Ast).next()?;
    }
    None
}

/// Call names appearing inside the named method's body (resolved to callee
/// full names where the call graph has a target, bare names otherwise).
pub fn callees_of(project: &Project, name: &str) -> Vec<String> {
    let cpg = &project.cpg;
    let mut out = BTreeSet::new();
    for method in cpg.method_named(name) {
        for node in cpg_analysis::pass::ast_descendants(cpg, method) {
            if cpg.kind_of(node) != NodeKind::Call {
                continue;
            }
            if let Some(callee) = callee_label(project, node) {
                out.insert(callee);
            }
        }
    }
    out.into_iter().collect()
}

fn callee_label(project: &Project, call: cpg_core::NodeId) -> Option<String> {
    let cpg = &project.cpg;
    let target = cpg
        .call_target(call)
        .and_then(|m| cpg.full_name_of(m).or(cpg.name_of(m)));
    target.or(cpg.name_of(call)).map(str::to_string)
}

/// The method whose start line is the closest at-or-before `line` in `file`.
/// APPROXIMATE: the graph has no method end lines, so a line after the last
/// method of a file maps to that method even when it falls outside it.
pub fn method_at(project: &Project, file: &str, line: u32) -> Option<MethodRecord> {
    let cpg = &project.cpg;
    cpg.methods()
        .into_iter()
        .filter(|m| {
            cpg.path_of(cpg.file_of(*m))
                .is_some_and(|path| file_matches(path, file))
        })
        .filter_map(|m| cpg.line_of(m).filter(|start| *start <= line).map(|s| (s, m)))
        .max_by_key(|(start, _)| *start)
        .map(|(_, m)| method_record(project, m))
}

/// One reaching-definition edge, projected for tool output.
#[derive(Debug, Clone)]
pub struct ReachingDefRecord {
    pub var: String,
    pub def_line: Option<u32>,
    pub def_code: Option<String>,
    pub use_line: Option<u32>,
    pub use_code: Option<String>,
}

/// Reaching definitions of `var` inside the method enclosing (file, line).
pub fn reaching_defs(
    project: &Project,
    file: &str,
    line: u32,
    var: &str,
) -> Vec<ReachingDefRecord> {
    let cpg = &project.cpg;
    let Some(method) = method_node_at(project, file, line) else {
        return Vec::new();
    };
    reaching_def_flows(cpg, method)
        .into_iter()
        .filter(|flow| flow.var == var)
        .map(|flow| ReachingDefRecord {
            var: flow.var,
            def_line: cpg.line_of(flow.src),
            def_code: cpg.code_of(flow.src).map(str::to_string),
            use_line: cpg.line_of(flow.dst),
            use_code: cpg.code_of(flow.dst).map(str::to_string),
        })
        .collect()
}

fn method_node_at(project: &Project, file: &str, line: u32) -> Option<cpg_core::NodeId> {
    let cpg = &project.cpg;
    cpg.methods()
        .into_iter()
        .filter(|m| {
            cpg.path_of(cpg.file_of(*m))
                .is_some_and(|path| file_matches(path, file))
        })
        .filter_map(|m| cpg.line_of(m).filter(|start| *start <= line).map(|s| (s, m)))
        .max_by_key(|(start, _)| *start)
        .map(|(_, m)| m)
}

/// One backward-slice entry, projected for tool output.
#[derive(Debug, Clone)]
pub struct SliceRecord {
    pub file: String,
    pub line: Option<u32>,
    pub code: String,
    pub method: String,
    pub hops: usize,
}

pub const SLICE_MAX_NODES: usize = 500;

/// Backward slice from every statement of `method_name` at `line`.
pub fn backward_slice_at(
    project: &Project,
    method_name: &str,
    line: u32,
    depth: usize,
) -> (Vec<SliceRecord>, bool) {
    let cpg = &project.cpg;
    let criteria = cpg_cli::slice::criterion_location(cpg, method_name, line);
    let (entries, truncated) = cpg_cli::slice::backward_slice(cpg, &criteria, depth, SLICE_MAX_NODES);
    let records = entries
        .into_iter()
        .map(|entry| SliceRecord {
            file: entry.file,
            line: entry.line,
            code: entry.code,
            method: entry.method,
            hops: entry.hops,
        })
        .collect();
    (records, truncated)
}

/// Node/method/call/summary counts for one graph.
#[derive(Debug, Clone)]
pub struct GraphStats {
    pub nodes: usize,
    pub methods: usize,
    pub calls: usize,
    pub summaries: usize,
}

pub fn graph_stats(project: &Project) -> GraphStats {
    GraphStats {
        nodes: project.cpg.live_count(),
        methods: project.cpg.methods().len(),
        calls: project.cpg.calls().len(),
        summaries: project.summaries.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_project(dir: &Path) -> Project {
        std::fs::write(
            dir.join("main.go"),
            "package main\n\nfunc handler(input string) {\n\tsanitize(input)\n\trun(input)\n}\n\nfunc run(cmd string) {\n\texec(cmd)\n}\n\nfunc sanitize(s string) {\n}\n",
        )
        .unwrap();
        crate::engine::ensure_project(dir, "go").unwrap().0
    }

    #[test]
    fn callers_callees_and_definitions_resolve() {
        let temp = tempfile::tempdir().unwrap();
        let project = fixture_project(temp.path());

        let callers = callers_of(&project, "run");
        assert_eq!(callers.len(), 1, "{callers:?}");
        assert_eq!(callers[0].name, "handler");

        let callees = callees_of(&project, "handler");
        assert!(callees.iter().any(|c| c.contains("run")), "{callees:?}");
        assert!(callees.iter().any(|c| c.contains("sanitize")), "{callees:?}");

        let defs = methods_named(&project, "run");
        assert_eq!(defs.len(), 1);
        assert!(defs[0].file.as_deref().unwrap().ends_with("main.go"));
    }

    #[test]
    fn method_at_maps_lines_to_the_enclosing_method() {
        let temp = tempfile::tempdir().unwrap();
        let project = fixture_project(temp.path());
        let record = method_at(&project, "main.go", 5).expect("line 5 is inside handler");
        assert_eq!(record.name, "handler");
        let record = method_at(&project, "main.go", 9).expect("line 9 is inside run");
        assert_eq!(record.name, "run");
        assert!(method_at(&project, "absent.go", 5).is_none());
    }

    #[test]
    fn graph_stats_are_populated() {
        let temp = tempfile::tempdir().unwrap();
        let project = fixture_project(temp.path());
        let stats = graph_stats(&project);
        assert!(stats.methods >= 3);
        assert!(stats.calls >= 2);
        assert!(stats.nodes > stats.methods);
    }

    #[test]
    fn file_matching_requires_a_path_boundary() {
        assert!(file_matches("/repo/src/users.ts", "src/users.ts"));
        assert!(file_matches("src/users.ts", "src/users.ts"));
        assert!(!file_matches("/repo/src/xusers.ts", "users.ts"));
        assert!(file_matches("/repo/src/users.ts", "users.ts"));
    }
}
