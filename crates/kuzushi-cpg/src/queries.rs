//! Graph query primitives behind the agent-facing MCP tools: callers,
//! callees, definitions, method-at-position, reaching definitions, backward
//! slices, and graph stats. Kept here (not in the MCP crate) so the logic
//! sits next to the engine deps and stays unit-testable without a server.

use cpg_analysis::reaching_def_flows;
use cpg_core::{EdgeKind, NodeKind, Query};
use cpg_incremental::Project;
use std::collections::BTreeSet;

mod resolution;
pub type QueryResult<T> = Result<T, String>;

/// One method, projected for tool output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodRecord {
    pub selector: String,
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
    let graph_path = graph_path.replace('\\', "/");
    let file = file.replace('\\', "/");
    if graph_path == file {
        return true;
    }
    graph_path
        .strip_suffix(&file)
        .is_some_and(|prefix| prefix.ends_with('/'))
}

fn method_record(project: &Project, method: cpg_core::NodeId) -> MethodRecord {
    let cpg = &project.cpg;
    MethodRecord {
        selector: resolution::method_selector(project, method),
        name: cpg.name_of(method).unwrap_or_default().to_string(),
        full_name: cpg.full_name_of(method).map(str::to_string),
        signature: cpg.signature_of(method).map(str::to_string),
        file: cpg.path_of(cpg.file_of(method)).map(str::to_string),
        line: cpg.line_of(method),
    }
}

/// Exact-name method definitions.
pub fn methods_named(project: &Project, name: &str) -> Vec<MethodRecord> {
    resolution::matching_methods(project, name)
        .into_iter()
        .map(|m| method_record(project, m))
        .collect()
}

/// Methods containing a call to `name`, deduped.
pub fn callers_of(project: &Project, name: &str) -> QueryResult<Vec<MethodRecord>> {
    let selected = resolution::unique_method(project, name)?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for call in selected_calls(project, name, selected) {
        let Some(method) = enclosing_method(project, call) else {
            continue;
        };
        let record = method_record(project, method);
        if seen.insert((record.name.clone(), record.file.clone(), record.line)) {
            out.push(record);
        }
    }
    Ok(out)
}

fn selected_calls(
    project: &Project,
    name: &str,
    selected: Option<cpg_core::NodeId>,
) -> Vec<cpg_core::NodeId> {
    let Some(method) = selected else {
        return project.cpg.calls_named(name);
    };
    if project.cpg.name_of(method) == Some(name) {
        return project.cpg.calls_named(name);
    }
    project
        .cpg
        .calls()
        .into_iter()
        .filter(|call| project.cpg.call_targets(*call).contains(&method))
        .collect()
}

fn enclosing_method(project: &Project, node: cpg_core::NodeId) -> Option<cpg_core::NodeId> {
    let cpg = &project.cpg;
    let mut current = node;
    for _ in 0..1024 {
        if cpg.kind_of(current) == NodeKind::Method {
            return Some(current);
        }
        let mut parents = cpg.in_kind(current, EdgeKind::Ast);
        current = parents.next()?;
        if parents.next().is_some() {
            return None;
        }
    }
    None
}

/// Call names appearing inside the named method's body (resolved to callee
/// full names where the call graph has a target, bare names otherwise).
pub fn callees_of(project: &Project, name: &str) -> QueryResult<Vec<String>> {
    let cpg = &project.cpg;
    let Some(method) = resolution::unique_method(project, name)? else {
        return Ok(Vec::new());
    };
    let mut out = BTreeSet::new();
    for node in cpg_analysis::pass::ast_descendants(cpg, method) {
        if is_call_in_method(project, node, method) {
            out.extend(callee_labels(project, node));
        }
    }
    Ok(out.into_iter().collect())
}

fn is_call_in_method(project: &Project, node: cpg_core::NodeId, method: cpg_core::NodeId) -> bool {
    project.cpg.kind_of(node) == NodeKind::Call && enclosing_method(project, node) == Some(method)
}

fn callee_labels(project: &Project, call: cpg_core::NodeId) -> Vec<String> {
    let cpg = &project.cpg;
    let targets = cpg.call_targets(call);
    if targets.is_empty() {
        return cpg.name_of(call).map(str::to_string).into_iter().collect();
    }
    targets
        .into_iter()
        .filter_map(|method| cpg.full_name_of(method).or(cpg.name_of(method)))
        .map(str::to_string)
        .collect()
}

/// The method whose start line is the closest at-or-before `line` in `file`.
/// APPROXIMATE: the graph has no method end lines, so a line after the last
/// method of a file maps to that method even when it falls outside it.
pub fn method_at(project: &Project, file: &str, line: u32) -> QueryResult<Option<MethodRecord>> {
    Ok(resolution::nearest_method(project, file, line)?
        .map(|method| method_record(project, method)))
}

/// Canonical graph path, or an explicit ambiguity when a suffix matches several files.
pub fn resolved_file(project: &Project, file: &str) -> QueryResult<Option<String>> {
    Ok(resolution::unique_file(project, file)?
        .and_then(|id| project.cpg.path_of(id).map(str::to_string)))
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
) -> QueryResult<Vec<ReachingDefRecord>> {
    let cpg = &project.cpg;
    let Some(method) = resolution::exact_method(project, file, line)? else {
        return Ok(Vec::new());
    };
    Ok(reaching_def_flows(cpg, method)
        .into_iter()
        .filter(|flow| flow.var == var)
        .map(|flow| ReachingDefRecord {
            var: flow.var,
            def_line: cpg.line_of(flow.src),
            def_code: cpg.code_of(flow.src).map(str::to_string),
            use_line: cpg.line_of(flow.dst),
            use_code: cpg.code_of(flow.dst).map(str::to_string),
        })
        .collect())
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
) -> QueryResult<(Vec<SliceRecord>, bool)> {
    let cpg = &project.cpg;
    let Some(method) = resolution::unique_method(project, method_name)? else {
        return Ok((Vec::new(), false));
    };
    let criteria: Vec<_> = cpg_analysis::pass::ast_descendants(cpg, method)
        .into_iter()
        .filter(|node| slice_criterion(project, method, *node, line))
        .collect();
    let (entries, truncated) =
        cpg_cli::slice::backward_slice(cpg, &criteria, depth, SLICE_MAX_NODES);
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
    Ok((records, truncated))
}

fn slice_criterion(
    project: &Project,
    method: cpg_core::NodeId,
    node: cpg_core::NodeId,
    line: u32,
) -> bool {
    let cpg = &project.cpg;
    cpg.line_of(node) == Some(line)
        && matches!(
            cpg.kind_of(node),
            NodeKind::Call | NodeKind::Identifier | NodeKind::Return
        )
        && enclosing_method(project, node) == Some(method)
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

        let callers = callers_of(&project, "run").unwrap();
        assert_eq!(callers.len(), 1, "{callers:?}");
        assert_eq!(callers[0].name, "handler");

        let callees = callees_of(&project, "handler").unwrap();
        assert!(callees.iter().any(|c| c.contains("run")), "{callees:?}");
        assert!(
            callees.iter().any(|c| c.contains("sanitize")),
            "{callees:?}"
        );

        let defs = methods_named(&project, "run");
        assert_eq!(defs.len(), 1);
        assert!(defs[0].file.as_deref().unwrap().ends_with("main.go"));
    }

    #[test]
    fn method_at_maps_lines_to_the_enclosing_method() {
        let temp = tempfile::tempdir().unwrap();
        let project = fixture_project(temp.path());
        let record = method_at(&project, "main.go", 5)
            .unwrap()
            .expect("line 5 is inside handler");
        assert_eq!(record.name, "handler");
        let record = method_at(&project, "main.go", 9)
            .unwrap()
            .expect("line 9 is inside run");
        assert_eq!(record.name, "run");
        assert!(method_at(&project, "absent.go", 5).unwrap().is_none());
    }

    #[test]
    fn reaching_definitions_require_ast_membership_instead_of_nearest_start() {
        let temp = tempfile::tempdir().unwrap();
        let project = fixture_project(temp.path());
        assert!(reaching_defs(&project, "main.go", 5, "input").is_ok());
        for line in [7, 11, 30] {
            assert!(reaching_defs(&project, "main.go", line, "input")
                .unwrap_err()
                .contains("exact method membership unavailable"));
        }
        assert_eq!(
            method_at(&project, "main.go", 7).unwrap().unwrap().name,
            "handler"
        );
        assert_eq!(
            method_at(&project, "main.go", 30).unwrap().unwrap().name,
            "sanitize"
        );
    }

    #[test]
    fn duplicate_files_and_methods_require_unambiguous_identity() {
        let temp = tempfile::tempdir().unwrap();
        for (package, callee) in [("one", "first"), ("two", "second")] {
            let directory = temp.path().join(package);
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(
                directory.join("shared.go"),
                format!(
                    "package {package}\nfunc duplicate(input string) {{\n  {callee}(input)\n}}\n"
                ),
            )
            .unwrap();
        }
        let project = crate::engine::ensure_project(temp.path(), "go").unwrap().0;
        assert!(method_at(&project, "shared.go", 3)
            .unwrap_err()
            .contains("ambiguous file"));
        assert!(method_at(&project, "one/shared.go", 3).unwrap().is_some());
        assert!(callees_of(&project, "duplicate")
            .unwrap_err()
            .contains("ambiguous method"));
        assert!(callers_of(&project, "duplicate").is_err());
        assert!(backward_slice_at(&project, "duplicate", 3, 2).is_err());
        let definitions = methods_named(&project, "duplicate");
        assert_eq!(definitions.len(), 2);
        assert_ne!(definitions[0].selector, definitions[1].selector);
        for record in definitions {
            let callees = callees_of(&project, &record.selector).unwrap();
            assert_eq!(callees.len(), 1);
            let expected = if record.file.unwrap().contains("one/") {
                "first"
            } else {
                "second"
            };
            assert!(callees[0].contains(expected), "{callees:?}");
            assert!(backward_slice_at(&project, &record.selector, 3, 2).is_ok());
        }
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
    fn overloaded_methods_in_one_file_have_distinct_selectors() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("Example.java"),
            "class Example {\n void work(int x) { first(); }\n void work(String x) { second(); }\n}\n").unwrap();
        let project = crate::engine::ensure_project(temp.path(), "java")
            .unwrap()
            .0;
        let definitions = methods_named(&project, "work");
        assert_eq!(definitions.len(), 2);
        assert_ne!(definitions[0].selector, definitions[1].selector);
        assert!(callees_of(&project, "work").is_err());
        for record in definitions {
            assert!(!callees_of(&project, &record.selector).unwrap().is_empty());
        }
    }

    #[test]
    fn nested_method_calls_are_not_attributed_to_the_outer_body() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("nested.ts"),
            "function outer() {\n function nested() { hidden(); }\n visible();\n}\n",
        )
        .unwrap();
        let project = crate::engine::ensure_project(temp.path(), "typescript")
            .unwrap()
            .0;
        let calls = callees_of(&project, "outer").unwrap();
        assert!(
            calls.iter().any(|name| name.contains("visible")),
            "{calls:?}"
        );
        assert!(
            !calls.iter().any(|name| name.contains("hidden")),
            "{calls:?}"
        );
    }

    #[test]
    fn file_matching_requires_a_path_boundary() {
        assert!(file_matches("/repo/src/users.ts", "src/users.ts"));
        assert!(file_matches("src/users.ts", "src/users.ts"));
        assert!(!file_matches("/repo/src/xusers.ts", "users.ts"));
        assert!(file_matches("/repo/src/users.ts", "users.ts"));
        assert!(file_matches("C:\\repo\\src\\users.ts", "src/users.ts"));
    }
}
