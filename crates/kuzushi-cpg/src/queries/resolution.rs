use super::{enclosing_method, QueryResult};
use cpg_core::{FileId, NodeId, Query};
use cpg_incremental::Project;
use std::collections::BTreeSet;

pub(super) fn method_selector(project: &Project, method: NodeId) -> String {
    let cpg = &project.cpg;
    let mut digest = blake3::Hasher::new();
    digest.update(b"kuzushi:cpg-method:v1");
    for value in [
        cpg.name_of(method),
        cpg.full_name_of(method),
        cpg.signature_of(method),
        cpg.path_of(cpg.file_of(method)),
    ] {
        let bytes = value.unwrap_or_default().as_bytes();
        digest.update(&(bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    digest.update(&cpg.line_of(method).unwrap_or(0).to_be_bytes());
    format!("method:{}", digest.finalize().to_hex())
}

pub(super) fn matching_methods(project: &Project, name: &str) -> Vec<NodeId> {
    project
        .cpg
        .methods()
        .into_iter()
        .filter(|method| matches_method(project, *method, name))
        .collect()
}

fn matches_method(project: &Project, method: NodeId, name: &str) -> bool {
    if name.starts_with("method:") {
        return method_selector(project, method) == name;
    }
    project.cpg.name_of(method) == Some(name) || project.cpg.full_name_of(method) == Some(name)
}

pub(super) fn unique_method(project: &Project, name: &str) -> QueryResult<Option<NodeId>> {
    let matches = matching_methods(project, name);
    if matches.len() > 1 {
        return Err(ambiguous_methods(project, &matches));
    }
    Ok(matches.first().copied())
}

pub(super) fn ambiguous_methods(project: &Project, methods: &[NodeId]) -> String {
    let candidates: Vec<String> = methods
        .iter()
        .take(8)
        .map(|method| {
            let record = super::method_record(project, *method);
            format!(
                "{}:{} ({})",
                record.file.unwrap_or_default(),
                record.line.unwrap_or(0),
                record.selector
            )
        })
        .collect();
    format!(
        "ambiguous method: {} candidates; use a selector from cpg.definitions: {}",
        methods.len(),
        candidates.join(", ")
    )
}

pub(super) fn unique_file(project: &Project, requested: &str) -> QueryResult<Option<FileId>> {
    let files: Vec<(FileId, String)> = project
        .cpg
        .files()
        .into_iter()
        .filter_map(|id| {
            project
                .cpg
                .path_of(id)
                .map(|path| (id, path.replace('\\', "/")))
        })
        .collect();
    let requested = requested.replace('\\', "/");
    let exact: Vec<_> = files
        .iter()
        .filter(|(_, path)| *path == requested)
        .collect();
    let matches = if exact.is_empty() {
        files
            .iter()
            .filter(|(_, path)| super::file_matches(path, &requested))
            .collect()
    } else {
        exact
    };
    if matches.len() > 1 {
        let candidates: Vec<_> = matches
            .iter()
            .take(8)
            .map(|(_, path)| path.as_str())
            .collect();
        return Err(format!(
            "ambiguous file; use a canonical path: {}",
            candidates.join(", ")
        ));
    }
    Ok(matches.first().map(|(id, _)| *id))
}

pub(super) fn nearest_method(
    project: &Project,
    file: &str,
    line: u32,
) -> QueryResult<Option<NodeId>> {
    let Some(file) = unique_file(project, file)? else {
        return Ok(None);
    };
    let mut methods: Vec<(u32, NodeId)> = project
        .cpg
        .methods()
        .into_iter()
        .filter(|method| project.cpg.file_of(*method) == file)
        .filter_map(|method| project.cpg.line_of(method).map(|start| (start, method)))
        .filter(|(start, _)| *start <= line)
        .collect();
    methods.sort_by_key(|(start, _)| *start);
    let Some((start, nearest)) = methods.last().copied() else {
        return Ok(None);
    };
    let tied: Vec<_> = methods
        .into_iter()
        .filter(|(at, _)| *at == start)
        .map(|(_, id)| id)
        .collect();
    if tied.len() > 1 {
        return Err(ambiguous_methods(project, &tied));
    }
    Ok(Some(nearest))
}

pub(super) fn exact_method(
    project: &Project,
    file: &str,
    line: u32,
) -> QueryResult<Option<NodeId>> {
    let Some(file) = unique_file(project, file)? else {
        return Ok(None);
    };
    let methods: BTreeSet<_> = project
        .cpg
        .nodes_in_file(file)
        .iter()
        .filter(|node| project.cpg.line_of(**node) == Some(line))
        .filter_map(|node| enclosing_method(project, *node))
        .collect();
    let methods: Vec<_> = methods.into_iter().collect();
    if methods.len() > 1 {
        return Err(ambiguous_methods(project, &methods));
    }
    let method = methods.first().copied().ok_or_else(|| {
        "exact method membership unavailable: no unambiguous AST node at the requested line"
            .to_string()
    })?;
    Ok(Some(method))
}
