use super::*;
use crate::findings::{FindingRelationshipKind, FindingRelationshipState};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn components(
    findings: &[Finding],
    relationships: &[FindingRelationship],
) -> Result<(Vec<Vec<usize>>, FindingGroupDiagnostics)> {
    let endpoints = findings
        .iter()
        .map(recorded_endpoint)
        .collect::<Result<Vec<_>>>()?;
    let by_id = endpoints
        .iter()
        .enumerate()
        .map(|(index, row)| (row.finding_id, index))
        .collect();
    let mut graph = vec![Vec::new(); findings.len()];
    let mut diagnostics = FindingGroupDiagnostics::default();
    for relation in relationships {
        attach_relation(relation, &endpoints, &by_id, &mut graph, &mut diagnostics);
    }
    Ok((connected_components(&graph), diagnostics))
}

fn attach_relation(
    relation: &FindingRelationship,
    endpoints: &[FindingRelationshipEndpoint],
    by_id: &BTreeMap<i64, usize>,
    graph: &mut [Vec<usize>],
    diagnostics: &mut FindingGroupDiagnostics,
) {
    if relation.state != FindingRelationshipState::Accepted {
        return;
    }
    match relation.kind {
        FindingRelationshipKind::RelatedVariant => diagnostics.related_variant_links += 1,
        FindingRelationshipKind::Uncertain => diagnostics.uncertain_links += 1,
        FindingRelationshipKind::Duplicate => {
            attach_duplicate(relation, endpoints, by_id, graph, diagnostics)
        }
    }
}

fn attach_duplicate(
    relation: &FindingRelationship,
    endpoints: &[FindingRelationshipEndpoint],
    by_id: &BTreeMap<i64, usize>,
    graph: &mut [Vec<usize>],
    diagnostics: &mut FindingGroupDiagnostics,
) {
    let pair = current_index(&relation.from, endpoints, by_id).zip(current_index(
        &relation.to,
        endpoints,
        by_id,
    ));
    let Some((from, to)) = pair else {
        diagnostics.inactive_duplicate_links += 1;
        return;
    };
    graph[from].push(to);
    graph[to].push(from);
}

fn current_index(
    endpoint: &FindingRelationshipEndpoint,
    endpoints: &[FindingRelationshipEndpoint],
    by_id: &BTreeMap<i64, usize>,
) -> Option<usize> {
    let index = *by_id.get(&endpoint.finding_id)?;
    (endpoints[index] == *endpoint).then_some(index)
}

fn connected_components(graph: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let mut visited = BTreeSet::new();
    let mut groups = Vec::new();
    for root in 0..graph.len() {
        if visited.contains(&root) {
            continue;
        }
        groups.push(walk_component(root, graph, &mut visited));
    }
    groups
}

fn walk_component(root: usize, graph: &[Vec<usize>], visited: &mut BTreeSet<usize>) -> Vec<usize> {
    let mut queue = vec![root];
    let mut cursor = 0;
    visited.insert(root);
    while cursor < queue.len() {
        for next in &graph[queue[cursor]] {
            if visited.insert(*next) {
                queue.push(*next);
            }
        }
        cursor += 1;
    }
    queue.sort_unstable();
    queue
}
