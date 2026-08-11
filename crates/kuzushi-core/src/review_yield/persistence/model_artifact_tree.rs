use super::model_artifact::ModelArtifactError;
use crate::review_yield::domain::{ModelNode, MAX_MODEL_DEPTH};

/// Proves the node list is a single-parent tree rooted at node 0, no deeper
/// than the depth bound, with every node reachable exactly once. Returns the
/// measured depth.
///
/// The walk is an explicit worklist, never recursion, so a hostile artifact
/// cannot exhaust the stack. Visiting an already-visited node covers both
/// cycles and shared children: this is a tree, not a DAG.
pub(crate) fn check_tree_shape(nodes: &[ModelNode]) -> Result<usize, ModelArtifactError> {
    let mut visited = vec![false; nodes.len()];
    let mut worklist = vec![(0usize, 0usize)];
    let mut depth = 0usize;
    visited[0] = true;
    while let Some((index, node_depth)) = worklist.pop() {
        depth = depth.max(node_depth);
        check_depth(node_depth)?;
        push_children(nodes, index, node_depth, &mut visited, &mut worklist)?;
    }
    require_all_reachable(&visited)?;
    Ok(depth)
}

fn check_depth(node_depth: usize) -> Result<(), ModelArtifactError> {
    if node_depth > MAX_MODEL_DEPTH {
        return Err(tree(format!(
            "depth {node_depth} exceeds the limit of {MAX_MODEL_DEPTH}"
        )));
    }
    Ok(())
}

fn push_children(
    nodes: &[ModelNode],
    index: usize,
    node_depth: usize,
    visited: &mut [bool],
    worklist: &mut Vec<(usize, usize)>,
) -> Result<(), ModelArtifactError> {
    for child in nodes[index].children() {
        let child = usize::from(child);
        require_in_bounds(child, nodes.len())?;
        require_first_visit(child, visited)?;
        visited[child] = true;
        worklist.push((child, node_depth + 1));
    }
    Ok(())
}

fn require_in_bounds(child: usize, count: usize) -> Result<(), ModelArtifactError> {
    if child >= count {
        return Err(tree(format!(
            "child index {child} is outside the {count} declared nodes"
        )));
    }
    Ok(())
}

/// A second visit means either a cycle back to an ancestor or a node with two
/// parents. Both are rejected: neither shape has a single decision path.
fn require_first_visit(child: usize, visited: &[bool]) -> Result<(), ModelArtifactError> {
    if visited[child] {
        return Err(tree(format!(
            "node {child} is reachable more than once (cycle or shared child)"
        )));
    }
    Ok(())
}

fn require_all_reachable(visited: &[bool]) -> Result<(), ModelArtifactError> {
    let orphan = visited.iter().position(|seen| !seen);
    match orphan {
        Some(index) => Err(tree(format!("node {index} is unreachable from the root"))),
        None => Ok(()),
    }
}

fn tree(message: String) -> ModelArtifactError {
    ModelArtifactError::Tree(message)
}
