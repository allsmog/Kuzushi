//! Recorded flow membership is a review cue, never an architectural verdict.
use super::DfdModel;
use std::collections::BTreeSet;

pub(super) const NO_RECORDED_COMPONENT_FLOWS: &str =
    "No incoming or outgoing flows recorded. Review this component's role.";

impl DfdModel {
    pub(crate) fn topology_notice(&self) -> Option<String> {
        if self.nodes.is_empty() {
            return None;
        }
        if self.flows.is_empty() {
            return Some(
                "Component map only. No data flows are recorded; relationships remain unknown."
                    .into(),
            );
        }
        partial_topology_notice(self.nodes_without_flows())
    }

    fn nodes_without_flows(&self) -> usize {
        let endpoints = self
            .flows
            .iter()
            .flat_map(|flow| [flow.from_id.as_str(), flow.to_id.as_str()])
            .collect::<BTreeSet<_>>();
        self.nodes
            .iter()
            .filter(|node| !endpoints.contains(node.key.as_str()))
            .count()
    }

    pub(crate) fn component_topology_notice(&self, key: &str) -> Option<&'static str> {
        if !self.nodes.iter().any(|node| node.key == key) {
            return None;
        }
        if self
            .flows
            .iter()
            .any(|flow| flow.from_id == key || flow.to_id == key)
        {
            return None;
        }
        Some(NO_RECORDED_COMPONENT_FLOWS)
    }
}

fn partial_topology_notice(count: usize) -> Option<String> {
    match count {
        0 => None,
        1 => Some("1 component has no recorded flows. Review its role.".into()),
        _ => Some(format!(
            "{count} components have no recorded flows. Review their roles."
        )),
    }
}

#[cfg(test)]
mod tests;
