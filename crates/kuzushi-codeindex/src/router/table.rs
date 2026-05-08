use super::defaults::DEFAULTS;
use super::{Backend, BackendCapability, Query};

#[derive(Debug, Clone, Default)]
pub struct RoutingTable {
    pub(crate) overrides: Vec<BackendCapability>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the routing for a single query type. Useful when the
    /// operator knows their joern install is stale and wants clang to win
    /// for callers, or similar.
    pub fn with_override(mut self, capability: BackendCapability) -> Self {
        self.overrides.retain(|c| c.query != capability.query);
        self.overrides.push(capability);
        self
    }

    /// Resolve the ordered list of backends to try for a given query.
    pub fn order_for(&self, query: Query) -> Vec<Backend> {
        let cap = self
            .overrides
            .iter()
            .find(|c| c.query == query)
            .copied()
            .or_else(|| DEFAULTS.iter().find(|c| c.query == query).copied())
            .unwrap_or(BackendCapability {
                query,
                primary: Backend::Gtags,
                fallback: None,
                last_resort: None,
            });
        route_order(cap)
    }
}

fn route_order(cap: BackendCapability) -> Vec<Backend> {
    let mut out = vec![cap.primary];
    if let Some(backend) = cap.fallback {
        out.push(backend);
    }
    if let Some(backend) = cap.last_resort {
        out.push(backend);
    }
    out
}
