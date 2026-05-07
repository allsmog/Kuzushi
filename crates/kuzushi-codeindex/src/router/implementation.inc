use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Gtags,
    Clang,
    Joern,
}

impl Backend {
    pub fn binary_name(self) -> &'static str {
        match self {
            Self::Gtags => "kuzushi-mcp-gtags",
            Self::Clang => "kuzushi-mcp-clang",
            Self::Joern => "kuzushi-mcp-joern",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Query {
    Definitions,
    References,
    SymbolsInFile,
    FilesMatching,
    Completion,
    CallersOfFunction,
    CalleesOfFunction,
    TaintPaths,
    ReachingDef,
    UnsafeBlocks,
    FfiBoundaries,
    TypeAtPosition,
    AstAtPosition,
    MacroExpansion,
    MethodAtPosition,
}

#[derive(Debug, Clone, Copy)]
pub struct BackendCapability {
    pub query: Query,
    pub primary: Backend,
    pub fallback: Option<Backend>,
    pub last_resort: Option<Backend>,
}

const DEFAULTS: &[BackendCapability] = &[
    BackendCapability {
        query: Query::Definitions,
        primary: Backend::Clang,
        fallback: Some(Backend::Gtags),
        last_resort: Some(Backend::Joern),
    },
    BackendCapability {
        query: Query::References,
        primary: Backend::Clang,
        fallback: Some(Backend::Gtags),
        last_resort: Some(Backend::Joern),
    },
    BackendCapability {
        query: Query::SymbolsInFile,
        primary: Backend::Gtags,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::FilesMatching,
        primary: Backend::Gtags,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::Completion,
        primary: Backend::Gtags,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::CallersOfFunction,
        primary: Backend::Clang,
        fallback: Some(Backend::Joern),
        last_resort: Some(Backend::Gtags),
    },
    BackendCapability {
        query: Query::CalleesOfFunction,
        primary: Backend::Joern,
        fallback: Some(Backend::Clang),
        last_resort: Some(Backend::Gtags),
    },
    BackendCapability {
        query: Query::TaintPaths,
        primary: Backend::Joern,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::ReachingDef,
        primary: Backend::Joern,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::UnsafeBlocks,
        primary: Backend::Joern,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::FfiBoundaries,
        primary: Backend::Joern,
        fallback: Some(Backend::Clang),
        last_resort: None,
    },
    BackendCapability {
        query: Query::TypeAtPosition,
        primary: Backend::Clang,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::AstAtPosition,
        primary: Backend::Clang,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::MacroExpansion,
        primary: Backend::Clang,
        fallback: None,
        last_resort: None,
    },
    BackendCapability {
        query: Query::MethodAtPosition,
        primary: Backend::Joern,
        fallback: Some(Backend::Clang),
        last_resort: Some(Backend::Gtags),
    },
];

#[derive(Debug, Clone, Default)]
pub struct RoutingTable {
    overrides: Vec<BackendCapability>,
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
        let mut out = vec![cap.primary];
        if let Some(b) = cap.fallback {
            out.push(b);
        }
        if let Some(b) = cap.last_resort {
            out.push(b);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_route_definitions_clang_first() {
        let table = RoutingTable::new();
        let order = table.order_for(Query::Definitions);
        assert_eq!(order[0], Backend::Clang);
        assert!(order.contains(&Backend::Gtags));
    }

    #[test]
    fn defaults_route_taint_paths_joern_only() {
        let table = RoutingTable::new();
        let order = table.order_for(Query::TaintPaths);
        assert_eq!(order, vec![Backend::Joern]);
    }

    #[test]
    fn override_replaces_default() {
        let table = RoutingTable::new().with_override(BackendCapability {
            query: Query::Definitions,
            primary: Backend::Gtags,
            fallback: None,
            last_resort: None,
        });
        assert_eq!(table.order_for(Query::Definitions), vec![Backend::Gtags]);
    }

    #[test]
    fn binary_names_round_trip() {
        assert_eq!(Backend::Gtags.binary_name(), "kuzushi-mcp-gtags");
        assert_eq!(Backend::Clang.binary_name(), "kuzushi-mcp-clang");
        assert_eq!(Backend::Joern.binary_name(), "kuzushi-mcp-joern");
    }
}
