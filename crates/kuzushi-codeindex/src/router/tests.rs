#[cfg(test)]
mod tests {
    use super::super::*;

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
