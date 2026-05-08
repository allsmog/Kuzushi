use super::*;

pub(super) fn inspect(inspection: &NodeLineInspection<'_>, builder: &mut AttackSurfaceBuilder) {
    let route = inspection.route();
    if !is_rpc_handler(inspection, &route) {
        return;
    }
    inspection.add_surface(
        builder,
        AttackSurfaceKind::RpcHandler,
        "RPC handler",
        route.method.as_deref(),
        route.path.as_deref(),
        Some("remote_rpc"),
        "node.rpc-handler",
    );
}

fn is_rpc_handler(inspection: &NodeLineInspection<'_>, route: &RouteLine) -> bool {
    inspection.has_any(&[
        "graphqlhttp(",
        "new apolloserver",
        "apolloserver(",
        "createexpressmiddleware",
        "trpc.",
        ".procedure",
        "grpc",
    ]) || route
        .path
        .as_deref()
        .is_some_and(|route| route.to_ascii_lowercase().contains("graphql"))
}
