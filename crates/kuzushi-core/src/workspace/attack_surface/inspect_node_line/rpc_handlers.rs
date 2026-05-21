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
        "createyoga(",
        "@resolver(",
        "@query(",
        "@mutation(",
        "@subscription(",
        "register(mercurius",
        "createtrpcrouter",
        "inittrpc",
        "protectedprocedure",
        "publicprocedure",
        "trpc.",
        ".procedure",
        "grpc",
        "websocketserver",
        "new websocket",
        "socket.io",
        "io.on(",
        "socket.on(",
        "app.ws(",
    ]) || route
        .path
        .as_deref()
        .is_some_and(route_looks_rpc_or_realtime)
}

fn route_looks_rpc_or_realtime(route: &str) -> bool {
    line_contains_any(
        &route.to_ascii_lowercase(),
        &["graphql", "realtime", "socket", "subscription", "websocket"],
    )
}
