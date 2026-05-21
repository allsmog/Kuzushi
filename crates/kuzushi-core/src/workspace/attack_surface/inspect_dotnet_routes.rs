use super::*;
use super::inspect_dotnet_route_groups::{
    add_dotnet_route_group, dotnet_chained_group_prefix, dotnet_chained_group_route,
    dotnet_route_group_for_line,
};
use super::inspect_dotnet_route_paths::{
    combine_dotnet_routes, dotnet_route_attribute, dotnet_route_path_for_line,
};
use super::inspect_dotnet_route_methods::dotnet_route_methods;

pub(crate) fn inspect_dotnet_routes(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    text: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let mut class_route = None;
    let mut pending_route = None;
    let mut route_groups = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        let detail = trim_detail(line);
        add_dotnet_route_group(&detail, &mut route_groups);
        let group_route = dotnet_route_group_for_line(&detail, &route_groups);
        update_dotnet_class_route(&detail, &mut pending_route, &mut class_route);
        add_dotnet_grpc_service(
            source_file,
            framework,
            line_number,
            &detail,
            group_route.as_deref(),
            builder,
        );
        add_dotnet_route(
            source_file,
            framework,
            line_number,
            &detail,
            class_route.as_deref(),
            pending_route.as_deref(),
            group_route.as_deref(),
            builder,
        );
    }
}

fn add_dotnet_grpc_service(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    group_route: Option<&str>,
    builder: &mut AttackSurfaceBuilder,
) {
    if !detail.to_ascii_lowercase().contains("mapgrpcservice<") {
        return;
    }
    let route = dotnet_chained_group_prefix(detail).or_else(|| group_route.map(str::to_string));
    let title = route
        .as_deref()
        .map(|route| format!("ANY {route}"))
        .unwrap_or_else(|| "gRPC service".to_string());
    builder.add(surface(
        AttackSurfaceKind::RpcHandler,
        source_file,
        framework.or(Some("ASP.NET Core")),
        line_number,
        &title,
        detail,
        Some("ANY"),
        route.as_deref(),
        Some("rpc_handler"),
        json!({ "source": "source_line", "detector": "dotnet.grpc-service" }),
    ));
}

fn add_dotnet_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    class_route: Option<&str>,
    action_route: Option<&str>,
    group_route: Option<&str>,
    builder: &mut AttackSurfaceBuilder,
) {
    let lower = detail.to_ascii_lowercase();
    let methods = dotnet_route_methods(&lower);
    if methods.is_empty() {
        return;
    }
    let Some(route) = dotnet_route_for_line(detail, class_route, action_route, group_route) else {
        return;
    };
    let (kind, boundary, detector) = dotnet_route_kind(&lower);
    for method in methods {
        builder.add(surface(
            kind,
            source_file,
            framework.or(Some("ASP.NET Core")),
            line_number,
            &format!("{method} {route}"),
            detail,
            Some(&method),
            Some(&route),
            Some(boundary),
            json!({ "source": "source_line", "detector": detector }),
        ));
    }
}

fn dotnet_route_kind(line: &str) -> (AttackSurfaceKind, &'static str, &'static str) {
    if line.contains("mapgraphql(") || line.contains("usegraphql(") {
        return (
            AttackSurfaceKind::RpcHandler,
            "remote_rpc",
            "dotnet.graphql",
        );
    }
    if line.contains("mapblazorhub(") {
        return (
            AttackSurfaceKind::RpcHandler,
            "remote_rpc",
            "dotnet.blazor-hub",
        );
    }
    if line.contains("maphub<") || line.contains("maphub(") {
        return (
            AttackSurfaceKind::RpcHandler,
            "remote_rpc",
            "dotnet.signalr-hub",
        );
    }
    (
        AttackSurfaceKind::HttpRoute,
        "public_http",
        "dotnet.aspnet-route",
    )
}

fn update_dotnet_class_route(
    line: &str,
    pending_route: &mut Option<String>,
    class_route: &mut Option<String>,
) {
    if let Some(route) = dotnet_route_attribute(line) {
        *pending_route = Some(route);
        return;
    }
    if line.contains(" class ") || line.starts_with("class ") {
        *class_route = pending_route.take();
        return;
    }
    if !line.is_empty() && !line.starts_with('[') {
        *pending_route = None;
    }
}

fn dotnet_route_for_line(
    line: &str,
    class_route: Option<&str>,
    action_route: Option<&str>,
    group_route: Option<&str>,
) -> Option<String> {
    if let Some(route) = dotnet_chained_group_route(line) {
        return Some(route);
    }
    if line.to_ascii_lowercase().contains("mapidentityapi") {
        return Some(group_route.unwrap_or("/identity").to_string());
    }
    let route = dotnet_route_path_for_line(line);
    let prefix = group_route.or(class_route);
    combine_dotnet_routes(prefix, route.as_deref().or(action_route))
}
