use super::super::common::*;
use super::super::*;

pub(super) fn inspect_vertx_route_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    remember_vertx_router_scope(lower, state);
    emit_vertx_route(
        source_file,
        framework,
        line_number,
        detail,
        lower,
        state,
        builder,
    );
}

fn remember_vertx_router_scope(lower: &str, state: &mut RouteScanState) {
    if lower.contains("router.router(") || lower.contains("router.router(vertx") {
        state.vertx_router_seen = true;
    }
}

fn emit_vertx_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    if !state.vertx_router_seen {
        return;
    }
    let Some(method) = vertx_route_method(lower) else {
        return;
    };
    let Some(route) = first_quoted(detail).and_then(|route| normalize_route_path(&route)) else {
        return;
    };
    add_route(
        source_file,
        framework.or(Some("Vert.x")),
        line_number,
        detail,
        method,
        &route,
        "jvm.vertx-route",
        builder,
    );
}

fn vertx_route_method(line: &str) -> Option<&'static str> {
    if line.contains(".route(") {
        return vertx_http_method_route(line).or(Some("ANY"));
    }
    for (marker, method) in [
        (".get(", "GET"),
        (".post(", "POST"),
        (".put(", "PUT"),
        (".patch(", "PATCH"),
        (".delete(", "DELETE"),
        (".head(", "HEAD"),
        (".options(", "OPTIONS"),
    ] {
        if line.contains(marker) {
            return Some(method);
        }
    }
    None
}

fn vertx_http_method_route(line: &str) -> Option<&'static str> {
    for (marker, method) in [
        ("httpmethod.get", "GET"),
        ("httpmethod.post", "POST"),
        ("httpmethod.put", "PUT"),
        ("httpmethod.patch", "PATCH"),
        ("httpmethod.delete", "DELETE"),
        ("httpmethod.head", "HEAD"),
        ("httpmethod.options", "OPTIONS"),
    ] {
        if line.contains(marker) {
            return Some(method);
        }
    }
    None
}
