use super::super::common::*;
use super::super::*;

pub(super) fn inspect_undertow_route_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    remember_undertow_scope(lower, state);
    emit_undertow_route(
        source_file,
        framework,
        line_number,
        detail,
        lower,
        state,
        builder,
    );
}

fn remember_undertow_scope(lower: &str, state: &mut RouteScanState) {
    if lower.contains("undertow.builder(")
        || lower.contains("handlers.path(")
        || lower.contains("handlers.routing(")
        || lower.contains("pathhandler")
        || lower.contains("routinghandler")
    {
        state.undertow_seen = true;
    }
}

fn emit_undertow_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    if !state.undertow_seen {
        return;
    }
    let Some(method) = undertow_route_method(lower) else {
        return;
    };
    let Some(route) = first_quoted(detail).and_then(|route| normalize_route_path(&route)) else {
        return;
    };
    add_route(
        source_file,
        framework.or(Some("Undertow")),
        line_number,
        detail,
        method,
        &route,
        "jvm.undertow-route",
        builder,
    );
}

fn undertow_route_method(line: &str) -> Option<&'static str> {
    if is_undertow_path_registration(line) {
        return Some("ANY");
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

fn is_undertow_path_registration(line: &str) -> bool {
    line.contains(".addexactpath(")
        || line.contains(".addprefixpath(")
        || line.contains(".addpath(")
}
