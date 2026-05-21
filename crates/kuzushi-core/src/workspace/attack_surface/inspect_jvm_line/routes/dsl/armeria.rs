use super::super::common::*;
use super::super::*;

pub(super) fn inspect_armeria_route_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    remember_armeria_scope(lower, state);
    emit_armeria_route(source_file, framework, line_number, detail, lower, state, builder);
}

fn remember_armeria_scope(lower: &str, state: &mut RouteScanState) {
    if lower.contains("server.builder(") || lower.contains("serverbuilder") {
        state.armeria_seen = true;
    }
}

fn emit_armeria_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    if !state.armeria_seen {
        return;
    }
    let Some(method) = armeria_route_method(lower) else {
        return;
    };
    let Some(route) = first_quoted(detail).and_then(|route| normalize_route_path(&route)) else {
        return;
    };
    add_route(
        source_file,
        framework.or(Some("Armeria")),
        line_number,
        detail,
        method,
        &route,
        "jvm.armeria-route",
        builder,
    );
}

fn armeria_route_method(line: &str) -> Option<&'static str> {
    if is_armeria_any_method_registration(line) {
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
        if line.contains(".route()") && line.contains(marker) {
            return Some(method);
        }
    }
    None
}

fn is_armeria_any_method_registration(line: &str) -> bool {
    is_armeria_service_registration(line) || is_armeria_route_path_registration(line)
}

fn is_armeria_service_registration(line: &str) -> bool {
    line.contains(".service(")
        || line.contains(".serviceunder(")
        || line.contains(".annotatedservice(")
}

fn is_armeria_route_path_registration(line: &str) -> bool {
    line.contains(".route()") && line.contains(".path(")
}
