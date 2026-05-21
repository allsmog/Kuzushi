use super::super::common::*;
use super::super::*;

pub(super) fn inspect_helidon_route_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    remember_helidon_scope(lower, state);
    remember_helidon_prefix(detail, lower, state);
    emit_helidon_route(source_file, framework, line_number, detail, lower, state, builder);
}

fn remember_helidon_scope(lower: &str, state: &mut RouteScanState) {
    if lower.contains("webserver.builder(") || lower.contains("routing.builder(") {
        state.helidon_seen = true;
    }
}

fn remember_helidon_prefix(detail: &str, lower: &str, state: &mut RouteScanState) {
    if state.helidon_seen && lower.contains(".register(") {
        state.helidon_prefix = first_quoted(detail).and_then(|route| normalize_route_path(&route));
    }
}

fn emit_helidon_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    if !state.helidon_seen {
        return;
    }
    let Some(method) = helidon_route_method(lower) else {
        return;
    };
    let Some(path) = first_quoted(detail).and_then(|route| normalize_route_path(&route)) else {
        return;
    };
    let route = join_route(state.helidon_prefix.as_deref(), &path);
    add_route(
        source_file,
        framework.or(Some("Helidon")),
        line_number,
        detail,
        method,
        &route,
        "jvm.helidon-route",
        builder,
    );
}

fn helidon_route_method(line: &str) -> Option<&'static str> {
    for (marker, method) in [
        (".get(", "GET"),
        (".post(", "POST"),
        (".put(", "PUT"),
        (".patch(", "PATCH"),
        (".delete(", "DELETE"),
        (".head(", "HEAD"),
        (".options(", "OPTIONS"),
        (".any(", "ANY"),
    ] {
        if line.contains(marker) {
            return Some(method);
        }
    }
    None
}
