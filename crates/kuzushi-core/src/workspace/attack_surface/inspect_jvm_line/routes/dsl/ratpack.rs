use super::super::common::*;
use super::super::*;

pub(super) fn inspect_ratpack_route_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    remember_ratpack_scope(lower, state);
    remember_ratpack_prefix(detail, lower, state);
    emit_ratpack_route(source_file, framework, line_number, detail, lower, state, builder);
}

fn remember_ratpack_scope(lower: &str, state: &mut RouteScanState) {
    if lower.contains("ratpackserver.start") || lower.contains("ratpackserver.of") {
        state.ratpack_seen = true;
    }
}

fn remember_ratpack_prefix(detail: &str, lower: &str, state: &mut RouteScanState) {
    if state.ratpack_seen && lower.contains(".prefix(") {
        state.ratpack_prefix = first_quoted(detail).and_then(|route| normalize_route_path(&route));
    }
}

fn emit_ratpack_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    if !state.ratpack_seen {
        return;
    }
    let Some(method) = ratpack_route_method(lower) else {
        return;
    };
    let Some(path) = first_quoted(detail).and_then(|route| normalize_route_path(&route)) else {
        return;
    };
    let route = join_route(state.ratpack_prefix.as_deref(), &path);
    add_route(
        source_file,
        framework.or(Some("Ratpack")),
        line_number,
        detail,
        method,
        &route,
        "jvm.ratpack-route",
        builder,
    );
}

fn ratpack_route_method(line: &str) -> Option<&'static str> {
    for (marker, method) in [
        (".get(", "GET"),
        (".post(", "POST"),
        (".put(", "PUT"),
        (".patch(", "PATCH"),
        (".delete(", "DELETE"),
        (".head(", "HEAD"),
        (".options(", "OPTIONS"),
        (".all(", "ANY"),
    ] {
        if line.contains(marker) {
            return Some(method);
        }
    }
    None
}
