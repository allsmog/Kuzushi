use super::super::common::*;
use super::super::*;

pub(super) fn inspect_javalin_route_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    remember_javalin_scope(lower, state);
    remember_javalin_prefix(detail, lower, state);
    emit_javalin_route(
        source_file,
        framework,
        line_number,
        detail,
        lower,
        state,
        builder,
    );
}

fn remember_javalin_scope(lower: &str, state: &mut RouteScanState) {
    if lower.contains("javalin.create") {
        state.javalin_seen = true;
    }
}

fn remember_javalin_prefix(detail: &str, lower: &str, state: &mut RouteScanState) {
    if state.javalin_seen && lower.contains("path(") {
        state.javalin_prefix = first_quoted(detail).and_then(|route| normalize_route_path(&route));
    }
}

fn emit_javalin_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    let Some(method) = javalin_route_method(lower, state) else {
        return;
    };
    let Some(path) = first_quoted(detail).and_then(|route| normalize_route_path(&route)) else {
        return;
    };
    let route = join_route(state.javalin_prefix.as_deref(), &path);
    add_route(
        source_file,
        framework.or(Some("Javalin")),
        line_number,
        detail,
        method,
        &route,
        "jvm.javalin-route",
        builder,
    );
}

fn javalin_route_method(line: &str, state: &RouteScanState) -> Option<&'static str> {
    javalin_static_route_method(line, state).or_else(|| javalin_chained_route_method(line, state))
}

fn javalin_static_route_method(line: &str, state: &RouteScanState) -> Option<&'static str> {
    state.javalin_seen.then(|| route_method_call(line))?
}

fn javalin_chained_route_method(line: &str, state: &RouteScanState) -> Option<&'static str> {
    for (marker, method) in [
        (".get(", "GET"),
        (".post(", "POST"),
        (".put(", "PUT"),
        (".patch(", "PATCH"),
        (".delete(", "DELETE"),
        (".head(", "HEAD"),
        (".options(", "OPTIONS"),
        (".before(", "ANY"),
        (".after(", "ANY"),
    ] {
        if line.contains(marker) && can_use_chained_javalin_method(line, state) {
            return Some(method);
        }
    }
    None
}

fn can_use_chained_javalin_method(line: &str, state: &RouteScanState) -> bool {
    state.javalin_seen || line.contains("javalin")
}
