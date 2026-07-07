use super::super::common::*;
use super::super::*;

pub(super) fn inspect_ktor_route_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    remember_ktor_scope(lower, state);
    remember_ktor_prefix(detail, lower, state);
    emit_ktor_route(
        source_file,
        framework,
        line_number,
        detail,
        lower,
        state,
        builder,
    );
}

fn remember_ktor_scope(lower: &str, state: &mut RouteScanState) {
    if lower.contains("routing") {
        state.ktor_routing = true;
    }
}

fn remember_ktor_prefix(detail: &str, lower: &str, state: &mut RouteScanState) {
    if state.ktor_routing && lower.trim_start().starts_with("route(") {
        state.ktor_prefix = first_quoted(detail).and_then(|route| normalize_route_path(&route));
    }
}

fn emit_ktor_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    if !state.ktor_routing {
        return;
    }
    let Some(method) = ktor_route_method(lower) else {
        return;
    };
    let route = ktor_route_path(detail, state);
    add_route(
        source_file,
        framework.or(Some("Ktor")),
        line_number,
        detail,
        method,
        &route,
        "jvm.ktor-route",
        builder,
    );
}

fn ktor_route_path(detail: &str, state: &RouteScanState) -> String {
    match first_quoted(detail).and_then(|route| normalize_route_path(&route)) {
        Some(path) => join_route(state.ktor_prefix.as_deref(), &path),
        None => state.ktor_prefix.clone().unwrap_or_else(|| "/".to_string()),
    }
}

fn ktor_route_method(line: &str) -> Option<&'static str> {
    route_method_call(line).or_else(|| ktor_block_route_method(line))
}

fn ktor_block_route_method(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    for (call, method) in [
        ("get", "GET"),
        ("post", "POST"),
        ("put", "PUT"),
        ("patch", "PATCH"),
        ("delete", "DELETE"),
        ("head", "HEAD"),
        ("options", "OPTIONS"),
    ] {
        if trimmed.strip_prefix(call).is_some_and(starts_block_route) {
            return Some(method);
        }
    }
    None
}

fn starts_block_route(remainder: &str) -> bool {
    remainder
        .trim_start()
        .chars()
        .next()
        .is_some_and(|next| next == '{')
}
