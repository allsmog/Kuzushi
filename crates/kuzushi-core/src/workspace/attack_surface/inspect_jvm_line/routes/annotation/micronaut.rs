use super::super::common::*;
use super::super::*;

pub(super) fn inspect_micronaut_route_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    remember_micronaut_prefix(detail, lower, state);
    emit_micronaut_route(
        source_file,
        framework,
        line_number,
        detail,
        lower,
        state,
        builder,
    );
}

fn remember_micronaut_prefix(detail: &str, lower: &str, state: &mut RouteScanState) {
    if lower.contains("@controller(") {
        state.micronaut_prefix =
            first_quoted(detail).and_then(|route| normalize_route_path(&route));
    }
}

fn emit_micronaut_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    let Some(method) = route_method_annotation(lower) else {
        return;
    };
    let route = micronaut_route_path(detail, state);
    add_route(
        source_file,
        framework.or(Some("Micronaut")),
        line_number,
        detail,
        method,
        &route,
        "jvm.micronaut-route",
        builder,
    );
}

fn micronaut_route_path(detail: &str, state: &RouteScanState) -> String {
    match first_quoted(detail).and_then(|route| normalize_route_path(&route)) {
        Some(path) => join_route(state.micronaut_prefix.as_deref(), &path),
        None => state
            .micronaut_prefix
            .clone()
            .unwrap_or_else(|| "/".to_string()),
    }
}
