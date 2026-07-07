use super::super::common::*;
use super::super::*;

pub(super) fn inspect_jooby_route_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    remember_jooby_scope(lower, state);
    remember_jooby_prefix(detail, lower, state);
    emit_jooby_route(
        source_file,
        framework,
        line_number,
        detail,
        lower,
        state,
        builder,
    );
}

fn remember_jooby_scope(lower: &str, state: &mut RouteScanState) {
    if lower.contains("extends jooby")
        || lower.contains("jooby.create")
        || lower.contains("new jooby")
    {
        state.jooby_seen = true;
    }
}

fn remember_jooby_prefix(detail: &str, lower: &str, state: &mut RouteScanState) {
    if state.jooby_seen && lower.trim_start().starts_with("path(") {
        state.jooby_prefix = first_quoted(detail).and_then(|route| normalize_route_path(&route));
    }
}

fn emit_jooby_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    if !state.jooby_seen {
        return;
    }
    let Some(method) = jooby_route_method(lower) else {
        return;
    };
    let Some(path) = first_quoted(detail).and_then(|route| normalize_route_path(&route)) else {
        return;
    };
    let route = join_route(state.jooby_prefix.as_deref(), &path);
    add_route(
        source_file,
        framework.or(Some("Jooby")),
        line_number,
        detail,
        method,
        &route,
        "jvm.jooby-route",
        builder,
    );
}

fn jooby_route_method(line: &str) -> Option<&'static str> {
    route_method_call(line).or_else(|| line.trim_start().starts_with("all(").then_some("ANY"))
}
