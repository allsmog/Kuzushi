use super::super::common::*;
use super::super::*;

pub(super) fn inspect_jaxrs_route_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    remember_jaxrs_path(detail, lower, state);
    remember_jaxrs_class_prefix(lower, state);
    remember_jaxrs_method(lower, state);
    emit_pending_jaxrs_route(source_file, framework, line_number, detail, lower, state, builder);
}

fn remember_jaxrs_path(detail: &str, lower: &str, state: &mut RouteScanState) {
    if lower.contains("@path(") {
        state.pending_jaxrs_path =
            first_quoted(detail).and_then(|route| normalize_route_path(&route));
    }
}

fn remember_jaxrs_class_prefix(lower: &str, state: &mut RouteScanState) {
    if state.pending_jaxrs_method.is_none() && is_jaxrs_type_declaration(lower) {
        state.jaxrs_class_prefix = state.pending_jaxrs_path.take();
    }
}

fn remember_jaxrs_method(lower: &str, state: &mut RouteScanState) {
    if let Some(method) = route_method_annotation(lower) {
        state.pending_jaxrs_method = Some(method);
    }
}

fn emit_pending_jaxrs_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    state: &mut RouteScanState,
    builder: &mut AttackSurfaceBuilder,
) {
    if state.pending_jaxrs_path.is_none() && !is_jaxrs_handler_declaration(lower) {
        return;
    }
    let Some(method) = state.pending_jaxrs_method.take() else {
        return;
    };
    let route = state
        .pending_jaxrs_path
        .take()
        .or_else(|| state.jaxrs_class_prefix.clone())
        .map(|path| join_route(state.jaxrs_class_prefix.as_deref(), &path));
    if let Some(route) = route {
        add_route(
            source_file,
            framework.or(Some("JAX-RS")),
            line_number,
            detail,
            method,
            &route,
            "jvm.jaxrs-route",
            builder,
        );
    }
}

fn is_jaxrs_type_declaration(line: &str) -> bool {
    line.contains(" class ")
        || line.starts_with("class ")
        || line.contains(" interface ")
        || line.starts_with("interface ")
        || line.contains(" record ")
        || line.starts_with("record ")
}

fn is_jaxrs_handler_declaration(line: &str) -> bool {
    line.contains('(') && !line.trim_start().starts_with('@')
}
