use super::*;

#[derive(Default)]
pub(super) struct RouteScanState {
    pub(super) jaxrs_class_prefix: Option<String>,
    pub(super) armeria_seen: bool,
    pub(super) helidon_prefix: Option<String>,
    pub(super) helidon_seen: bool,
    pub(super) javalin_prefix: Option<String>,
    pub(super) javalin_seen: bool,
    pub(super) jooby_seen: bool,
    pub(super) jooby_prefix: Option<String>,
    pub(super) ktor_prefix: Option<String>,
    pub(super) ktor_routing: bool,
    pub(super) micronaut_prefix: Option<String>,
    pub(super) pending_jaxrs_path: Option<String>,
    pub(super) pending_jaxrs_method: Option<&'static str>,
    pub(super) ratpack_prefix: Option<String>,
    pub(super) ratpack_seen: bool,
    pub(super) spark_static_routes: bool,
    pub(super) undertow_seen: bool,
    pub(super) vertx_router_seen: bool,
}

pub(super) fn add_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    method: &str,
    route: &str,
    detector: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    builder.add(surface(
        AttackSurfaceKind::HttpRoute,
        source_file,
        framework,
        line_number,
        &format!("{method} {route}"),
        detail,
        Some(method),
        Some(route),
        Some("public_http"),
        json!({ "source": "source_file", "detector": detector }),
    ));
}

pub(super) fn route_method_annotation(line: &str) -> Option<&'static str> {
    for (annotation, method) in [
        ("get", "GET"),
        ("post", "POST"),
        ("put", "PUT"),
        ("patch", "PATCH"),
        ("delete", "DELETE"),
        ("head", "HEAD"),
        ("options", "OPTIONS"),
    ] {
        if has_http_annotation(line, annotation) {
            return Some(method);
        }
    }
    None
}

pub(super) fn route_method_call(line: &str) -> Option<&'static str> {
    let trimmed = line.trim_start();
    for (call, method) in [
        ("get(", "GET"),
        ("post(", "POST"),
        ("put(", "PUT"),
        ("patch(", "PATCH"),
        ("delete(", "DELETE"),
        ("head(", "HEAD"),
        ("options(", "OPTIONS"),
    ] {
        if trimmed.starts_with(call) {
            return Some(method);
        }
    }
    None
}

pub(super) fn normalize_route_path(route: &str) -> Option<String> {
    let route = route.trim().trim_matches('/');
    (!route.is_empty()).then(|| format!("/{route}"))
}

pub(super) fn join_route(prefix: Option<&str>, path: &str) -> String {
    match prefix {
        Some(prefix) if prefix != path => format!(
            "{}/{}",
            prefix.trim_end_matches('/'),
            path.trim_start_matches('/')
        ),
        _ => path.to_string(),
    }
}

fn has_http_annotation(line: &str, annotation: &str) -> bool {
    let marker = format!("@{annotation}");
    let Some(start) = line.find(&marker) else {
        return false;
    };
    line[start + marker.len()..]
        .chars()
        .next()
        .is_none_or(|next| next.is_whitespace() || next == '(')
}
