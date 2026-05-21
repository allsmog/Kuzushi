use super::super::common::*;
use super::super::*;

pub(super) fn emit_servlet_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    if !lower.contains("@webservlet") {
        return;
    }
    for route in servlet_route_paths(detail) {
        add_route(
            source_file,
            framework.or(Some("Servlet")),
            line_number,
            detail,
            "ANY",
            &route,
            "jvm.servlet-route",
            builder,
        );
    }
}

fn servlet_route_paths(detail: &str) -> Vec<String> {
    let mut routes = Vec::new();
    collect_quoted_routes(detail, '"', &mut routes);
    collect_quoted_routes(detail, '\'', &mut routes);
    routes
}

fn collect_quoted_routes(detail: &str, quote: char, routes: &mut Vec<String>) {
    let mut remaining = detail;
    while let Some(start) = remaining.find(quote) {
        let quoted_start = start + quote.len_utf8();
        let Some(end) = remaining[quoted_start..].find(quote) else {
            break;
        };
        let candidate = remaining[quoted_start..quoted_start + end].trim();
        if let Some(route) = servlet_route_path(candidate) {
            routes.push(route);
        }
        remaining = &remaining[quoted_start + end + quote.len_utf8()..];
    }
}

fn servlet_route_path(candidate: &str) -> Option<String> {
    backend_route_path(candidate).then(|| normalize_route_path(candidate))?
}
