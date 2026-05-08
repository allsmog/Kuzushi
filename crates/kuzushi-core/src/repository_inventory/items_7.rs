use super::prelude::*;
use super::*;

pub(crate) fn inspect_python_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    builder: &mut InventoryBuilder,
) {
    let trimmed = line.trim();
    if !trimmed.starts_with('@') {
        return;
    }
    for (method, marker, framework) in [
        ("ANY", ".route(", "Flask"),
        ("GET", ".get(", "FastAPI"),
        ("POST", ".post(", "FastAPI"),
        ("PUT", ".put(", "FastAPI"),
        ("PATCH", ".patch(", "FastAPI"),
        ("DELETE", ".delete(", "FastAPI"),
    ] {
        if let Some(route) = extract_quoted_after_marker(trimmed, marker) {
            let method = if method == "ANY" {
                python_route_methods(trimmed).unwrap_or_else(|| method.to_string())
            } else {
                method.to_string()
            };
            builder.add_route_controller(route_item(
                relative,
                line_number,
                &method,
                &route,
                framework,
                trim_detail(line),
            ));
        }
    }
}

pub(crate) fn inspect_go_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    builder: &mut InventoryBuilder,
) {
    for (method, marker, framework) in [
        ("ANY", "http.handlefunc(", "net/http"),
        ("ANY", ".handlefunc(", "net/http"),
        ("GET", ".get(", "Gin"),
        ("POST", ".post(", "Gin"),
        ("PUT", ".put(", "Gin"),
        ("PATCH", ".patch(", "Gin"),
        ("DELETE", ".delete(", "Gin"),
    ] {
        if let Some(route) = extract_quoted_after_marker_case_insensitive(line, marker) {
            builder.add_route_controller(route_item(
                relative,
                line_number,
                method,
                &route,
                framework,
                trim_detail(line),
            ));
        }
    }
}

pub(crate) fn inspect_rust_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    builder: &mut InventoryBuilder,
) {
    for (method, marker, framework) in [
        ("ANY", ".route(", "Axum"),
        ("GET", "#[get(", "Actix Web"),
        ("POST", "#[post(", "Actix Web"),
        ("PUT", "#[put(", "Actix Web"),
        ("PATCH", "#[patch(", "Actix Web"),
        ("DELETE", "#[delete(", "Actix Web"),
    ] {
        if let Some(route) = extract_quoted_after_marker_case_insensitive(line, marker) {
            builder.add_route_controller(route_item(
                relative,
                line_number,
                method,
                &route,
                framework,
                trim_detail(line),
            ));
        }
    }
}

pub(crate) fn inspect_controller_path(relative: &str, builder: &mut InventoryBuilder) {
    let lower = relative.to_ascii_lowercase();
    if lower.contains("/controllers/")
        || lower.contains("/controller/")
        || lower.contains("controller.")
        || lower.contains("/handlers/")
        || lower.contains("/routes/")
    {
        builder.add_route_controller(InventoryRouteController {
            kind: "controller".to_string(),
            path: relative.to_string(),
            line: None,
            method: None,
            route: None,
            framework: None,
            detail: "controller, route, or handler path".to_string(),
        });
    }
}
