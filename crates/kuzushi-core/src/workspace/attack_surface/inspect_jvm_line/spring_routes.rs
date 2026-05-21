use super::*;

pub(super) fn add_spring_routes(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    add_spring_route(source_file, framework, line_number, detail, lower, builder);
    add_spring_functional_route(source_file, framework, line_number, detail, lower, builder);
    add_spring_inferred_route(source_file, framework, line_number, detail, lower, builder);
}

fn add_spring_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let Some(method) = spring_route_method(lower) else {
        return;
    };
    let Some(route) = first_quoted(detail).filter(|route| backend_route_path(route)) else {
        return;
    };
    builder.add(surface(
        AttackSurfaceKind::HttpRoute,
        source_file,
        framework.or(Some("Spring")),
        line_number,
        &format!("{method} {route}"),
        detail,
        Some(method),
        Some(&route),
        Some("public_http"),
        json!({ "source": "source_line", "detector": "jvm.spring-route" }),
    ));
}

fn add_spring_functional_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let Some(method) = spring_functional_route_method(lower) else {
        return;
    };
    let Some(route) = first_quoted(detail).filter(|route| backend_route_path(route)) else {
        return;
    };
    builder.add(surface(
        AttackSurfaceKind::HttpRoute,
        source_file,
        framework.or(Some("Spring")),
        line_number,
        &format!("{method} {route}"),
        detail,
        Some(method),
        Some(&route),
        Some("public_http"),
        json!({ "source": "source_line", "detector": "jvm.spring-functional-route" }),
    ));
}

fn add_spring_inferred_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    add_spring_actuator_route(source_file, framework, line_number, detail, lower, builder);
    add_spring_openapi_route(source_file, framework, line_number, detail, lower, builder);
}

fn add_spring_actuator_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    if lower.contains("@endpoint(") {
        if let Some(id) = first_quoted(detail) {
            add_known_spring_route(
                source_file,
                framework,
                line_number,
                detail,
                &format!("/actuator/{id}"),
                "jvm.spring-actuator-route",
                builder,
            );
        }
    }
}

fn add_spring_openapi_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    lower: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    if lower.contains("groupedopenapi.builder") || lower.contains("new openapi()") {
        add_known_spring_route(
            source_file,
            framework,
            line_number,
            detail,
            "/v3/api-docs",
            "jvm.spring-openapi-route",
            builder,
        );
    }
    if lower.contains("swaggeruiconfigparameters") {
        add_known_spring_route(
            source_file,
            framework,
            line_number,
            detail,
            "/swagger-ui/index.html",
            "jvm.spring-openapi-route",
            builder,
        );
    }
}

fn add_known_spring_route(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    detail: &str,
    route: &str,
    detector: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    builder.add(surface(
        AttackSurfaceKind::HttpRoute,
        source_file,
        framework.or(Some("Spring")),
        line_number,
        &format!("GET {route}"),
        detail,
        Some("GET"),
        Some(route),
        Some("public_http"),
        json!({ "source": "source_line", "detector": detector }),
    ));
}

fn spring_route_method(line: &str) -> Option<&'static str> {
    if line.contains("@requestmapping") {
        return spring_request_mapping_method(line).or(Some("ANY"));
    }
    for (marker, method) in [
        ("@getmapping", "GET"),
        ("@postmapping", "POST"),
        ("@putmapping", "PUT"),
        ("@patchmapping", "PATCH"),
        ("@deletemapping", "DELETE"),
    ] {
        if line.contains(marker) {
            return Some(method);
        }
    }
    None
}

fn spring_functional_route_method(line: &str) -> Option<&'static str> {
    for (method, direct, predicate, builder) in [
        ("GET", "route(get(", "requestpredicates.get(", ".get("),
        ("POST", "route(post(", "requestpredicates.post(", ".post("),
        ("PUT", "route(put(", "requestpredicates.put(", ".put("),
        ("PATCH", "route(patch(", "requestpredicates.patch(", ".patch("),
        ("DELETE", "route(delete(", "requestpredicates.delete(", ".delete("),
        ("HEAD", "route(head(", "requestpredicates.head(", ".head("),
        ("OPTIONS", "route(options(", "requestpredicates.options(", ".options("),
    ] {
        if line.contains(direct) || line.contains(predicate) || is_route_builder_call(line, builder) {
            return Some(method);
        }
    }
    None
}

fn is_route_builder_call(line: &str, method_call: &str) -> bool {
    line.contains(method_call)
        && (line.contains("routerfunctions.route()")
            || line.contains("routerfunctions.route(")
            || line.contains(".androute("))
}

fn spring_request_mapping_method(line: &str) -> Option<&'static str> {
    for (needle, method) in [
        ("requestmethod.get", "GET"),
        ("requestmethod.post", "POST"),
        ("requestmethod.put", "PUT"),
        ("requestmethod.patch", "PATCH"),
        ("requestmethod.delete", "DELETE"),
    ] {
        if line.contains(needle) {
            return Some(method);
        }
    }
    None
}
