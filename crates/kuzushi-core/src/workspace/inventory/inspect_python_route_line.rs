use super::*;

pub(crate) fn inspect_python_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    let trimmed = line.trim();
    if is_sanic_source(text) {
        inspect_sanic_route(relative, line_number, trimmed, builder);
    } else {
        inspect_python_decorator_route(relative, line_number, trimmed, builder);
    }
    inspect_bottle_route(relative, line_number, trimmed, text, builder);
    inspect_falcon_route(relative, line_number, trimmed, text, builder);
    inspect_flask_add_url_rule(relative, line_number, trimmed, builder);
    inspect_litestar_route(relative, line_number, trimmed, text, builder);
    inspect_pyramid_route(relative, line_number, trimmed, text, builder);
    inspect_starlette_route(relative, line_number, trimmed, text, builder);
    inspect_aiohttp_route(relative, line_number, trimmed, text, builder);
    inspect_tornado_route(relative, line_number, trimmed, text, builder);
    inspect_django_urlpattern(relative, line_number, trimmed, builder);
}

fn inspect_python_decorator_route(
    relative: &str,
    line_number: u32,
    trimmed: &str,
    builder: &mut InventoryBuilder,
) {
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
        ("ANY", ".api_route(", "FastAPI"),
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
                trim_detail(trimmed),
            ));
        }
    }
}

fn inspect_sanic_route(
    relative: &str,
    line_number: u32,
    trimmed: &str,
    builder: &mut InventoryBuilder,
) {
    if !trimmed.starts_with('@') {
        return;
    }
    let Some((method, route)) = sanic_decorator_route(trimmed) else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        method,
        &route,
        "Sanic",
        trim_detail(trimmed),
    ));
}

fn is_sanic_source(text: &str) -> bool {
    text.to_ascii_lowercase().contains("sanic")
}

fn sanic_decorator_route(line: &str) -> Option<(&'static str, String)> {
    for (method, marker) in [
        ("GET", ".get("),
        ("POST", ".post("),
        ("PUT", ".put("),
        ("PATCH", ".patch("),
        ("DELETE", ".delete("),
    ] {
        if let Some(route) = extract_quoted_after_marker_case_insensitive(line, marker) {
            return Some((method, route));
        }
    }
    let route = extract_quoted_after_marker_case_insensitive(line, ".route(")?;
    Some((sanic_route_method(line), route))
}

fn sanic_route_method(line: &str) -> &'static str {
    bottle_route_method(line)
}

fn inspect_bottle_route(
    relative: &str,
    line_number: u32,
    trimmed: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    if !text.to_ascii_lowercase().contains("bottle") {
        return;
    }
    let Some((method, route)) = bottle_decorator_route(trimmed) else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        method,
        &route,
        "Bottle",
        trim_detail(trimmed),
    ));
}

fn bottle_decorator_route(line: &str) -> Option<(&'static str, String)> {
    for (method, marker) in [
        ("GET", "@get("),
        ("POST", "@post("),
        ("PUT", "@put("),
        ("PATCH", "@patch("),
        ("DELETE", "@delete("),
    ] {
        if let Some(route) = extract_quoted_after_marker_case_insensitive(line, marker) {
            return Some((method, route));
        }
    }
    bottle_any_route(line)
}

fn bottle_any_route(line: &str) -> Option<(&'static str, String)> {
    let route = extract_quoted_after_marker_case_insensitive(line, "@route(")?;
    Some((bottle_route_method(line), route))
}

fn bottle_route_method(line: &str) -> &'static str {
    let lower = line.to_ascii_lowercase();
    for (needle, method) in [
        ("'post'", "POST"),
        ("\"post\"", "POST"),
        ("'put'", "PUT"),
        ("\"put\"", "PUT"),
        ("'patch'", "PATCH"),
        ("\"patch\"", "PATCH"),
        ("'delete'", "DELETE"),
        ("\"delete\"", "DELETE"),
        ("'get'", "GET"),
        ("\"get\"", "GET"),
    ] {
        if lower.contains(needle) {
            return method;
        }
    }
    "ANY"
}

fn inspect_falcon_route(
    relative: &str,
    line_number: u32,
    trimmed: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    if !text.to_ascii_lowercase().contains("falcon") {
        return;
    }
    let Some(route) = extract_quoted_after_marker_case_insensitive(trimmed, ".add_route(") else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        falcon_route_method(text),
        &route,
        "Falcon",
        trim_detail(trimmed),
    ));
}

fn inspect_litestar_route(
    relative: &str,
    line_number: u32,
    trimmed: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    if !is_litestar_source(text) {
        return;
    }
    let Some((method, route)) = litestar_decorator_route(trimmed) else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        method,
        &route,
        "Litestar",
        trim_detail(trimmed),
    ));
}

fn is_litestar_source(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("litestar") || lower.contains("starlite")
}

fn litestar_decorator_route(line: &str) -> Option<(&'static str, String)> {
    for (method, marker) in [
        ("GET", "@get("),
        ("POST", "@post("),
        ("PUT", "@put("),
        ("PATCH", "@patch("),
        ("DELETE", "@delete("),
    ] {
        if let Some(route) = extract_quoted_after_marker_case_insensitive(line, marker) {
            return Some((method, route));
        }
    }
    None
}

fn falcon_route_method(text: &str) -> &'static str {
    let lower = text.to_ascii_lowercase();
    for (needle, method) in [
        ("def on_post(", "POST"),
        ("def on_put(", "PUT"),
        ("def on_patch(", "PATCH"),
        ("def on_delete(", "DELETE"),
        ("def on_get(", "GET"),
    ] {
        if lower.contains(needle) {
            return method;
        }
    }
    "ANY"
}

fn inspect_flask_add_url_rule(
    relative: &str,
    line_number: u32,
    trimmed: &str,
    builder: &mut InventoryBuilder,
) {
    let Some(route) = extract_quoted_after_marker_case_insensitive(trimmed, ".add_url_rule(")
    else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        &python_route_methods(trimmed).unwrap_or_else(|| "ANY".to_string()),
        &route,
        "Flask",
        trim_detail(trimmed),
    ));
}

fn inspect_pyramid_route(
    relative: &str,
    line_number: u32,
    trimmed: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    if !text.to_ascii_lowercase().contains("pyramid") {
        return;
    }
    let Some(route) = pyramid_route_path(trimmed) else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        pyramid_route_method(trimmed).unwrap_or("ANY"),
        &route,
        "Pyramid",
        trim_detail(trimmed),
    ));
}

fn pyramid_route_path(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let marker = ".add_route(";
    let index = lower.find(marker)? + marker.len();
    let mut args = line[index..].split(',');
    args.next()?;
    extract_first_quoted(args.next()?).filter(|route| route.starts_with('/'))
}

fn pyramid_route_method(line: &str) -> Option<&'static str> {
    let lower = line.to_ascii_lowercase();
    let index = lower.find("request_method")?;
    let method = extract_first_quoted(&line[index..])?.to_ascii_uppercase();
    aiohttp_method(&method)
}

fn inspect_starlette_route(
    relative: &str,
    line_number: u32,
    trimmed: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    if !text.to_ascii_lowercase().contains("starlette") {
        return;
    }
    let Some(route) = extract_quoted_after_marker_case_insensitive(trimmed, "route(") else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        &python_route_methods(trimmed).unwrap_or_else(|| "ANY".to_string()),
        &route,
        "Starlette",
        trim_detail(trimmed),
    ));
}

fn inspect_aiohttp_route(
    relative: &str,
    line_number: u32,
    trimmed: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    if !text.to_ascii_lowercase().contains("aiohttp") {
        return;
    }
    if let Some((method, route)) = aiohttp_add_route(trimmed) {
        add_aiohttp_route(relative, line_number, trimmed, builder, method, &route);
        return;
    }
    inspect_aiohttp_method_routes(relative, line_number, trimmed, builder);
}

fn inspect_aiohttp_method_routes(
    relative: &str,
    line_number: u32,
    trimmed: &str,
    builder: &mut InventoryBuilder,
) {
    for (method, marker) in [
        ("GET", ".add_get("),
        ("POST", ".add_post("),
        ("PUT", ".add_put("),
        ("PATCH", ".add_patch("),
        ("DELETE", ".add_delete("),
        ("GET", "web.get("),
        ("POST", "web.post("),
        ("PUT", "web.put("),
        ("PATCH", "web.patch("),
        ("DELETE", "web.delete("),
    ] {
        if let Some(route) = extract_quoted_after_marker_case_insensitive(trimmed, marker) {
            add_aiohttp_route(relative, line_number, trimmed, builder, method, &route);
        }
    }
}

fn add_aiohttp_route(
    relative: &str,
    line_number: u32,
    trimmed: &str,
    builder: &mut InventoryBuilder,
    method: &str,
    route: &str,
) {
    builder.add_route_controller(route_item(
        relative,
        line_number,
        method,
        route,
        "aiohttp",
        trim_detail(trimmed),
    ));
}

fn aiohttp_add_route(line: &str) -> Option<(&'static str, String)> {
    let lower = line.to_ascii_lowercase();
    let marker = ".add_route(";
    let index = lower.find(marker)? + marker.len();
    let mut args = line[index..].split(',');
    let method = extract_first_quoted(args.next()?)?.to_ascii_uppercase();
    let route = extract_first_quoted(args.next()?)?;
    aiohttp_method(&method).map(|method| (method, route))
}

fn aiohttp_method(method: &str) -> Option<&'static str> {
    match method {
        "GET" => Some("GET"),
        "POST" => Some("POST"),
        "PUT" => Some("PUT"),
        "PATCH" => Some("PATCH"),
        "DELETE" => Some("DELETE"),
        "OPTIONS" => Some("OPTIONS"),
        "HEAD" => Some("HEAD"),
        _ => None,
    }
}

fn inspect_tornado_route(
    relative: &str,
    line_number: u32,
    trimmed: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    if !text.to_ascii_lowercase().contains("tornado") {
        return;
    }
    let Some(route) = tornado_route_tuple(trimmed) else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        tornado_route_method(text),
        &route,
        "Tornado",
        trim_detail(trimmed),
    ));
}

fn tornado_route_tuple(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if !(trimmed.starts_with("(r") || trimmed.starts_with("(\"") || trimmed.starts_with("('")) {
        return None;
    }
    extract_first_quoted(trimmed).filter(|route| route.starts_with('/'))
}

fn tornado_route_method(text: &str) -> &'static str {
    let lower = text.to_ascii_lowercase();
    for (needle, method) in [
        ("def post(", "POST"),
        ("def put(", "PUT"),
        ("def patch(", "PATCH"),
        ("def delete(", "DELETE"),
        ("def get(", "GET"),
    ] {
        if lower.contains(needle) {
            return method;
        }
    }
    "ANY"
}

fn inspect_django_urlpattern(
    relative: &str,
    line_number: u32,
    trimmed: &str,
    builder: &mut InventoryBuilder,
) {
    let Some(marker) = django_route_marker(trimmed) else {
        return;
    };
    let Some(route) = extract_quoted_after_marker_case_insensitive(trimmed, marker) else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        django_urlpattern_method(trimmed),
        &django_route_path(&route),
        "Django",
        trim_detail(trimmed),
    ));
}

fn django_route_marker(line: &str) -> Option<&'static str> {
    let lower = line.to_ascii_lowercase();
    ["re_path(", "path("]
        .into_iter()
        .find(|marker| lower.contains(marker))
}

fn django_route_path(route: &str) -> String {
    if route.starts_with('/') {
        route.to_string()
    } else {
        format!("/{route}")
    }
}

fn django_urlpattern_method(line: &str) -> &'static str {
    let lower = line.to_ascii_lowercase();
    for (needle, method) in [
        ("'get'", "GET"),
        ("\"get\"", "GET"),
        ("'post'", "POST"),
        ("\"post\"", "POST"),
        ("'put'", "PUT"),
        ("\"put\"", "PUT"),
        ("'patch'", "PATCH"),
        ("\"patch\"", "PATCH"),
        ("'delete'", "DELETE"),
        ("\"delete\"", "DELETE"),
        ("'options'", "OPTIONS"),
        ("\"options\"", "OPTIONS"),
        ("'head'", "HEAD"),
        ("\"head\"", "HEAD"),
    ] {
        if lower.contains(needle) {
            return method;
        }
    }
    "ANY"
}

pub(crate) fn inspect_go_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    let method_route_framework = go_method_route_framework(text);
    for (method, marker, framework) in [
        ("ANY", "http.handlefunc(", "net/http"),
        ("ANY", ".handlefunc(", "net/http"),
        ("GET", ".get(", method_route_framework),
        ("POST", ".post(", method_route_framework),
        ("PUT", ".put(", method_route_framework),
        ("PATCH", ".patch(", method_route_framework),
        ("DELETE", ".delete(", method_route_framework),
    ] {
        if let Some(route) = extract_quoted_after_marker_case_insensitive(line, marker) {
            if framework != "net/http" && !route.starts_with('/') {
                continue;
            }
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

fn go_method_route_framework(text: &str) -> &'static str {
    let lower = text.to_ascii_lowercase();
    if contains_any(&lower, &["github.com/gofiber/fiber", "fiber.new("]) {
        "Fiber"
    } else if contains_any(&lower, &["github.com/labstack/echo", "echo.new("]) {
        "Echo"
    } else if contains_any(&lower, &["github.com/go-chi/chi", "chi.newrouter("]) {
        "Chi"
    } else {
        "Gin"
    }
}

pub(crate) fn inspect_rust_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    inspect_warp_route_line(relative, line_number, line, builder);
    let attribute_framework = rust_attribute_route_framework(text);
    for (method, marker, framework) in [
        ("ANY", ".route(", "Axum"),
        ("GET", "#[get(", attribute_framework),
        ("POST", "#[post(", attribute_framework),
        ("PUT", "#[put(", attribute_framework),
        ("PATCH", "#[patch(", attribute_framework),
        ("DELETE", "#[delete(", attribute_framework),
    ] {
        if let Some(route) = extract_quoted_after_marker_case_insensitive(line, marker) {
            if !rust_route_path(&route) {
                continue;
            }
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

fn inspect_warp_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    builder: &mut InventoryBuilder,
) {
    let Some(route) = warp_macro_route(line) else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        warp_method(line),
        &route,
        "Warp",
        trim_detail(line),
    ));
}

fn warp_macro_route(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let start = lower.find("path!(")? + "path!(".len();
    let end = line[start..].find(')')? + start;
    let segments = line[start..end]
        .split('/')
        .filter_map(extract_first_quoted)
        .collect::<Vec<_>>();
    (!segments.is_empty()).then(|| format!("/{}", segments.join("/")))
}

fn warp_method(line: &str) -> &'static str {
    let lower = line.to_ascii_lowercase();
    for (needle, method) in [
        ("warp::get()", "GET"),
        ("warp::post()", "POST"),
        ("warp::put()", "PUT"),
        ("warp::patch()", "PATCH"),
        ("warp::delete()", "DELETE"),
    ] {
        if lower.contains(needle) {
            return method;
        }
    }
    "ANY"
}

fn rust_attribute_route_framework(text: &str) -> &'static str {
    let lower = text.to_ascii_lowercase();
    if contains_any(&lower, &["rocket::", "use rocket", "#[launch]"]) {
        "Rocket"
    } else {
        "Actix Web"
    }
}

fn rust_route_path(route: &str) -> bool {
    route.starts_with('/') || route == "*"
}

pub(crate) fn inspect_jvm_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    _text: &str,
    builder: &mut InventoryBuilder,
) {
    let lower = line.to_ascii_lowercase();
    let Some(method) = jvm_route_method(&lower) else {
        return;
    };
    let Some(route) = extract_first_quoted(line).filter(|route| backend_route_path(route)) else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        method,
        &route,
        "Spring",
        trim_detail(line),
    ));
}

pub(crate) fn inspect_dotnet_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    let lower = line.to_ascii_lowercase();
    let Some(method) = dotnet_route_method(&lower) else {
        return;
    };
    let Some(route) = dotnet_route_for_line(line, text, line_number) else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        &method,
        &route,
        "ASP.NET Core",
        trim_detail(line),
    ));
}

fn dotnet_route_for_line(line: &str, text: &str, line_number: u32) -> Option<String> {
    if let Some(route) = dotnet_chained_group_route(line) {
        return Some(route);
    }
    let context = dotnet_route_context(text, line, line_number);
    if line.to_ascii_lowercase().contains("mapidentityapi") {
        return Some(context.group_route.unwrap_or_else(|| "/identity".to_string()));
    }
    let route = dotnet_route_path_for_line(line);
    let action_route = route.as_deref().or(context.action_route.as_deref());
    let prefix = context.group_route.as_deref().or(context.class_route.as_deref());
    combine_dotnet_routes(prefix, action_route)
}

fn dotnet_route_path_for_line(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    if lower.contains("mapblazorhub(") {
        return Some(dotnet_blazor_hub_route(line));
    }
    if is_dotnet_attribute_route_line(&lower) {
        return dotnet_attribute_route(line, &lower);
    }
    if let Some(route) = dotnet_conventional_route(line, &lower) {
        return Some(route);
    }
    extract_first_quoted(line).and_then(dotnet_route_path)
}

fn dotnet_blazor_hub_route(line: &str) -> String {
    extract_first_quoted(line)
        .and_then(dotnet_route_path)
        .unwrap_or_else(|| "/_blazor".to_string())
}

fn dotnet_conventional_route(line: &str, lower: &str) -> Option<String> {
    if lower.contains("mapdefaultcontrollerroute(") {
        return Some("/{controller=Home}/{action=Index}/{id?}".to_string());
    }
    if let Some(route) = dotnet_page_or_document_route(line, lower) {
        return Some(route);
    }
    if let Some(route) = dotnet_fallback_or_proxy_route(line, lower) {
        return Some(route);
    }
    dotnet_controller_route(line, lower)
}

fn dotnet_fallback_or_proxy_route(line: &str, lower: &str) -> Option<String> {
    if lower.contains("mapfallbacktofile(") || lower.contains("mapfallbacktopage(") {
        return Some("*".to_string());
    }
    if lower.contains("mapreverseproxy(") {
        return Some(dotnet_defaultable_route(line, "/{**proxy}"));
    }
    if lower.contains("mapforwarder(") {
        return extract_first_quoted(line).and_then(dotnet_route_path);
    }
    dotnet_fallback_controller_route(line, lower)
}

fn dotnet_fallback_controller_route(line: &str, lower: &str) -> Option<String> {
    if !lower.contains("mapfallbacktocontroller(")
        && !lower.contains("mapfallbacktoareacontroller(")
    {
        return None;
    }
    dotnet_quoted_values(line)
        .into_iter()
        .find_map(dotnet_fallback_controller_path)
        .or_else(|| Some("*".to_string()))
}

fn dotnet_fallback_controller_path(value: String) -> Option<String> {
    let value = value.trim();
    if !(value.contains('*') || value.starts_with('/') || starts_with_route_parameter(value)) {
        return None;
    }
    dotnet_route_path(value.to_string())
}

fn starts_with_route_parameter(value: &str) -> bool {
    value.as_bytes().first() == Some(&123)
}

fn dotnet_controller_route(line: &str, lower: &str) -> Option<String> {
    if let Some(route) = dotnet_dynamic_route(line, lower) {
        return Some(route);
    }
    if lower.contains("mapcontrollers(") {
        return Some("/{controller}/{action}".to_string());
    }
    if lower.contains("mapcontrollerroute(") || lower.contains("mapareacontrollerroute(") {
        return dotnet_named_argument_route(line, "pattern").or_else(|| dotnet_last_quoted_route(line));
    }
    None
}

fn dotnet_dynamic_route(line: &str, lower: &str) -> Option<String> {
    if !lower.contains("mapdynamiccontrollerroute") && !lower.contains("mapdynamicpageroute") {
        return None;
    }
    dotnet_quoted_values(line).into_iter().find_map(dotnet_route_path)
}

fn dotnet_last_quoted_route(line: &str) -> Option<String> {
    dotnet_quoted_values(line)
        .into_iter()
        .rev()
        .find_map(dotnet_route_path)
}

fn dotnet_http_attribute_route(line: &str) -> Option<String> {
    if let Some(route) = dotnet_named_argument_route(line, "route") {
        return Some(route);
    }
    if let Some(route) = dotnet_named_argument_route(line, "template") {
        return Some(route);
    }
    dotnet_positional_attribute_route(line)
}

fn dotnet_positional_attribute_route(line: &str) -> Option<String> {
    let open = line.find('(')?;
    let before_quote = line[open + 1..].split('"').next().unwrap_or_default();
    if before_quote.contains('=') {
        return None;
    }
    extract_first_quoted(line).and_then(dotnet_route_path)
}

fn dotnet_attribute_route(line: &str, lower: &str) -> Option<String> {
    if lower.contains("[acceptverbs(") {
        return dotnet_named_argument_route(line, "route");
    }
    if lower.contains("[http") {
        return dotnet_http_attribute_route(line);
    }
    None
}

fn is_dotnet_attribute_route_line(lower: &str) -> bool {
    lower.contains("[acceptverbs(") || lower.contains("[http")
}

fn dotnet_page_or_document_route(line: &str, lower: &str) -> Option<String> {
    if let Some(route) = dotnet_page_or_openapi_route(line, lower) {
        return Some(route);
    }
    dotnet_swagger_or_graphql_route(line, lower)
}

fn dotnet_page_or_openapi_route(line: &str, lower: &str) -> Option<String> {
    if let Some(route) = dotnet_razor_page_route(line, lower) {
        return Some(route);
    }
    if let Some(route) = dotnet_asset_or_metrics_route(line, lower) {
        return Some(route);
    }
    dotnet_openapi_route(line, lower)
}

fn dotnet_razor_page_route(line: &str, lower: &str) -> Option<String> {
    if lower.contains("maprazorpages(") {
        return Some("/{page}".to_string());
    }
    if lower.contains("mappageroute(") || lower.contains("mapareapageroute(") {
        return dotnet_last_quoted_route(line);
    }
    lower
        .contains("maprazorcomponents")
        .then(|| dotnet_defaultable_route(line, "/{component}"))
}

fn dotnet_asset_or_metrics_route(line: &str, lower: &str) -> Option<String> {
    if lower.contains("mapmetrics(") || lower.contains("mapprometheusscrapingendpoint(") {
        return Some(dotnet_defaultable_route(line, "/metrics"));
    }
    if lower.contains("mapshortcircuit(") {
        return extract_first_quoted(line).and_then(dotnet_route_path);
    }
    if lower.contains("mapstaticassets(") {
        return Some(dotnet_defaultable_route(line, "/{staticAsset}"));
    }
    None
}

fn dotnet_openapi_route(line: &str, lower: &str) -> Option<String> {
    lower.contains("mapopenapi(").then(|| {
        dotnet_defaultable_route(line, "/openapi/{documentName}.json")
    })
}

fn dotnet_swagger_or_graphql_route(line: &str, lower: &str) -> Option<String> {
    if lower.contains("mapswagger(") || lower.contains("useswagger(") {
        return Some(dotnet_swagger_route(line));
    }
    if lower.contains("mapgraphql(") || lower.contains("usegraphql(") {
        return Some(dotnet_graphql_route(line));
    }
    None
}

fn dotnet_swagger_route(line: &str) -> String {
    dotnet_defaultable_route(line, "/swagger/{documentName}/swagger.json")
}

fn dotnet_graphql_route(line: &str) -> String {
    dotnet_defaultable_route(line, "/graphql")
}

fn dotnet_defaultable_route(line: &str, default: &str) -> String {
    extract_first_quoted(line)
        .and_then(dotnet_route_path)
        .unwrap_or_else(|| default.to_string())
}

fn dotnet_named_argument_route(line: &str, name: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let index = dotnet_named_argument_value_index(&lower, name)?;
    extract_first_quoted(&line[index..]).and_then(dotnet_route_path)
}

fn dotnet_named_argument_value_index(lower: &str, name: &str) -> Option<usize> {
    let index = lower.find(name)?;
    let tail_start = index + name.len();
    let trimmed_start = lower[tail_start..].find(|character: char| !character.is_whitespace())?;
    let separator = tail_start + trimmed_start;
    matches!(lower.as_bytes().get(separator), Some(b':' | b'=')).then_some(separator + 1)
}

fn dotnet_chained_group_route(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    if !lower.contains(".mapgroup(") || !lower.contains(").map") {
        return None;
    }
    let mut route_segments = dotnet_chained_group_prefix_segments(line, &lower)?;
    route_segments.push(dotnet_chained_endpoint_route(line, &lower)?);
    Some(join_dotnet_route_segments(&route_segments))
}

fn dotnet_chained_group_prefix_segments(line: &str, lower: &str) -> Option<Vec<String>> {
    let group_count = lower.matches(".mapgroup(").count();
    let segments = dotnet_quoted_values(line)
        .into_iter()
        .take(group_count)
        .map(dotnet_route_path)
        .collect::<Option<Vec<_>>>()?;
    (segments.len() == group_count).then_some(segments)
}

fn dotnet_chained_endpoint_route(line: &str, lower: &str) -> Option<String> {
    let endpoint = dotnet_chained_endpoint_slice(line, lower)?;
    if endpoint.to_ascii_lowercase().contains("mapidentityapi") {
        return Some(String::new());
    }
    dotnet_route_path_for_line(endpoint)
}

fn dotnet_chained_endpoint_slice<'a>(line: &'a str, lower: &str) -> Option<&'a str> {
    let index = lower.rfind(".map")?;
    if lower[index..].starts_with(".mapgroup(") {
        return None;
    }
    Some(&line[index..])
}

fn join_dotnet_route_segments(segments: &[String]) -> String {
    let mut joined = segments.first().cloned().unwrap_or_default();
    for segment in &segments[1..] {
        joined = join_dotnet_routes(&joined, segment);
    }
    joined
}

struct DotnetRouteContext {
    class_route: Option<String>,
    action_route: Option<String>,
    group_route: Option<String>,
}

fn dotnet_route_context(text: &str, line: &str, line_number: u32) -> DotnetRouteContext {
    let mut pending_route = None;
    let mut class_route = None;
    let mut route_groups = Vec::new();
    for line in text.lines().take(line_number.saturating_sub(1) as usize) {
        let trimmed = line.trim();
        add_dotnet_route_group(trimmed, &mut route_groups);
        update_dotnet_route_context(trimmed, &mut pending_route, &mut class_route);
    }
    DotnetRouteContext {
        class_route,
        action_route: pending_route,
        group_route: dotnet_route_group_for_line(line, &route_groups),
    }
}

fn add_dotnet_route_group(line: &str, route_groups: &mut Vec<(String, String)>) {
    if let Some((name, route)) = dotnet_map_group_assignment(line) {
        let route = dotnet_parent_route_group(line, route_groups)
            .map(|parent| join_dotnet_routes(&parent, &route))
            .unwrap_or(route);
        route_groups.push((name, route));
    }
}

fn dotnet_map_group_assignment(line: &str) -> Option<(String, String)> {
    let lower = line.to_ascii_lowercase();
    if !lower.contains(".mapgroup(") {
        return None;
    }
    let name = dotnet_assignment_name(line)?;
    let route = dotnet_map_group_assignment_route(line, &lower)?;
    Some((name, route))
}

fn dotnet_map_group_assignment_route(line: &str, lower: &str) -> Option<String> {
    let group_count = lower.matches(".mapgroup(").count();
    let segments = dotnet_quoted_values(line)
        .into_iter()
        .take(group_count)
        .map(dotnet_route_path)
        .collect::<Option<Vec<_>>>()?;
    (segments.len() == group_count).then(|| join_dotnet_route_segments(&segments))
}

fn dotnet_parent_route_group(line: &str, route_groups: &[(String, String)]) -> Option<String> {
    let receiver = dotnet_route_receiver(line)?;
    route_groups
        .iter()
        .rev()
        .find(|(name, _)| *name == receiver)
        .map(|(_, route)| route.clone())
}

fn dotnet_assignment_name(line: &str) -> Option<String> {
    let left = line.split('=').next()?.trim();
    left.split_whitespace().last().map(|name| name.to_ascii_lowercase())
}

fn dotnet_route_group_for_line(line: &str, route_groups: &[(String, String)]) -> Option<String> {
    let receiver = dotnet_route_receiver(line)?;
    route_groups
        .iter()
        .rev()
        .find(|(name, _)| *name == receiver)
        .map(|(_, route)| route.clone())
}

fn dotnet_route_receiver(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let index = lower.find(".map")?;
    lower[..index]
        .rsplit(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .next()
        .filter(|receiver| !receiver.is_empty())
        .map(str::to_string)
}

fn update_dotnet_route_context(
    line: &str,
    pending_route: &mut Option<String>,
    class_route: &mut Option<String>,
) {
    if let Some(route) = dotnet_route_attribute(line) {
        *pending_route = Some(route);
        return;
    }
    if line.contains(" class ") || line.starts_with("class ") {
        *class_route = pending_route.take();
        return;
    }
    if !line.is_empty() && !line.starts_with('[') {
        *pending_route = None;
    }
}

fn dotnet_route_attribute(line: &str) -> Option<String> {
    if !line.to_ascii_lowercase().contains("[route(") {
        return None;
    }
    dotnet_named_argument_route(line, "template").or_else(|| dotnet_positional_attribute_route(line))
}

fn combine_dotnet_routes(prefix: Option<&str>, route: Option<&str>) -> Option<String> {
    match (prefix, route) {
        (Some(prefix), Some(route)) => Some(join_dotnet_routes(prefix, route)),
        (Some(prefix), None) => Some(prefix.to_string()),
        (None, Some(route)) => Some(route.to_string()),
        (None, None) => None,
    }
}

fn join_dotnet_routes(prefix: &str, route: &str) -> String {
    if route == "*" {
        let prefix = prefix.trim_matches('/');
        return if prefix.is_empty() {
            route.to_string()
        } else {
            format!("/{prefix}/*")
        };
    }
    let prefix = prefix.trim_matches('/');
    let route = route.trim_matches('/');
    if prefix.is_empty() {
        return format!("/{route}");
    }
    if route.is_empty() {
        return format!("/{prefix}");
    }
    format!("/{prefix}/{route}")
}

fn dotnet_route_path(route: String) -> Option<String> {
    let route = route.trim();
    let route = normalize_dotnet_route_tokens(route);
    if route.starts_with('/') || route == "*" {
        return Some(route);
    }
    if route.is_empty() || route.contains(' ') {
        return None;
    }
    Some(format!("/{route}"))
}

fn normalize_dotnet_route_tokens(route: &str) -> String {
    route
        .replace("[controller]", "{controller}")
        .replace("[action]", "{action}")
        .replace("[area]", "{area}")
}

fn dotnet_route_method(line: &str) -> Option<String> {
    if let Some(method) = dotnet_special_route_method(line) {
        return Some(method);
    }
    for (needle, method) in DOTNET_ROUTE_METHODS {
        if line.contains(needle) {
            return Some(method.to_string());
        }
    }
    None
}

fn dotnet_special_route_method(line: &str) -> Option<String> {
    if line.contains("mapmethods(") {
        return dotnet_map_methods_method(line);
    }
    if line.contains("[acceptverbs(") {
        return dotnet_accept_verbs_method(line);
    }
    None
}

const DOTNET_ROUTE_METHODS: &[(&str, &str)] = &[
    ("mapget(", "GET"),
    ("mappost(", "POST"),
    ("mapput(", "PUT"),
    ("mappatch(", "PATCH"),
    ("mapdelete(", "DELETE"),
    ("maphead(", "HEAD"),
    ("mapoptions(", "OPTIONS"),
    ("maphealthchecks(", "GET"),
    ("mapmetrics(", "GET"),
    ("mapopenapi(", "GET"),
    ("mapprometheusscrapingendpoint(", "GET"),
    ("mapshortcircuit(", "ANY"),
    ("mapstaticassets(", "GET"),
    ("mapswagger(", "GET"),
    ("useswagger(", "GET"),
    ("mapgraphql(", "ANY"),
    ("usegraphql(", "ANY"),
    ("mapidentityapi<", "ANY"),
    ("mapidentityapi(", "ANY"),
    ("mapareapageroute(", "ANY"),
    ("mappageroute(", "ANY"),
    ("maprazorcomponents<", "ANY"),
    ("maprazorcomponents(", "ANY"),
    ("maprazorpages(", "ANY"),
    ("mapreverseproxy(", "ANY"),
    ("mapblazorhub(", "ANY"),
    ("maphub<", "ANY"),
    ("maphub(", "ANY"),
    ("mapfallback(", "ANY"),
    ("mapfallbacktoareacontroller(", "ANY"),
    ("mapfallbacktocontroller(", "ANY"),
    ("mapfallbacktofile(", "ANY"),
    ("mapfallbacktopage(", "ANY"),
    ("mapforwarder(", "ANY"),
    ("mapdynamiccontrollerroute<", "ANY"),
    ("mapdynamiccontrollerroute(", "ANY"),
    ("mapdynamicpageroute<", "ANY"),
    ("mapdynamicpageroute(", "ANY"),
    ("mapcontrollers(", "ANY"),
    ("mapcontrollerroute(", "ANY"),
    ("mapareacontrollerroute(", "ANY"),
    ("mapdefaultcontrollerroute(", "ANY"),
    ("[httpget(", "GET"),
    ("[httppost(", "POST"),
    ("[httpput(", "PUT"),
    ("[httppatch(", "PATCH"),
    ("[httpdelete(", "DELETE"),
    ("[httphead(", "HEAD"),
    ("[httpoptions(", "OPTIONS"),
    ("[httpget]", "GET"),
    ("[httppost]", "POST"),
    ("[httpput]", "PUT"),
    ("[httppatch]", "PATCH"),
    ("[httpdelete]", "DELETE"),
    ("[httphead]", "HEAD"),
    ("[httpoptions]", "OPTIONS"),
];

fn dotnet_map_methods_method(line: &str) -> Option<String> {
    let skip = dotnet_map_methods_quoted_route_args(line);
    let mut methods = dotnet_methods_from_values(dotnet_quoted_values(line).into_iter().skip(skip));
    push_dotnet_http_method_constants(&mut methods, line);
    dotnet_join_methods(methods)
}

fn dotnet_map_methods_quoted_route_args(line: &str) -> usize {
    let lower = line.to_ascii_lowercase();
    let group_count = lower.matches(".mapgroup(").count();
    if group_count == 0 || !lower.contains(").map") {
        return 1;
    }
    group_count + 1
}

fn dotnet_accept_verbs_method(line: &str) -> Option<String> {
    let mut methods = dotnet_methods_from_values(dotnet_quoted_values(line).into_iter());
    push_dotnet_http_method_constants(&mut methods, line);
    dotnet_join_methods(methods)
}

const DOTNET_HTTP_METHOD_CONSTANTS: &[(&str, &str)] = &[
    ("httpmethods.get", "GET"),
    ("httpmethods.post", "POST"),
    ("httpmethods.put", "PUT"),
    ("httpmethods.patch", "PATCH"),
    ("httpmethods.delete", "DELETE"),
    ("httpmethods.head", "HEAD"),
    ("httpmethods.options", "OPTIONS"),
    ("httpmethods.trace", "TRACE"),
    ("httpmethods.connect", "CONNECT"),
];

fn dotnet_methods_from_values(values: impl Iterator<Item = String>) -> Vec<String> {
    let mut methods = Vec::new();
    for value in values {
        push_dotnet_http_method(&mut methods, &value);
    }
    methods
}

fn push_dotnet_http_method(methods: &mut Vec<String>, value: &str) {
    let Some(method) = dotnet_http_method(value) else {
        return;
    };
    if !methods.iter().any(|existing| existing == method) {
        methods.push(method.to_string());
    }
}

fn push_dotnet_http_method_constants(methods: &mut Vec<String>, line: &str) {
    let lower = line.to_ascii_lowercase();
    for (needle, method) in DOTNET_HTTP_METHOD_CONSTANTS {
        if lower.contains(needle) && !methods.iter().any(|existing| existing == method) {
            methods.push(method.to_string());
        }
    }
}

fn dotnet_join_methods(methods: Vec<String>) -> Option<String> {
    (!methods.is_empty()).then(|| methods.join(","))
}

fn dotnet_http_method(value: &str) -> Option<&'static str> {
    match value.trim().to_ascii_uppercase().as_str() {
        "GET" => Some("GET"),
        "POST" => Some("POST"),
        "PUT" => Some("PUT"),
        "PATCH" => Some("PATCH"),
        "DELETE" => Some("DELETE"),
        "HEAD" => Some("HEAD"),
        "OPTIONS" => Some("OPTIONS"),
        "TRACE" => Some("TRACE"),
        "CONNECT" => Some("CONNECT"),
        _ => None,
    }
}

fn dotnet_quoted_values(value: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = value;
    while let Some((body, tail)) = dotnet_next_quoted(rest) {
        values.push(body.to_string());
        rest = tail;
    }
    values
}

fn dotnet_next_quoted(value: &str) -> Option<(&str, &str)> {
    let (start, quote) = value
        .char_indices()
        .find(|(_, character)| matches!(*character, '"' | '\''))?;
    let body = &value[start + quote.len_utf8()..];
    let end = body.find(quote)?;
    Some((&body[..end], &body[end + quote.len_utf8()..]))
}

pub(crate) fn inspect_ruby_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    _text: &str,
    builder: &mut InventoryBuilder,
) {
    let lower = line.to_ascii_lowercase();
    let Some(method) = ruby_route_method(&lower) else {
        return;
    };
    let Some(route) = extract_first_quoted(line).filter(|route| backend_route_path(route)) else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        method,
        &route,
        "Rails",
        trim_detail(line),
    ));
}

pub(crate) fn inspect_php_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    _text: &str,
    builder: &mut InventoryBuilder,
) {
    let lower = line.to_ascii_lowercase();
    if let Some((method, route)) = laravel_match_route(line, &lower) {
        builder.add_route_controller(route_item(
            relative,
            line_number,
            method,
            &route,
            "Laravel",
            trim_detail(line),
        ));
        return;
    }
    let Some((method, marker)) = php_route_method(&lower) else {
        return;
    };
    let Some(route) =
        extract_quoted_after_marker_case_insensitive(line, marker).filter(|route| backend_route_path(route))
    else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        method,
        &route,
        "Laravel",
        trim_detail(line),
    ));
}

fn laravel_match_route(line: &str, lower: &str) -> Option<(&'static str, String)> {
    let marker = "route::match(";
    let start = lower.find(marker)? + marker.len();
    let arguments = &line[start..];
    let method = laravel_match_method(&arguments.to_ascii_lowercase())?;
    let route_start = arguments.find(']')? + 1;
    let route = extract_first_quoted(&arguments[route_start..]).filter(|route| backend_route_path(route))?;
    Some((method, route))
}

fn laravel_match_method(arguments: &str) -> Option<&'static str> {
    for (needle, method) in [
        ("'get'", "GET"),
        ("\"get\"", "GET"),
        ("'post'", "POST"),
        ("\"post\"", "POST"),
        ("'put'", "PUT"),
        ("\"put\"", "PUT"),
        ("'patch'", "PATCH"),
        ("\"patch\"", "PATCH"),
        ("'delete'", "DELETE"),
        ("\"delete\"", "DELETE"),
    ] {
        if arguments.contains(needle) {
            return Some(method);
        }
    }
    None
}

fn jvm_route_method(line: &str) -> Option<&'static str> {
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

fn backend_route_path(route: &str) -> bool {
    route.starts_with('/') || route == "*"
}

fn ruby_route_method(line: &str) -> Option<&'static str> {
    if line.trim_start().starts_with("match ") {
        return rails_match_via_method(line).or(Some("ANY"));
    }
    for (marker, method) in [
        ("get ", "GET"),
        ("post ", "POST"),
        ("put ", "PUT"),
        ("patch ", "PATCH"),
        ("delete ", "DELETE"),
    ] {
        if line.trim_start().starts_with(marker) {
            return Some(method);
        }
    }
    None
}

fn rails_match_via_method(line: &str) -> Option<&'static str> {
    for (needle, method) in [
        ("via: :get", "GET"),
        ("via: :post", "POST"),
        ("via: :put", "PUT"),
        ("via: :patch", "PATCH"),
        ("via: :delete", "DELETE"),
        ("via: 'get'", "GET"),
        ("via: 'post'", "POST"),
        ("via: 'put'", "PUT"),
        ("via: 'patch'", "PATCH"),
        ("via: 'delete'", "DELETE"),
        ("via: \"get\"", "GET"),
        ("via: \"post\"", "POST"),
        ("via: \"put\"", "PUT"),
        ("via: \"patch\"", "PATCH"),
        ("via: \"delete\"", "DELETE"),
    ] {
        if line.contains(needle) {
            return Some(method);
        }
    }
    None
}

fn php_route_method(line: &str) -> Option<(&'static str, &'static str)> {
    for (marker, method) in [
        ("route::get(", "GET"),
        ("route::post(", "POST"),
        ("route::put(", "PUT"),
        ("route::patch(", "PATCH"),
        ("route::delete(", "DELETE"),
        ("route::any(", "ANY"),
    ] {
        if line.contains(marker) {
            return Some((method, marker));
        }
    }
    None
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
