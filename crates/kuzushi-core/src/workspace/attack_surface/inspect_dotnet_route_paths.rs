use super::*;

pub(super) fn dotnet_route_path_for_line(line: &str) -> Option<String> {
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

pub(super) fn dotnet_route_attribute(line: &str) -> Option<String> {
    if !line.to_ascii_lowercase().contains("[route(") {
        return None;
    }
    dotnet_named_argument_route(line, "template")
        .or_else(|| dotnet_positional_attribute_route(line))
}

pub(super) fn combine_dotnet_routes(prefix: Option<&str>, route: Option<&str>) -> Option<String> {
    match (prefix, route) {
        (Some(prefix), Some(route)) => Some(join_dotnet_routes(prefix, route)),
        (Some(prefix), None) => Some(prefix.to_string()),
        (None, Some(route)) => Some(route.to_string()),
        (None, None) => None,
    }
}

pub(super) fn dotnet_quoted_values(value: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut rest = value;
    while let Some((body, tail)) = dotnet_next_quoted(rest) {
        values.push(body.to_string());
        rest = tail;
    }
    values
}

fn dotnet_blazor_hub_route(line: &str) -> String {
    dotnet_defaultable_route(line, "/_blazor")
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
    lower
        .contains("mapopenapi(")
        .then(|| dotnet_defaultable_route(line, "/openapi/{documentName}.json"))
}

fn dotnet_swagger_or_graphql_route(line: &str, lower: &str) -> Option<String> {
    if lower.contains("mapswagger(") || lower.contains("useswagger(") {
        return Some(dotnet_defaultable_route(
            line,
            "/swagger/{documentName}/swagger.json",
        ));
    }
    if lower.contains("mapgraphql(") || lower.contains("usegraphql(") {
        return Some(dotnet_defaultable_route(line, "/graphql"));
    }
    None
}

fn dotnet_controller_route(line: &str, lower: &str) -> Option<String> {
    if let Some(route) = dotnet_dynamic_route(line, lower) {
        return Some(route);
    }
    if lower.contains("mapcontrollers(") {
        return Some("/{controller}/{action}".to_string());
    }
    if lower.contains("mapcontrollerroute(") || lower.contains("mapareacontrollerroute(") {
        return dotnet_named_argument_route(line, "pattern")
            .or_else(|| dotnet_last_quoted_route(line));
    }
    None
}

fn dotnet_dynamic_route(line: &str, lower: &str) -> Option<String> {
    if !lower.contains("mapdynamiccontrollerroute") && !lower.contains("mapdynamicpageroute") {
        return None;
    }
    dotnet_quoted_values(line)
        .into_iter()
        .find_map(dotnet_route_path)
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

fn dotnet_defaultable_route(line: &str, default: &str) -> String {
    extract_first_quoted(line)
        .and_then(dotnet_route_path)
        .unwrap_or_else(|| default.to_string())
}

pub(super) fn dotnet_named_argument_route(line: &str, name: &str) -> Option<String> {
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

pub(super) fn join_dotnet_routes(prefix: &str, route: &str) -> String {
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

pub(super) fn dotnet_route_path(route: String) -> Option<String> {
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

fn dotnet_next_quoted(value: &str) -> Option<(&str, &str)> {
    let (start, quote) = value
        .char_indices()
        .find(|(_, character)| matches!(*character, '"' | '\''))?;
    let body = &value[start + quote.len_utf8()..];
    let end = body.find(quote)?;
    Some((&body[..end], &body[end + quote.len_utf8()..]))
}
