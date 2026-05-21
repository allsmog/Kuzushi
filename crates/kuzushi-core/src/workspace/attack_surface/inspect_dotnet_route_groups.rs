use super::inspect_dotnet_route_paths::{
    dotnet_named_argument_route, dotnet_quoted_values, dotnet_route_path, join_dotnet_routes,
};

pub(super) fn add_dotnet_route_group(line: &str, route_groups: &mut Vec<(String, String)>) {
    if let Some((name, route)) = dotnet_map_group_assignment(line) {
        let route = dotnet_parent_route_group(line, route_groups)
            .map(|parent| join_dotnet_routes(&parent, &route))
            .unwrap_or(route);
        route_groups.push((name, route));
    }
}

pub(super) fn dotnet_route_group_for_line(
    line: &str,
    route_groups: &[(String, String)],
) -> Option<String> {
    let receiver = dotnet_route_receiver(line)?;
    route_groups
        .iter()
        .rev()
        .find(|(name, _)| *name == receiver)
        .map(|(_, route)| route.clone())
}

pub(super) fn dotnet_chained_group_route(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    if !lower.contains(".mapgroup(") || !lower.contains(").map") {
        return None;
    }
    let mut route_segments = dotnet_chained_group_prefix_segments(line, &lower)?;
    route_segments.push(dotnet_chained_endpoint_route(line, &lower)?);
    Some(join_dotnet_route_segments(&route_segments))
}

pub(super) fn dotnet_chained_group_prefix(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    if !lower.contains(".mapgroup(") || !lower.contains(").map") {
        return None;
    }
    let route_segments = dotnet_chained_group_prefix_segments(line, &lower)?;
    Some(join_dotnet_route_segments(&route_segments))
}

fn dotnet_chained_group_prefix_segments(line: &str, lower: &str) -> Option<Vec<String>> {
    let group_count = lower.matches(".mapgroup(").count();
    let segments = dotnet_quoted_values(line)
        .into_iter()
        .take(group_count)
        .map(dotnet_route_path)
        .collect::<Option<Vec<_>>>()?;
    if segments.len() != group_count {
        return None;
    }
    Some(segments)
}

fn dotnet_chained_endpoint_route(line: &str, lower: &str) -> Option<String> {
    if lower.contains(".mapcontrollers(") {
        return Some("/{controller}/{action}".to_string());
    }
    if lower.contains(".mapdefaultcontrollerroute(") {
        return Some("/{controller=Home}/{action=Index}/{id?}".to_string());
    }
    if lower.contains(".mapfallbacktofile(") || lower.contains(".mapfallbacktopage(") {
        return Some("*".to_string());
    }
    dotnet_chained_quoted_endpoint_route(line, lower)
        .or_else(|| dotnet_chained_default_endpoint_route(lower).map(str::to_string))
}

fn dotnet_chained_default_endpoint_route(lower: &str) -> Option<&'static str> {
    DOTNET_CHAINED_DEFAULT_ROUTES
        .iter()
        .find_map(|(needle, route)| lower.contains(needle).then_some(*route))
}

const DOTNET_CHAINED_DEFAULT_ROUTES: &[(&str, &str)] = &[
    (".mapopenapi(", "/openapi/{documentName}.json"),
    (".mapswagger(", "/swagger/{documentName}/swagger.json"),
    (".mapgraphql(", "/graphql"),
    (".mapblazorhub(", "/_blazor"),
    (".mapidentityapi", ""),
    (".mapmetrics(", "/metrics"),
    (".mapprometheusscrapingendpoint(", "/metrics"),
    (".maprazorcomponents", "/{component}"),
    (".maprazorpages(", "/{page}"),
    (".mapstaticassets(", "/{staticAsset}"),
];

fn dotnet_chained_quoted_endpoint_route(line: &str, lower: &str) -> Option<String> {
    let endpoint = dotnet_chained_endpoint_slice(line, lower)?;
    let endpoint_lower = endpoint.to_ascii_lowercase();
    let quoted_values = dotnet_quoted_values(endpoint);
    if endpoint_lower.contains(".mapcontrollerroute(")
        || endpoint_lower.contains(".mapareacontrollerroute(")
    {
        return dotnet_named_argument_route(endpoint, "pattern")
            .or_else(|| quoted_values.into_iter().rev().find_map(dotnet_route_path));
    }
    quoted_values.into_iter().next().and_then(dotnet_route_path)
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
    left.split_whitespace()
        .last()
        .map(|name| name.to_ascii_lowercase())
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
