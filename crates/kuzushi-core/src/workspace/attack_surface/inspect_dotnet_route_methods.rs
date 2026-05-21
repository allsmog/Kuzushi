use super::inspect_dotnet_route_paths::dotnet_quoted_values;

pub(super) fn dotnet_route_methods(line: &str) -> Vec<String> {
    if let Some(methods) = dotnet_special_route_methods(line) {
        return methods;
    }
    for (needle, method) in DOTNET_ROUTE_METHODS {
        if line.contains(needle) {
            return vec![method.to_string()];
        }
    }
    Vec::new()
}

fn dotnet_special_route_methods(line: &str) -> Option<Vec<String>> {
    if line.contains("mapmethods(") {
        return Some(dotnet_map_methods(line));
    }
    if line.contains("[acceptverbs(") {
        return Some(dotnet_accept_verbs_methods(line));
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

fn dotnet_map_methods(line: &str) -> Vec<String> {
    let skip = dotnet_map_methods_quoted_route_args(line);
    let mut methods = dotnet_methods_from_values(dotnet_quoted_values(line).into_iter().skip(skip));
    push_dotnet_http_method_constants(&mut methods, line);
    methods
}

fn dotnet_map_methods_quoted_route_args(line: &str) -> usize {
    let lower = line.to_ascii_lowercase();
    let group_count = lower.matches(".mapgroup(").count();
    if group_count == 0 || !lower.contains(").map") {
        return 1;
    }
    group_count + 1
}

fn dotnet_accept_verbs_methods(line: &str) -> Vec<String> {
    let mut methods = dotnet_methods_from_values(dotnet_quoted_values(line).into_iter());
    push_dotnet_http_method_constants(&mut methods, line);
    methods
}

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
    for (needle, method) in DOTNET_HTTP_METHOD_CONSTANTS {
        if line.contains(needle) && !methods.iter().any(|existing| existing == method) {
            methods.push(method.to_string());
        }
    }
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
