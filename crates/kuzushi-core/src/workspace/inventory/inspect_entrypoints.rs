use super::*;

pub(crate) fn inspect_entrypoints(
    relative: &str,
    language: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    let lower_path = relative.to_ascii_lowercase();
    let lower = text.to_ascii_lowercase();
    let file_name = Path::new(relative)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(relative)
        .to_ascii_lowercase();

    match language {
        "JavaScript" | "TypeScript" => {
            inspect_node_entrypoint(relative, &file_name, &lower, builder)
        }
        "Python" => inspect_python_entrypoint(relative, &file_name, &lower, builder),
        "Go" => inspect_go_entrypoint(relative, &lower, builder),
        "Rust" => inspect_rust_entrypoint(relative, &lower_path, &lower, builder),
        _ => {}
    }
}

pub(crate) fn inspect_node_entrypoint(
    relative: &str,
    file_name: &str,
    lower: &str,
    builder: &mut InventoryBuilder,
) {
    if !node_entrypoint_file(file_name)
        || !contains_any(lower, &[".listen(", "createserver(", "express("])
    {
        return;
    }

    builder.add_entrypoint(
        "node-server",
        relative,
        "server file with listener or app factory",
    );
}

pub(crate) fn node_entrypoint_file(file_name: &str) -> bool {
    matches!(
        file_name,
        "server.js" | "server.ts" | "app.js" | "app.ts" | "index.js" | "index.ts"
    )
}

pub(crate) fn inspect_python_entrypoint(
    relative: &str,
    file_name: &str,
    lower: &str,
    builder: &mut InventoryBuilder,
) {
    if python_entrypoint_file(file_name) || python_entrypoint_marker(lower) {
        builder.add_entrypoint("python-app", relative, "Python application entrypoint");
    }
}

pub(crate) fn python_entrypoint_file(file_name: &str) -> bool {
    matches!(file_name, "app.py" | "main.py" | "manage.py")
}

pub(crate) fn python_entrypoint_marker(lower: &str) -> bool {
    lower.contains("if __name__ == \"__main__\"")
        || lower.contains("if __name__ == '__main__'")
        || lower.contains("uvicorn.run(")
}

pub(crate) fn inspect_go_entrypoint(relative: &str, lower: &str, builder: &mut InventoryBuilder) {
    if lower.contains("package main") && lower.contains("func main(") {
        builder.add_entrypoint("go-main", relative, "Go package main entrypoint");
    }
}

pub(crate) fn inspect_rust_entrypoint(
    relative: &str,
    lower_path: &str,
    lower: &str,
    builder: &mut InventoryBuilder,
) {
    if lower_path == "src/main.rs" || lower.contains("fn main(") || lower.contains("#[tokio::main]")
    {
        builder.add_entrypoint("rust-binary", relative, "Rust binary entrypoint");
    }
}

pub(crate) fn inspect_routes(
    relative: &str,
    language: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    for (index, line) in text.lines().enumerate() {
        let line_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        for inspector in ROUTE_INSPECTORS {
            if inspector.supports(language) {
                (inspector.inspect)(relative, line_number, line, text, builder);
            }
        }
    }
}

struct RouteInspector {
    languages: &'static [&'static str],
    inspect: fn(&str, u32, &str, &str, &mut InventoryBuilder),
}

impl RouteInspector {
    fn supports(&self, language: &str) -> bool {
        self.languages.contains(&language)
    }
}

const ROUTE_INSPECTORS: &[RouteInspector] = &[
    RouteInspector {
        languages: &["JavaScript", "TypeScript"],
        inspect: inspect_node_route_line,
    },
    RouteInspector {
        languages: &["Python"],
        inspect: inspect_python_route_line,
    },
    RouteInspector {
        languages: &["Go"],
        inspect: inspect_go_route_line,
    },
    RouteInspector {
        languages: &["Rust"],
        inspect: inspect_rust_route_line,
    },
    RouteInspector {
        languages: &["Java", "Kotlin"],
        inspect: inspect_jvm_route_line,
    },
    RouteInspector {
        languages: &["C#"],
        inspect: inspect_dotnet_route_line,
    },
    RouteInspector {
        languages: &["Ruby"],
        inspect: inspect_ruby_route_line,
    },
    RouteInspector {
        languages: &["PHP"],
        inspect: inspect_php_route_line,
    },
];

pub(crate) fn inspect_node_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    let framework = node_route_framework(text);
    inspect_express_route_line(relative, line_number, line, framework, builder);
    inspect_nest_route_line(relative, line_number, line, builder);
    inspect_next_route_line(relative, line_number, line, builder);
}

fn inspect_express_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    framework: &str,
    builder: &mut InventoryBuilder,
) {
    for (method, marker) in [
        ("GET", ".get("),
        ("POST", ".post("),
        ("PUT", ".put("),
        ("PATCH", ".patch("),
        ("DELETE", ".delete("),
        ("USE", ".use("),
        ("ANY", ".all("),
    ] {
        if let Some(route) = extract_quoted_after_marker(line, marker) {
            if !node_route_path(&route) {
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

fn node_route_framework(text: &str) -> &'static str {
    if source_looks_like_elysia(text) {
        "Elysia"
    } else if source_looks_like_fastify(text) {
        "Fastify"
    } else if source_looks_like_hono(text) {
        "Hono"
    } else if source_looks_like_koa(text) {
        "Koa"
    } else {
        "Express"
    }
}

fn source_looks_like_elysia(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "from 'elysia'",
            "from \"elysia\"",
            "require('elysia')",
            "require(\"elysia\")",
            "new elysia",
        ],
    )
}

fn source_looks_like_fastify(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "from 'fastify'",
            "from \"fastify\"",
            "require('fastify')",
            "require(\"fastify\")",
            "fastify(",
        ],
    )
}

fn source_looks_like_hono(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "from 'hono'",
            "from \"hono\"",
            "require('hono')",
            "require(\"hono\")",
            "new hono",
        ],
    )
}

fn source_looks_like_koa(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    contains_any(
        &lower,
        &[
            "from 'koa'",
            "from \"koa\"",
            "require('koa')",
            "require(\"koa\")",
            "@koa/router",
        ],
    )
}

fn inspect_nest_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    builder: &mut InventoryBuilder,
) {
    for (method, marker) in [
        ("GET", "@Get("),
        ("POST", "@Post("),
        ("PUT", "@Put("),
        ("PATCH", "@Patch("),
        ("DELETE", "@Delete("),
        ("ANY", "@All("),
    ] {
        if let Some(route) = extract_quoted_after_marker(line, marker) {
            if !node_route_path(&route) {
                continue;
            }
            builder.add_route_controller(route_item(
                relative,
                line_number,
                method,
                &route,
                "NestJS",
                trim_detail(line),
            ));
        }
    }
}

fn inspect_next_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    builder: &mut InventoryBuilder,
) {
    let Some(route) = next_route_from_path(relative) else {
        return;
    };
    let Some(method) = next_route_method(relative, line) else {
        return;
    };
    builder.add_route_controller(route_item(
        relative,
        line_number,
        method,
        &route,
        "Next.js",
        trim_detail(line),
    ));
}

fn next_route_method(relative: &str, line: &str) -> Option<&'static str> {
    next_app_route_method(line).or_else(|| next_pages_api_route_method(relative, line))
}

fn next_app_route_method(line: &str) -> Option<&'static str> {
    let normalized = line
        .trim_start()
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    NEXT_ROUTE_METHODS
        .iter()
        .find(|method| next_app_method_export(&normalized, method))
        .copied()
}

fn next_app_method_export(line: &str, method: &str) -> bool {
    let lower_method = method.to_ascii_lowercase();
    let function_export = format!("export async function {lower_method}(");
    let sync_function_export = format!("export function {lower_method}(");
    let const_export = format!("export const {lower_method}");
    line.starts_with(&function_export)
        || line.starts_with(&sync_function_export)
        || line.starts_with(&const_export)
}

fn next_pages_api_route_method(relative: &str, line: &str) -> Option<&'static str> {
    if !is_next_pages_api_path(relative) || !is_next_pages_api_handler(line) {
        return None;
    }
    Some("ANY")
}

fn is_next_pages_api_handler(line: &str) -> bool {
    let lower = line.trim_start().to_ascii_lowercase();
    lower.starts_with("export default function")
        || lower.starts_with("export default async function")
        || lower.starts_with("export default")
}

fn next_route_from_path(relative: &str) -> Option<String> {
    let normalized = relative.replace('\\', "/");
    next_app_route_from_path(&normalized).or_else(|| next_pages_api_route_from_path(&normalized))
}

fn next_app_route_from_path(path: &str) -> Option<String> {
    let parts = path.split('/').collect::<Vec<_>>();
    let app_index = parts.iter().position(|part| *part == "app")?;
    let file_name = parts.last()?;
    if !file_stem_is(file_name, "route") {
        return None;
    }
    route_from_segments(&parts[app_index + 1..parts.len().saturating_sub(1)])
}

fn next_pages_api_route_from_path(path: &str) -> Option<String> {
    let parts = path.split('/').collect::<Vec<_>>();
    let pages_index = parts.iter().position(|part| *part == "pages")?;
    if parts.get(pages_index + 1) != Some(&"api") {
        return None;
    }
    let mut route_parts = parts[pages_index + 1..].to_vec();
    let last = route_parts.pop()?;
    route_parts.push(strip_extension(last));
    route_from_segments(&route_parts)
}

fn is_next_pages_api_path(relative: &str) -> bool {
    next_pages_api_route_from_path(&relative.replace('\\', "/")).is_some()
}

fn route_from_segments(segments: &[&str]) -> Option<String> {
    let route_segments = segments
        .iter()
        .filter_map(|segment| route_segment(segment))
        .collect::<Vec<_>>();
    Some(format!("/{}", route_segments.join("/")))
}

fn route_segment(segment: &str) -> Option<String> {
    let segment = strip_extension(segment);
    if segment.is_empty() || segment == "index" || route_group_segment(segment) {
        return None;
    }
    Some(next_dynamic_segment(segment).unwrap_or_else(|| segment.to_string()))
}

fn next_dynamic_segment(segment: &str) -> Option<String> {
    let body = segment.strip_prefix('[')?.strip_suffix(']')?;
    let parameter = body
        .strip_prefix("[...")
        .and_then(|value| value.strip_suffix(']'))
        .or_else(|| body.strip_prefix("..."))
        .unwrap_or(body);
    Some(format!(":{parameter}"))
}

fn route_group_segment(segment: &str) -> bool {
    segment.starts_with('(') && segment.ends_with(')')
}

fn file_stem_is(file_name: &str, expected: &str) -> bool {
    strip_extension(file_name) == expected
}

fn strip_extension(segment: &str) -> &str {
    match segment.rsplit_once('.') {
        Some((stem, extension)) if NEXT_ROUTE_EXTENSIONS.contains(&extension) => stem,
        _ => segment,
    }
}

fn node_route_path(route: &str) -> bool {
    route.starts_with('/') || route == "*"
}

const NEXT_ROUTE_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const NEXT_ROUTE_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs"];
