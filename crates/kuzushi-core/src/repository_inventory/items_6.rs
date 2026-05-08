use super::prelude::*;
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
            if matches!(
                file_name.as_str(),
                "server.js" | "server.ts" | "app.js" | "app.ts" | "index.js" | "index.ts"
            ) && contains_any(&lower, &[".listen(", "createserver(", "express("])
            {
                builder.add_entrypoint(
                    "node-server",
                    relative,
                    "server file with listener or app factory",
                );
            }
        }
        "Python" => {
            if matches!(file_name.as_str(), "app.py" | "main.py" | "manage.py")
                || lower.contains("if __name__ == \"__main__\"")
                || lower.contains("if __name__ == '__main__'")
                || lower.contains("uvicorn.run(")
            {
                builder.add_entrypoint("python-app", relative, "Python application entrypoint");
            }
        }
        "Go" => {
            if lower.contains("package main") && lower.contains("func main(") {
                builder.add_entrypoint("go-main", relative, "Go package main entrypoint");
            }
        }
        "Rust" => {
            if lower_path == "src/main.rs"
                || lower.contains("fn main(")
                || lower.contains("#[tokio::main]")
            {
                builder.add_entrypoint("rust-binary", relative, "Rust binary entrypoint");
            }
        }
        _ => {}
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
        match language {
            "JavaScript" | "TypeScript" => {
                inspect_node_route_line(relative, line_number, line, builder)
            }
            "Python" => inspect_python_route_line(relative, line_number, line, builder),
            "Go" => inspect_go_route_line(relative, line_number, line, builder),
            "Rust" => inspect_rust_route_line(relative, line_number, line, builder),
            _ => {}
        }
    }
}

pub(crate) fn inspect_node_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
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
            builder.add_route_controller(route_item(
                relative,
                line_number,
                method,
                &route,
                "Express",
                trim_detail(line),
            ));
        }
    }
}
