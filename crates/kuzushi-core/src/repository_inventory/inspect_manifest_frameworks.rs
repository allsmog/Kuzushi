use super::*;

pub(crate) fn inspect_manifest_frameworks(
    relative: &str,
    file_name: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    let lower_name = file_name.to_ascii_lowercase();
    let lower = text.to_ascii_lowercase();

    if lower_name == "package.json" {
        inspect_package_json_frameworks(relative, &lower, builder);
    }

    if matches!(lower_name.as_str(), "pyproject.toml" | "requirements.txt") {
        inspect_python_manifest_frameworks(relative, &lower, builder);
    }

    if lower_name == "go.mod" {
        inspect_go_manifest_frameworks(relative, &lower, builder);
    }

    if lower_name == "cargo.toml" {
        inspect_rust_manifest_frameworks(relative, &lower, builder);
    }
}

fn inspect_package_json_frameworks(relative: &str, lower: &str, builder: &mut InventoryBuilder) {
    inspect_framework_needles(
        relative,
        lower,
        "JavaScript",
        builder,
        &[
            ("\"express\"", "Express"),
            ("\"fastify\"", "Fastify"),
            ("\"koa\"", "Koa"),
            ("\"next\"", "Next.js"),
            ("\"react\"", "React"),
            ("\"@nestjs/core\"", "NestJS"),
        ],
    );
    if lower.contains("\"start\"") {
        builder.add_entrypoint(
            "node-start-script",
            relative,
            "package manifest start script",
        );
    }
}

fn inspect_python_manifest_frameworks(relative: &str, lower: &str, builder: &mut InventoryBuilder) {
    inspect_framework_needles(
        relative,
        lower,
        "Python",
        builder,
        &[
            ("django", "Django"),
            ("fastapi", "FastAPI"),
            ("flask", "Flask"),
        ],
    );
}

fn inspect_go_manifest_frameworks(relative: &str, lower: &str, builder: &mut InventoryBuilder) {
    inspect_framework_needles(
        relative,
        lower,
        "Go",
        builder,
        &[
            ("github.com/gin-gonic/gin", "Gin"),
            ("github.com/gorilla/mux", "Gorilla Mux"),
            ("google.golang.org/grpc", "gRPC"),
        ],
    );
}

fn inspect_rust_manifest_frameworks(relative: &str, lower: &str, builder: &mut InventoryBuilder) {
    inspect_framework_needles(
        relative,
        lower,
        "Rust",
        builder,
        &[
            ("axum", "Axum"),
            ("actix-web", "Actix Web"),
            ("rocket", "Rocket"),
            ("warp", "Warp"),
            ("tonic", "Tonic"),
        ],
    );
}

fn inspect_framework_needles(
    relative: &str,
    lower: &str,
    language: &str,
    builder: &mut InventoryBuilder,
    needles: &[(&str, &str)],
) {
    for (needle, framework) in needles {
        if lower.contains(needle) {
            builder.add_framework(framework, language, framework_evidence(relative, framework));
        }
    }
}

fn framework_evidence(relative: &str, framework: &str) -> String {
    format!("{relative} references {framework}")
}

pub(crate) fn inspect_source_file(
    relative: &str,
    language: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    inspect_entrypoints(relative, language, text, builder);
    inspect_source_frameworks(relative, language, text, builder);
    inspect_routes(relative, language, text, builder);
    inspect_controller_path(relative, builder);
}
