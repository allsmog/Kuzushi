use super::prelude::*;
use super::*;

pub(crate) fn inspect_manifest_frameworks(
    relative: &str,
    file_name: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    let lower_name = file_name.to_ascii_lowercase();
    let lower = text.to_ascii_lowercase();
    let evidence = |framework: &str| format!("{relative} references {framework}");

    if lower_name == "package.json" {
        for (needle, framework) in [
            ("\"express\"", "Express"),
            ("\"fastify\"", "Fastify"),
            ("\"koa\"", "Koa"),
            ("\"next\"", "Next.js"),
            ("\"react\"", "React"),
            ("\"@nestjs/core\"", "NestJS"),
        ] {
            if lower.contains(needle) {
                builder.add_framework(framework, "JavaScript", evidence(framework));
            }
        }
        if lower.contains("\"start\"") {
            builder.add_entrypoint(
                "node-start-script",
                relative,
                "package manifest start script",
            );
        }
    }

    if matches!(lower_name.as_str(), "pyproject.toml" | "requirements.txt") {
        for (needle, framework) in [
            ("django", "Django"),
            ("fastapi", "FastAPI"),
            ("flask", "Flask"),
        ] {
            if lower.contains(needle) {
                builder.add_framework(framework, "Python", evidence(framework));
            }
        }
    }

    if lower_name == "go.mod" {
        if lower.contains("github.com/gin-gonic/gin") {
            builder.add_framework("Gin", "Go", evidence("Gin"));
        }
        if lower.contains("github.com/gorilla/mux") {
            builder.add_framework("Gorilla Mux", "Go", evidence("Gorilla Mux"));
        }
        if lower.contains("google.golang.org/grpc") {
            builder.add_framework("gRPC", "Go", evidence("gRPC"));
        }
    }

    if lower_name == "cargo.toml" {
        for (needle, framework) in [
            ("axum", "Axum"),
            ("actix-web", "Actix Web"),
            ("rocket", "Rocket"),
            ("warp", "Warp"),
            ("tonic", "Tonic"),
        ] {
            if lower.contains(needle) {
                builder.add_framework(framework, "Rust", evidence(framework));
            }
        }
    }
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
