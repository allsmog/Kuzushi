use super::*;

pub(crate) fn inspect_source_frameworks(
    relative: &str,
    language: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    let lower = text.to_ascii_lowercase();
    match language {
        "JavaScript" | "TypeScript" => {
            inspect_javascript_frameworks(relative, language, &lower, builder)
        }
        "Python" => inspect_python_frameworks(relative, language, &lower, builder),
        "Go" => inspect_go_frameworks(relative, language, &lower, builder),
        "Rust" => inspect_rust_frameworks(relative, language, &lower, builder),
        _ => {}
    }
}

fn inspect_javascript_frameworks(
    relative: &str,
    language: &str,
    lower: &str,
    builder: &mut InventoryBuilder,
) {
    if contains_any(
        lower,
        &[
            "from 'express'",
            "from \"express\"",
            "require('express')",
            "require(\"express\")",
            "express.router",
        ],
    ) {
        builder.add_framework("Express", language, format!("{relative} imports express"));
    }
    if contains_any(lower, &["fastify(", "from 'fastify'", "from \"fastify\""]) {
        builder.add_framework("Fastify", language, format!("{relative} imports fastify"));
    }
}

fn inspect_python_frameworks(
    relative: &str,
    language: &str,
    lower: &str,
    builder: &mut InventoryBuilder,
) {
    for (framework, needles) in [
        ("Flask", &["from flask", "import flask", "flask("][..]),
        (
            "FastAPI",
            &["from fastapi", "import fastapi", "fastapi("][..],
        ),
        ("Django", &["from django", "import django"][..]),
    ] {
        if contains_any(lower, needles) {
            builder.add_framework(
                framework,
                language,
                format!("{relative} imports {}", framework.to_ascii_lowercase()),
            );
        }
    }
}

fn inspect_go_frameworks(
    relative: &str,
    language: &str,
    lower: &str,
    builder: &mut InventoryBuilder,
) {
    if contains_any(lower, &["net/http", "http.handlefunc", "http.newservemux"]) {
        builder.add_framework("net/http", language, format!("{relative} uses net/http"));
    }
    if contains_any(lower, &["github.com/gin-gonic/gin", ".get(\"/"]) {
        builder.add_framework(
            "Gin",
            language,
            format!("{relative} contains gin-style routes"),
        );
    }
}

fn inspect_rust_frameworks(
    relative: &str,
    language: &str,
    lower: &str,
    builder: &mut InventoryBuilder,
) {
    for (needle, framework) in [
        ("axum", "Axum"),
        ("actix_web", "Actix Web"),
        ("rocket::", "Rocket"),
        ("warp::", "Warp"),
        ("tonic::", "Tonic"),
    ] {
        if lower.contains(needle) {
            builder.add_framework(
                framework,
                language,
                format!("{relative} references {framework}"),
            );
        }
    }
}
