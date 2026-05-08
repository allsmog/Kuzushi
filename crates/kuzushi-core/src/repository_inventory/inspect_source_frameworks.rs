use super::prelude::*;
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
            if contains_any(
                &lower,
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
            if lower.contains("fastify(")
                || lower.contains("from 'fastify'")
                || lower.contains("from \"fastify\"")
            {
                builder.add_framework("Fastify", language, format!("{relative} imports fastify"));
            }
        }
        "Python" => {
            if contains_any(&lower, &["from flask", "import flask", "flask("]) {
                builder.add_framework("Flask", language, format!("{relative} imports flask"));
            }
            if contains_any(&lower, &["from fastapi", "import fastapi", "fastapi("]) {
                builder.add_framework("FastAPI", language, format!("{relative} imports fastapi"));
            }
            if contains_any(&lower, &["from django", "import django"]) {
                builder.add_framework("Django", language, format!("{relative} imports django"));
            }
        }
        "Go" => {
            if contains_any(&lower, &["net/http", "http.handlefunc", "http.newservemux"]) {
                builder.add_framework("net/http", language, format!("{relative} uses net/http"));
            }
            if lower.contains("github.com/gin-gonic/gin") || lower.contains(".get(\"/") {
                builder.add_framework(
                    "Gin",
                    language,
                    format!("{relative} contains gin-style routes"),
                );
            }
        }
        "Rust" => {
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
        _ => {}
    }
}
