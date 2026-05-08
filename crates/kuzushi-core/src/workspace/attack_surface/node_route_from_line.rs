use super::*;

#[derive(Debug, Default)]
pub(crate) struct RouteLine {
    pub(crate) method: Option<String>,
    pub(crate) path: Option<String>,
}

pub(crate) fn node_route_from_line(line: &str) -> RouteLine {
    for (method, marker) in [
        ("GET", ".get("),
        ("POST", ".post("),
        ("PUT", ".put("),
        ("PATCH", ".patch("),
        ("DELETE", ".delete("),
        ("USE", ".use("),
        ("ANY", ".all("),
    ] {
        if let Some(path) = extract_quoted_after_marker_case_insensitive(line, marker) {
            return RouteLine {
                method: Some(method.to_string()),
                path: Some(path),
            };
        }
    }
    RouteLine::default()
}

pub(crate) fn is_route_line(lower: &str) -> bool {
    line_contains_any(
        lower,
        &[
            ".get(", ".post(", ".put(", ".patch(", ".delete(", ".use(", ".all(",
        ],
    )
}

pub(crate) fn line_has_auth_guard(lower: &str) -> bool {
    line_contains_any(
        lower,
        &[
            "requireauth",
            "authmiddleware",
            "passport.authenticate",
            "authorize",
            "ensureauthenticated",
            "checkjwt",
            "requireuser",
            "require_admin",
            "isadmin",
        ],
    )
}

pub(crate) fn framework_for_source(language: &str, text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    match language {
        "JavaScript" | "TypeScript" => {
            if line_contains_any(
                &lower,
                &[
                    "from 'express'",
                    "from \"express\"",
                    "require('express')",
                    "require(\"express\")",
                    "express.router",
                    "express()",
                ],
            ) {
                return Some("Express".to_string());
            }
            if lower.contains("fastify(") {
                return Some("Fastify".to_string());
            }
        }
        "Python" => {
            if line_contains_any(&lower, &["from flask", "import flask", "flask("]) {
                return Some("Flask".to_string());
            }
            if line_contains_any(&lower, &["from fastapi", "import fastapi", "fastapi("]) {
                return Some("FastAPI".to_string());
            }
        }
        "Go" => {
            if line_contains_any(&lower, &["github.com/gin-gonic/gin", ".get(\"/"]) {
                return Some("Gin".to_string());
            }
            if line_contains_any(&lower, &["net/http", "http.handlefunc"]) {
                return Some("net/http".to_string());
            }
        }
        "Rust" => {
            for (needle, framework) in [
                ("axum", "Axum"),
                ("actix_web", "Actix Web"),
                ("rocket::", "Rocket"),
                ("warp::", "Warp"),
            ] {
                if lower.contains(needle) {
                    return Some(framework.to_string());
                }
            }
        }
        _ => {}
    }
    None
}
