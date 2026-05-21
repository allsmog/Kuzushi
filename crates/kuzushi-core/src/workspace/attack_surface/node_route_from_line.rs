use super::*;

#[derive(Debug, Default)]
pub(crate) struct RouteLine {
    pub(crate) method: Option<String>,
    pub(crate) path: Option<String>,
}

pub(crate) fn node_route_from_line(line: &str) -> RouteLine {
    for (method, marker) in NODE_ROUTE_MARKERS {
        if let Some(path) = extract_quoted_after_marker_case_insensitive(line, marker) {
            if !node_route_path(&path) {
                continue;
            }
            return RouteLine {
                method: Some(method.to_string()),
                path: Some(path),
            };
        }
    }
    RouteLine::default()
}

const NODE_ROUTE_MARKERS: &[(&str, &str)] = &[
    ("GET", ".get("),
    ("POST", ".post("),
    ("PUT", ".put("),
    ("PATCH", ".patch("),
    ("DELETE", ".delete("),
    ("USE", ".use("),
    ("ANY", ".all("),
    ("GET", "@Get("),
    ("POST", "@Post("),
    ("PUT", "@Put("),
    ("PATCH", "@Patch("),
    ("DELETE", "@Delete("),
    ("ANY", "@All("),
];

fn node_route_path(path: &str) -> bool {
    path.starts_with('/') || path == "*"
}

pub(crate) fn is_route_line(lower: &str) -> bool {
    node_route_from_line(lower).path.is_some()
}

pub(crate) fn line_has_auth_guard(lower: &str) -> bool {
    line_contains_any(
        lower,
        &[
            "requireauth",
            "authmiddleware",
            "authguard",
            "passport.authenticate",
            "useguards",
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
    FRAMEWORK_DETECTORS
        .iter()
        .find(|detector| detector.supports(language) && detector.matches(&lower))
        .map(|detector| detector.framework.to_string())
}

struct FrameworkDetector {
    languages: &'static [&'static str],
    needles: &'static [&'static str],
    framework: &'static str,
}

impl FrameworkDetector {
    fn supports(&self, language: &str) -> bool {
        self.languages.contains(&language)
    }

    fn matches(&self, lower_source: &str) -> bool {
        line_contains_any(lower_source, self.needles)
    }
}

const FRAMEWORK_DETECTORS: &[FrameworkDetector] = &[
    FrameworkDetector {
        languages: &["JavaScript", "TypeScript"],
        needles: &[
            "from 'elysia'",
            "from \"elysia\"",
            "require('elysia')",
            "new elysia",
        ],
        framework: "Elysia",
    },
    FrameworkDetector {
        languages: &["JavaScript", "TypeScript"],
        needles: &[
            "from 'express'",
            "from \"express\"",
            "require('express')",
            "require(\"express\")",
            "express.router",
            "express()",
        ],
        framework: "Express",
    },
    FrameworkDetector {
        languages: &["JavaScript", "TypeScript"],
        needles: &[
            "from 'fastify'",
            "from \"fastify\"",
            "require('fastify')",
            "require(\"fastify\")",
            "fastify(",
        ],
        framework: "Fastify",
    },
    FrameworkDetector {
        languages: &["JavaScript", "TypeScript"],
        needles: &["from 'hono'", "from \"hono\"", "require('hono')", "new hono"],
        framework: "Hono",
    },
    FrameworkDetector {
        languages: &["JavaScript", "TypeScript"],
        needles: &[
            "from 'koa'",
            "from \"koa\"",
            "require('koa')",
            "require(\"koa\")",
            "@koa/router",
        ],
        framework: "Koa",
    },
    FrameworkDetector {
        languages: &["JavaScript", "TypeScript"],
        needles: &[
            "from 'next/server'",
            "from \"next/server\"",
            "nextrequest",
            "nextresponse",
        ],
        framework: "Next.js",
    },
    FrameworkDetector {
        languages: &["JavaScript", "TypeScript"],
        needles: &[
            "@nestjs/common",
            "from '@nestjs/",
            "from \"@nestjs/",
            "@controller(",
        ],
        framework: "NestJS",
    },
    FrameworkDetector {
        languages: &["Python"],
        needles: &["from flask", "import flask", "flask("],
        framework: "Flask",
    },
    FrameworkDetector {
        languages: &["Python"],
        needles: &["from fastapi", "import fastapi", "fastapi("],
        framework: "FastAPI",
    },
    FrameworkDetector {
        languages: &["Go"],
        needles: &["github.com/gin-gonic/gin", ".get(\"/"],
        framework: "Gin",
    },
    FrameworkDetector {
        languages: &["Go"],
        needles: &["github.com/gofiber/fiber", "fiber.new("],
        framework: "Fiber",
    },
    FrameworkDetector {
        languages: &["Go"],
        needles: &["github.com/labstack/echo", "echo.new("],
        framework: "Echo",
    },
    FrameworkDetector {
        languages: &["Go"],
        needles: &["github.com/go-chi/chi", "chi.newrouter("],
        framework: "Chi",
    },
    FrameworkDetector {
        languages: &["Go"],
        needles: &["net/http", "http.handlefunc"],
        framework: "net/http",
    },
    FrameworkDetector {
        languages: &["Rust"],
        needles: &["axum"],
        framework: "Axum",
    },
    FrameworkDetector {
        languages: &["Rust"],
        needles: &["actix_web"],
        framework: "Actix Web",
    },
    FrameworkDetector {
        languages: &["Rust"],
        needles: &["rocket::", "use rocket", "#[launch]"],
        framework: "Rocket",
    },
    FrameworkDetector {
        languages: &["Rust"],
        needles: &["warp::"],
        framework: "Warp",
    },
    FrameworkDetector {
        languages: &["Java", "Kotlin"],
        needles: &["springframework", "requestmapping", "getmapping"],
        framework: "Spring",
    },
    FrameworkDetector {
        languages: &["Ruby"],
        needles: &[
            "rails.application.routes.draw",
            "applicationcontroller",
            "activerecord::",
            "before_action",
        ],
        framework: "Rails",
    },
    FrameworkDetector {
        languages: &["PHP"],
        needles: &["illuminate\\", "laravel", "route::", "middleware('auth"],
        framework: "Laravel",
    },
];
