use super::*;

pub(crate) fn inspect_source_frameworks(
    relative: &str,
    language: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    let lower = text.to_ascii_lowercase();
    for detector in SOURCE_FRAMEWORK_DETECTORS {
        if detector.supports(language) && detector.matches(&lower) {
            builder.add_framework(
                detector.framework,
                language,
                format!("{relative} references {}", detector.framework),
            );
        }
    }
}

struct SourceFrameworkDetector {
    languages: &'static [&'static str],
    needles: &'static [&'static str],
    framework: &'static str,
}

impl SourceFrameworkDetector {
    fn supports(&self, language: &str) -> bool {
        self.languages.contains(&language)
    }

    fn matches(&self, lower: &str) -> bool {
        contains_any(lower, self.needles)
    }
}

const SOURCE_FRAMEWORK_DETECTORS: &[SourceFrameworkDetector] = &[
    SourceFrameworkDetector {
        languages: &["JavaScript", "TypeScript"],
        needles: &[
            "from 'elysia'",
            "from \"elysia\"",
            "require('elysia')",
            "new elysia",
        ],
        framework: "Elysia",
    },
    SourceFrameworkDetector {
        languages: &["JavaScript", "TypeScript"],
        needles: &[
            "from 'express'",
            "from \"express\"",
            "require('express')",
            "require(\"express\")",
            "express.router",
        ],
        framework: "Express",
    },
    SourceFrameworkDetector {
        languages: &["JavaScript", "TypeScript"],
        needles: &["fastify(", "from 'fastify'", "from \"fastify\""],
        framework: "Fastify",
    },
    SourceFrameworkDetector {
        languages: &["JavaScript", "TypeScript"],
        needles: &["from 'hono'", "from \"hono\"", "require('hono')", "new hono"],
        framework: "Hono",
    },
    SourceFrameworkDetector {
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
    SourceFrameworkDetector {
        languages: &["JavaScript", "TypeScript"],
        needles: &[
            "@nestjs/common",
            "from '@nestjs/",
            "from \"@nestjs/",
            "@controller(",
        ],
        framework: "NestJS",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["from flask", "import flask", "flask("],
        framework: "Flask",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["from bottle", "import bottle", "bottle."],
        framework: "Bottle",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["from aiohttp", "import aiohttp", "aiohttp."],
        framework: "aiohttp",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["import falcon", "from falcon", "falcon."],
        framework: "Falcon",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["from fastapi", "import fastapi", "fastapi("],
        framework: "FastAPI",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["from litestar", "import litestar", "litestar("],
        framework: "Litestar",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["from starlite", "import starlite", "starlite("],
        framework: "Litestar",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["from pyramid", "import pyramid", "pyramid."],
        framework: "Pyramid",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["from sanic", "import sanic", "sanic("],
        framework: "Sanic",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["from starlette", "import starlette", "starlette("],
        framework: "Starlette",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["from tornado", "import tornado", "tornado."],
        framework: "Tornado",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["from django", "import django"],
        framework: "Django",
    },
    SourceFrameworkDetector {
        languages: &["Go"],
        needles: &["net/http", "http.handlefunc", "http.newservemux"],
        framework: "net/http",
    },
    SourceFrameworkDetector {
        languages: &["Go"],
        needles: &["github.com/gin-gonic/gin", ".get(\"/"],
        framework: "Gin",
    },
    SourceFrameworkDetector {
        languages: &["Go"],
        needles: &["github.com/gofiber/fiber", "fiber.new("],
        framework: "Fiber",
    },
    SourceFrameworkDetector {
        languages: &["Go"],
        needles: &["github.com/labstack/echo", "echo.new("],
        framework: "Echo",
    },
    SourceFrameworkDetector {
        languages: &["Go"],
        needles: &["github.com/go-chi/chi", "chi.newrouter("],
        framework: "Chi",
    },
    SourceFrameworkDetector {
        languages: &["Rust"],
        needles: &["axum"],
        framework: "Axum",
    },
    SourceFrameworkDetector {
        languages: &["Rust"],
        needles: &["actix_web"],
        framework: "Actix Web",
    },
    SourceFrameworkDetector {
        languages: &["Rust"],
        needles: &["rocket::", "use rocket", "#[launch]"],
        framework: "Rocket",
    },
    SourceFrameworkDetector {
        languages: &["Rust"],
        needles: &["warp::"],
        framework: "Warp",
    },
    SourceFrameworkDetector {
        languages: &["Rust"],
        needles: &["tonic::"],
        framework: "Tonic",
    },
    SourceFrameworkDetector {
        languages: &["Java", "Kotlin"],
        needles: &["springframework", "requestmapping", "getmapping"],
        framework: "Spring",
    },
    SourceFrameworkDetector {
        languages: &["C#"],
        needles: &[
            "microsoft.aspnetcore",
            "webapplication.createbuilder",
            "mapget(",
            "mappost(",
            "[httppost",
        ],
        framework: "ASP.NET Core",
    },
    SourceFrameworkDetector {
        languages: &["Ruby"],
        needles: &[
            "rails.application.routes.draw",
            "applicationcontroller",
            "activerecord::",
            "before_action",
        ],
        framework: "Rails",
    },
    SourceFrameworkDetector {
        languages: &["PHP"],
        needles: &["illuminate\\", "laravel", "route::", "middleware('auth"],
        framework: "Laravel",
    },
];
