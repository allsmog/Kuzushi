use super::*;

pub(crate) fn inspect_source_frameworks(
    relative: &str,
    language: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    let lower = text.to_ascii_lowercase();
    for detector in SOURCE_FRAMEWORK_DETECTORS {
        if detector.supports(language) && detector.matches(language, &lower) {
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

    fn matches(&self, language: &str, lower: &str) -> bool {
        if language == "Python" {
            return python_imports_any_module(lower, self.needles);
        }
        contains_any(lower, self.needles)
    }
}

/// Source text is weaker evidence than a manifest: a string literal, comment,
/// schema name, or local identifier that happens to contain `falcon.` is not a
/// declaration that the target uses the Falcon web framework. For Python,
/// accept only actual `import` / `from` statements and leave dependency-based
/// discovery to the manifest inspector.
fn python_imports_any_module(source: &str, modules: &[&str]) -> bool {
    source.lines().any(|line| {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("from ") {
            let imported = rest.split_ascii_whitespace().next().unwrap_or("");
            return modules
                .iter()
                .any(|module| python_module_path_matches(imported, module));
        }
        let Some(rest) = trimmed.strip_prefix("import ") else {
            return false;
        };
        rest.split(',').any(|binding| {
            let imported = binding
                .trim_start()
                .split_ascii_whitespace()
                .next()
                .unwrap_or("");
            modules
                .iter()
                .any(|module| python_module_path_matches(imported, module))
        })
    })
}

fn python_module_path_matches(imported: &str, module: &str) -> bool {
    imported == module
        || imported
            .strip_prefix(module)
            .is_some_and(|suffix| suffix.starts_with('.'))
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
        needles: &[
            "from 'hono'",
            "from \"hono\"",
            "require('hono')",
            "new hono",
        ],
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
        needles: &["flask"],
        framework: "Flask",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["bottle"],
        framework: "Bottle",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["aiohttp"],
        framework: "aiohttp",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["falcon"],
        framework: "Falcon",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["fastapi"],
        framework: "FastAPI",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["litestar"],
        framework: "Litestar",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["starlite"],
        framework: "Litestar",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["pyramid"],
        framework: "Pyramid",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["sanic"],
        framework: "Sanic",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["starlette"],
        framework: "Starlette",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["tornado"],
        framework: "Tornado",
    },
    SourceFrameworkDetector {
        languages: &["Python"],
        needles: &["django"],
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

#[cfg(test)]
mod tests {
    use super::*;

    fn detector(framework: &str) -> &'static SourceFrameworkDetector {
        SOURCE_FRAMEWORK_DETECTORS
            .iter()
            .find(|detector| detector.framework == framework)
            .unwrap_or_else(|| panic!("missing source framework detector for {framework}"))
    }

    #[test]
    fn python_framework_detection_ignores_strings_comments_and_prefix_collisions() {
        let falcon = detector("Falcon");
        for source in [
            r#"schema = "falcon.benchmark_run.v1""#,
            r#"contract = "falcon.analysis_plan.v1""#,
            "# import falcon",
            "client = falcon.App()",
            "import falconry",
            "from falconry import Bird",
        ] {
            assert!(
                !falcon.matches("Python", &source.to_ascii_lowercase()),
                "non-import source must not establish Falcon usage: {source}"
            );
        }
    }

    #[test]
    fn python_framework_detection_accepts_real_module_imports() {
        let falcon = detector("Falcon");
        for source in [
            "import falcon",
            "import falcon.asgi as falcon_asgi",
            "import os, falcon",
            "from falcon import App",
            "    from falcon.asgi import App",
        ] {
            assert!(
                falcon.matches("Python", &source.to_ascii_lowercase()),
                "real Falcon import must establish framework usage: {source}"
            );
        }
    }

    #[test]
    fn every_python_framework_detector_accepts_its_module_import() {
        for detector in SOURCE_FRAMEWORK_DETECTORS
            .iter()
            .filter(|detector| detector.supports("Python"))
        {
            let module = detector.needles[0];
            let source = format!("from {module}.app import App");
            assert!(
                detector.matches("Python", &source),
                "{} detector must accept an import of {module}",
                detector.framework
            );
        }
    }
}
