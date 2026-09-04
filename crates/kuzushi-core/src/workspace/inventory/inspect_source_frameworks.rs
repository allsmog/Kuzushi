use super::*;
use tree_sitter::{Node, Parser};

pub(crate) fn inspect_source_frameworks(
    relative: &str,
    language: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    let lower = text.to_ascii_lowercase();
    let python_imports = if language == "Python" {
        python_imported_modules(text)
    } else {
        Vec::new()
    };

    for detector in SOURCE_FRAMEWORK_DETECTORS {
        if detector.supports(language) && detector.matches(language, &lower, &python_imports) {
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

    fn matches(&self, language: &str, lower: &str, python_imports: &[String]) -> bool {
        if language == "Python" {
            return self
                .needles
                .iter()
                .any(|module| python_imports_module(python_imports, module));
        }
        contains_any(lower, self.needles)
    }
}

/// Source text is weaker evidence than a manifest: a string literal, comment,
/// schema name, or local identifier that happens to contain `falcon.` is not a
/// declaration that the target uses the Falcon web framework. Python already
/// has a Tree-sitter grammar in kuzushi-core, so source-only framework claims
/// are derived from syntactic import statements rather than a second ad-hoc
/// lexer. Parser failure simply contributes no source claim; manifest evidence
/// remains an independent path.
fn python_imported_modules(source: &str) -> Vec<String> {
    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .is_err()
    {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source.as_bytes(), None) else {
        return Vec::new();
    };

    let mut imports = Vec::new();
    collect_python_imports(tree.root_node(), source.as_bytes(), &mut imports);
    imports
}

fn collect_python_imports(node: Node<'_>, source: &[u8], imports: &mut Vec<String>) {
    if matches!(node.kind(), "import_statement" | "import_from_statement") {
        if let Ok(text) = node.utf8_text(source) {
            record_python_import_node(text, imports);
        }
        return;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_python_imports(child, source, imports);
    }
}

/// Tree-sitter has already established that `text` is an import statement, so
/// this helper only extracts module paths from that syntax node. Normalizing a
/// backslash continuation here is safe: comments, strings, and docstrings never
/// reach this function as import nodes.
fn record_python_import_node(text: &str, imports: &mut Vec<String>) {
    let normalized = text.replace("\\\r\n", " ").replace("\\\n", " ");
    let trimmed = normalized.trim_start();

    if let Some(rest) = strip_python_keyword(trimmed, "from") {
        record_python_module_token(rest, imports);
    } else if let Some(rest) = strip_python_keyword(trimmed, "import") {
        record_python_import_list(rest, imports);
    }
}

/// Python permits any whitespace (tabs, form feeds) between the keyword and
/// the module path, so a literal-space prefix would drop legal imports.
fn strip_python_keyword<'a>(text: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = text.strip_prefix(keyword)?;
    rest.chars()
        .next()
        .filter(|next| next.is_ascii_whitespace())
        .map(|_| rest.trim_start())
}

fn record_python_import_list(rest: &str, imports: &mut Vec<String>) {
    for binding in rest.split(',') {
        record_python_module_token(binding, imports);
    }
}

fn record_python_module_token(binding: &str, imports: &mut Vec<String>) {
    if let Some(imported) = binding.trim_start().split_ascii_whitespace().next() {
        record_python_module(imported, imports);
    }
}

fn record_python_module(imported: &str, imports: &mut Vec<String>) {
    let imported = imported.to_ascii_lowercase();
    if imported.is_empty() || imports.iter().any(|existing| existing == &imported) {
        return;
    }
    imports.push(imported);
}

fn python_imports_module(imports: &[String], module: &str) -> bool {
    imports.iter().any(|imported| {
        imported == module
            || imported
                .strip_prefix(module)
                .is_some_and(|suffix| suffix.starts_with('.'))
    })
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

    fn python_detector_matches(detector: &SourceFrameworkDetector, source: &str) -> bool {
        let imports = python_imported_modules(source);
        detector.matches("Python", &source.to_ascii_lowercase(), &imports)
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
                !python_detector_matches(falcon, source),
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
            "from falcon import (\n    App,\n)",
            "import\tfalcon",
            "from\tfalcon import App",
            "import\u{0c}falcon",
        ] {
            assert!(
                python_detector_matches(falcon, source),
                "real Falcon import must establish framework usage: {source}"
            );
        }
    }

    #[test]
    fn python_framework_detection_ignores_import_text_inside_strings() {
        let falcon = detector("Falcon");
        for source in [
            "\"\"\"\nimport falcon\n\"\"\"\nclient = falcon.App()",
            "'''\nfrom falcon import App\n'''",
            "doc = \"\"\"usage:\n    import falcon\n\"\"\"",
        ] {
            assert!(
                !python_detector_matches(falcon, source),
                "string-literal text must not establish Falcon usage: {source}"
            );
        }
    }

    #[test]
    fn python_framework_detection_accepts_import_after_triple_quote_text_in_non_code_contexts() {
        let falcon = detector("Falcon");
        for source in [
            "# unmatched doc marker \"\"\" in a comment\nimport falcon",
            "marker = 'not a delimiter: \"\"\"'\nimport falcon",
            "marker = \"not a delimiter: '''\"\nfrom falcon import App",
        ] {
            assert!(
                python_detector_matches(falcon, source),
                "comment/string contents must not suppress later real imports: {source}"
            );
        }
    }

    #[test]
    fn python_framework_detection_accepts_backslash_continued_imports() {
        let falcon = detector("Falcon");
        for source in [
            "import os, \\\n    falcon",
            "from falcon \\\n    import App",
        ] {
            assert!(
                python_detector_matches(falcon, source),
                "backslash-continued import must establish framework usage: {source}"
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
                python_detector_matches(detector, &source),
                "{} detector must accept an import of {module}",
                detector.framework
            );
        }
    }
}
