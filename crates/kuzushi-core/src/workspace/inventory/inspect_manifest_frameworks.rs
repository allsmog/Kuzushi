use super::*;

pub(crate) fn inspect_manifest_frameworks(
    relative: &str,
    file_name: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    let lower_name = file_name.to_ascii_lowercase();
    let lower = text.to_ascii_lowercase();

    inspect_manifest_framework_entries(relative, &lower_name, &lower, builder);
    if lower_name == "package.json" && lower.contains("\"start\"") {
        builder.add_entrypoint(
            "node-start-script",
            relative,
            "package manifest start script",
        );
    }
}

fn inspect_manifest_framework_entries(
    relative: &str,
    lower_name: &str,
    lower: &str,
    builder: &mut InventoryBuilder,
) {
    let probes = manifest_framework_probes(lower_name);
    if probes.is_empty() {
        return;
    }
    let declarations = manifest_declaration_lines(lower);
    for (language, needles) in probes {
        inspect_framework_needles(relative, &declarations, language, builder, needles);
    }
}

type FrameworkProbe = (&'static str, &'static [(&'static str, &'static str)]);

/// The needle tables that apply to one manifest, resolved from its file name
/// alone so a source file never pays for the declaration-line scan.
fn manifest_framework_probes(lower_name: &str) -> Vec<FrameworkProbe> {
    let mut probes = Vec::new();
    if lower_name.ends_with(".csproj") {
        probes.push(("C#", DOTNET_FRAMEWORK_PROBES));
    }
    for entry in MANIFEST_FRAMEWORK_ENTRIES {
        if entry.matches_file(lower_name) {
            probes.push((entry.language, entry.needles));
        }
    }
    probes
}

struct ManifestFrameworkEntry {
    file_names: &'static [&'static str],
    language: &'static str,
    needles: &'static [(&'static str, &'static str)],
}

impl ManifestFrameworkEntry {
    fn matches_file(&self, lower_name: &str) -> bool {
        self.file_names.contains(&lower_name)
    }
}

const MANIFEST_FRAMEWORK_ENTRIES: &[ManifestFrameworkEntry] = &[
    ManifestFrameworkEntry {
        file_names: &["package.json"],
        language: "JavaScript",
        needles: &[
            ("\"elysia\"", "Elysia"),
            ("\"express\"", "Express"),
            ("\"fastify\"", "Fastify"),
            ("\"hono\"", "Hono"),
            ("\"koa\"", "Koa"),
            ("\"next\"", "Next.js"),
            ("\"react\"", "React"),
            ("\"@nestjs/core\"", "NestJS"),
        ],
    },
    ManifestFrameworkEntry {
        file_names: &["pyproject.toml", "requirements.txt"],
        language: "Python",
        needles: &[
            ("aiohttp", "aiohttp"),
            ("bottle", "Bottle"),
            ("django", "Django"),
            ("falcon", "Falcon"),
            ("fastapi", "FastAPI"),
            ("flask", "Flask"),
            ("litestar", "Litestar"),
            ("pyramid", "Pyramid"),
            ("sanic", "Sanic"),
            ("starlette", "Starlette"),
            ("starlite", "Litestar"),
            ("tornado", "Tornado"),
        ],
    },
    ManifestFrameworkEntry {
        file_names: &["go.mod"],
        language: "Go",
        needles: &[
            ("github.com/gin-gonic/gin", "Gin"),
            ("github.com/gorilla/mux", "Gorilla Mux"),
            ("google.golang.org/grpc", "gRPC"),
        ],
    },
    ManifestFrameworkEntry {
        file_names: &["cargo.toml"],
        language: "Rust",
        needles: &[
            ("axum", "Axum"),
            ("actix-web", "Actix Web"),
            ("rocket", "Rocket"),
            ("warp", "Warp"),
            ("tonic", "Tonic"),
        ],
    },
    ManifestFrameworkEntry {
        file_names: &["build.gradle", "build.gradle.kts", "pom.xml"],
        language: "Java",
        needles: &[
            ("spring-boot-starter", "Spring"),
            ("org.springframework", "Spring"),
        ],
    },
    ManifestFrameworkEntry {
        file_names: &["gemfile"],
        language: "Ruby",
        needles: &[("rails", "Rails")],
    },
    ManifestFrameworkEntry {
        file_names: &["composer.json"],
        language: "PHP",
        needles: &[("laravel/framework", "Laravel")],
    },
];

const DOTNET_FRAMEWORK_PROBES: &[(&str, &str)] = &[
    ("microsoft.net.sdk.web", "ASP.NET Core"),
    ("microsoft.aspnetcore", "ASP.NET Core"),
];

fn inspect_framework_needles(
    relative: &str,
    declarations: &[&str],
    language: &str,
    builder: &mut InventoryBuilder,
    needles: &[(&str, &str)],
) {
    for (needle, framework) in needles {
        if declares_framework(declarations, needle) {
            builder.add_framework(framework, language, framework_evidence(relative, framework));
        }
    }
}

fn declares_framework(declarations: &[&str], needle: &str) -> bool {
    declarations
        .iter()
        .any(|line| declares_package_token(line, needle))
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
