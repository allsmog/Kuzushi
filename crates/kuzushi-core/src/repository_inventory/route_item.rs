use super::*;

pub(crate) fn route_item(
    relative: &str,
    line_number: u32,
    method: &str,
    route: &str,
    framework: &str,
    detail: String,
) -> InventoryRouteController {
    InventoryRouteController {
        kind: "route".to_string(),
        path: relative.to_string(),
        line: Some(line_number),
        method: Some(method.to_string()),
        route: Some(route.to_string()),
        framework: Some(framework.to_string()),
        detail,
    }
}

pub(crate) fn manifest_kind(relative: &str, file_name: &str) -> Option<&'static str> {
    let lower_name = file_name.to_ascii_lowercase();
    let lower_path = relative.to_ascii_lowercase();
    match lower_name.as_str() {
        "package.json" => Some("node-package"),
        "pyproject.toml" => Some("python-project"),
        "requirements.txt" => Some("python-requirements"),
        "go.mod" => Some("go-module"),
        "cargo.toml" => Some("rust-cargo"),
        "pom.xml" => Some("maven-project"),
        "build.gradle" | "build.gradle.kts" => Some("gradle-project"),
        "gemfile" => Some("ruby-gemfile"),
        _ if lower_path.ends_with("/requirements.txt") => Some("python-requirements"),
        _ => None,
    }
}

pub(crate) fn dependency_manifest_kind(relative: &str, file_name: &str) -> Option<&'static str> {
    let lower_name = file_name.to_ascii_lowercase();
    let lower_path = relative.to_ascii_lowercase();
    if lower_path.ends_with("/requirements.txt") {
        return Some("python-requirements");
    }
    lookup_named_kind(&lower_name, dependency_manifest_kind_table())
}

fn dependency_manifest_kind_table() -> &'static [(&'static [&'static str], &'static str)] {
    &[
        (&["package.json"], "node-dependencies"),
        (
            &["package-lock.json", "npm-shrinkwrap.json"],
            "npm-lockfile",
        ),
        (&["pnpm-lock.yaml"], "pnpm-lockfile"),
        (&["yarn.lock"], "yarn-lockfile"),
        (&["bun.lockb"], "bun-lockfile"),
        (&["pyproject.toml"], "python-project-dependencies"),
        (&["poetry.lock"], "poetry-lockfile"),
        (&["pipfile", "pipfile.lock"], "pipenv-dependencies"),
        (&["requirements.txt"], "python-requirements"),
        (&["go.mod"], "go-module-dependencies"),
        (&["go.sum"], "go-checksums"),
        (&["cargo.toml"], "rust-cargo-dependencies"),
        (&["cargo.lock"], "rust-cargo-lockfile"),
        (&["pom.xml"], "maven-dependencies"),
        (&["build.gradle", "build.gradle.kts"], "gradle-dependencies"),
        (&["gemfile", "gemfile.lock"], "ruby-dependencies"),
    ]
}

fn lookup_named_kind(
    lower_name: &str,
    table: &[(&'static [&'static str], &'static str)],
) -> Option<&'static str> {
    table
        .iter()
        .find(|(names, _)| names.contains(&lower_name))
        .map(|(_, kind)| *kind)
}

pub(crate) fn config_file_kind(relative: &str, file_name: &str) -> Option<&'static str> {
    let lower_name = file_name.to_ascii_lowercase();
    let lower_path = relative.to_ascii_lowercase();
    match lower_name.as_str() {
        "dockerfile" => Some("dockerfile"),
        "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml" => {
            Some("compose")
        }
        "tsconfig.json" => Some("typescript-config"),
        "jsconfig.json" => Some("javascript-config"),
        "vite.config.js" | "vite.config.ts" => Some("vite-config"),
        "next.config.js" | "next.config.mjs" | "next.config.ts" => Some("next-config"),
        "webpack.config.js" | "webpack.config.ts" => Some("webpack-config"),
        "ruff.toml" | "mypy.ini" | "pytest.ini" | "tox.ini" => Some("python-tool-config"),
        ".env.example" | ".env.sample" => Some("environment-template"),
        _ if lower_path.starts_with("config/") => Some("application-config"),
        _ if lower_name.ends_with(".config.js") || lower_name.ends_with(".config.ts") => {
            Some("tool-config")
        }
        _ => None,
    }
}

pub(crate) fn language_for_path(path: &Path) -> Option<&'static str> {
    let extension = path.extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "js" | "jsx" | "mjs" | "cjs" => Some("JavaScript"),
        "ts" | "tsx" => Some("TypeScript"),
        "py" => Some("Python"),
        "go" => Some("Go"),
        "rs" => Some("Rust"),
        "java" => Some("Java"),
        "kt" | "kts" => Some("Kotlin"),
        "rb" => Some("Ruby"),
        "php" => Some("PHP"),
        "c" | "h" => Some("C"),
        "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" => Some("C++"),
        _ => None,
    }
}
