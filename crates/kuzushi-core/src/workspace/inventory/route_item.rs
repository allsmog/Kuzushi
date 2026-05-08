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
    lookup_named_kind(&lower_name, manifest_kind_table()).or_else(|| requirements_kind(&lower_path))
}

fn manifest_kind_table() -> &'static [(&'static [&'static str], &'static str)] {
    &[
        (&["package.json"], "node-package"),
        (&["pyproject.toml"], "python-project"),
        (&["requirements.txt"], "python-requirements"),
        (&["go.mod"], "go-module"),
        (&["cargo.toml"], "rust-cargo"),
        (&["pom.xml"], "maven-project"),
        (&["build.gradle", "build.gradle.kts"], "gradle-project"),
        (&["gemfile"], "ruby-gemfile"),
    ]
}

fn requirements_kind(lower_path: &str) -> Option<&'static str> {
    lower_path
        .ends_with("/requirements.txt")
        .then_some("python-requirements")
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
    lookup_named_kind(&lower_name, config_file_kind_table())
        .or_else(|| config_path_kind(&lower_path))
        .or_else(|| tool_config_kind(&lower_name))
}

fn config_file_kind_table() -> &'static [(&'static [&'static str], &'static str)] {
    &[
        (&["dockerfile"], "dockerfile"),
        (
            &[
                "docker-compose.yml",
                "docker-compose.yaml",
                "compose.yml",
                "compose.yaml",
            ],
            "compose",
        ),
        (&["tsconfig.json"], "typescript-config"),
        (&["jsconfig.json"], "javascript-config"),
        (&["vite.config.js", "vite.config.ts"], "vite-config"),
        (
            &["next.config.js", "next.config.mjs", "next.config.ts"],
            "next-config",
        ),
        (
            &["webpack.config.js", "webpack.config.ts"],
            "webpack-config",
        ),
        (
            &["ruff.toml", "mypy.ini", "pytest.ini", "tox.ini"],
            "python-tool-config",
        ),
        (&[".env.example", ".env.sample"], "environment-template"),
    ]
}

fn config_path_kind(lower_path: &str) -> Option<&'static str> {
    lower_path
        .starts_with("config/")
        .then_some("application-config")
}

fn tool_config_kind(lower_name: &str) -> Option<&'static str> {
    (lower_name.ends_with(".config.js") || lower_name.ends_with(".config.ts"))
        .then_some("tool-config")
}
