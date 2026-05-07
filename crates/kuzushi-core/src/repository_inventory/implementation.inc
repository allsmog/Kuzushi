use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryInventory {
    pub root_name: String,
    pub languages: Vec<InventoryLanguage>,
    pub source_files: Vec<InventorySourceFile>,
    pub manifests: Vec<InventoryFile>,
    pub dependency_manifests: Vec<InventoryFile>,
    pub config_files: Vec<InventoryFile>,
    pub frameworks: Vec<InventoryFramework>,
    pub entrypoints: Vec<InventoryEntrypoint>,
    pub routes_controllers: Vec<InventoryRouteController>,
    pub generated_vendor_paths: Vec<InventoryPathClassification>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventoryLanguage {
    pub name: String,
    pub files: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventorySourceFile {
    pub path: String,
    pub language: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventoryFile {
    pub path: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventoryFramework {
    pub name: String,
    pub language: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventoryEntrypoint {
    pub kind: String,
    pub path: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventoryRouteController {
    pub kind: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InventoryPathClassification {
    pub path: String,
    pub kind: String,
    pub reason: String,
}

#[derive(Debug, Default)]
struct InventoryBuilder {
    languages: BTreeMap<String, LanguageAccumulator>,
    source_files: BTreeMap<String, InventorySourceFile>,
    manifests: BTreeMap<String, InventoryFile>,
    dependency_manifests: BTreeMap<String, InventoryFile>,
    config_files: BTreeMap<String, InventoryFile>,
    frameworks: BTreeMap<(String, String), FrameworkAccumulator>,
    entrypoints: BTreeMap<String, InventoryEntrypoint>,
    routes_controllers: BTreeMap<String, InventoryRouteController>,
    generated_vendor_paths: BTreeMap<String, InventoryPathClassification>,
}

#[derive(Debug, Default)]
struct LanguageAccumulator {
    files: usize,
    bytes: u64,
}

#[derive(Debug, Default)]
struct FrameworkAccumulator {
    evidence: BTreeSet<String>,
}

pub fn build_repository_inventory(root: impl AsRef<Path>) -> Result<RepositoryInventory> {
    let root = root
        .as_ref()
        .canonicalize()
        .with_context(|| format!("repository root {} does not exist", root.as_ref().display()))?;
    if !root.is_dir() {
        anyhow::bail!("repository root {} is not a directory", root.display());
    }

    let mut builder = InventoryBuilder::default();
    walk_repository(&root, &root, &mut builder)?;
    Ok(builder.finish(root_name(&root)))
}

fn walk_repository(root: &Path, dir: &Path, builder: &mut InventoryBuilder) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy().to_string();
        let relative = repo_relative(root, &path);

        if file_type.is_dir() {
            if ignored_dir(&name) {
                continue;
            }
            if let Some(classification) = generated_vendor_path(&relative, &name, true) {
                builder.add_generated_vendor_path(classification);
                continue;
            }
            walk_repository(root, &path, builder)?;
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        let generated_vendor = generated_vendor_path(&relative, &name, false);
        if let Some(classification) = generated_vendor.clone() {
            builder.add_generated_vendor_path(classification);
        }

        if let Some(kind) = manifest_kind(&relative, &name) {
            builder.add_manifest(&relative, kind);
        }
        if let Some(kind) = dependency_manifest_kind(&relative, &name) {
            builder.add_dependency_manifest(&relative, kind);
        }
        if let Some(kind) = config_file_kind(&relative, &name) {
            builder.add_config_file(&relative, kind);
        }

        let Some(text) = read_text_prefix(&path, 256 * 1024)? else {
            continue;
        };
        inspect_manifest_frameworks(&relative, &name, &text, builder);

        if generated_vendor.is_some() {
            continue;
        }

        let Some(language) = language_for_path(&path) else {
            continue;
        };
        builder.add_source_file(&relative, language, text.len() as u64);
        inspect_source_file(&relative, language, &text, builder);
    }

    Ok(())
}

impl InventoryBuilder {
    fn add_source_file(&mut self, path: &str, language: &str, bytes: u64) {
        let language_accumulator = self.languages.entry(language.to_string()).or_default();
        language_accumulator.files += 1;
        language_accumulator.bytes += bytes;
        self.source_files.insert(
            path.to_string(),
            InventorySourceFile {
                path: path.to_string(),
                language: language.to_string(),
            },
        );
    }

    fn add_manifest(&mut self, path: &str, kind: &str) {
        self.manifests.insert(
            path.to_string(),
            InventoryFile {
                path: path.to_string(),
                kind: kind.to_string(),
            },
        );
    }

    fn add_dependency_manifest(&mut self, path: &str, kind: &str) {
        self.dependency_manifests.insert(
            path.to_string(),
            InventoryFile {
                path: path.to_string(),
                kind: kind.to_string(),
            },
        );
    }

    fn add_config_file(&mut self, path: &str, kind: &str) {
        self.config_files.insert(
            path.to_string(),
            InventoryFile {
                path: path.to_string(),
                kind: kind.to_string(),
            },
        );
    }

    fn add_framework(&mut self, name: &str, language: &str, evidence: impl Into<String>) {
        self.frameworks
            .entry((name.to_string(), language.to_string()))
            .or_default()
            .evidence
            .insert(evidence.into());
    }

    fn add_entrypoint(&mut self, kind: &str, path: &str, detail: &str) {
        let key = format!("{kind}:{path}:{detail}");
        self.entrypoints
            .entry(key)
            .or_insert_with(|| InventoryEntrypoint {
                kind: kind.to_string(),
                path: path.to_string(),
                detail: detail.to_string(),
            });
    }

    fn add_route_controller(&mut self, item: InventoryRouteController) {
        let key = format!(
            "{}:{}:{:?}:{:?}:{:?}",
            item.kind, item.path, item.line, item.method, item.route
        );
        self.routes_controllers.entry(key).or_insert(item);
    }

    fn add_generated_vendor_path(&mut self, item: InventoryPathClassification) {
        self.generated_vendor_paths
            .entry(item.path.clone())
            .or_insert(item);
    }

    fn finish(self, root_name: String) -> RepositoryInventory {
        RepositoryInventory {
            root_name,
            languages: self
                .languages
                .into_iter()
                .map(|(name, accumulator)| InventoryLanguage {
                    name,
                    files: accumulator.files,
                    bytes: accumulator.bytes,
                })
                .collect(),
            source_files: self.source_files.into_values().collect(),
            manifests: self.manifests.into_values().collect(),
            dependency_manifests: self.dependency_manifests.into_values().collect(),
            config_files: self.config_files.into_values().collect(),
            frameworks: self
                .frameworks
                .into_iter()
                .map(|((name, language), accumulator)| InventoryFramework {
                    name,
                    language,
                    evidence: accumulator.evidence.into_iter().collect(),
                })
                .collect(),
            entrypoints: self.entrypoints.into_values().collect(),
            routes_controllers: self.routes_controllers.into_values().collect(),
            generated_vendor_paths: self.generated_vendor_paths.into_values().collect(),
        }
    }
}

fn inspect_manifest_frameworks(
    relative: &str,
    file_name: &str,
    text: &str,
    builder: &mut InventoryBuilder,
) {
    let lower_name = file_name.to_ascii_lowercase();
    let lower = text.to_ascii_lowercase();
    let evidence = |framework: &str| format!("{relative} references {framework}");

    if lower_name == "package.json" {
        for (needle, framework) in [
            ("\"express\"", "Express"),
            ("\"fastify\"", "Fastify"),
            ("\"koa\"", "Koa"),
            ("\"next\"", "Next.js"),
            ("\"react\"", "React"),
            ("\"@nestjs/core\"", "NestJS"),
        ] {
            if lower.contains(needle) {
                builder.add_framework(framework, "JavaScript", evidence(framework));
            }
        }
        if lower.contains("\"start\"") {
            builder.add_entrypoint(
                "node-start-script",
                relative,
                "package manifest start script",
            );
        }
    }

    if matches!(lower_name.as_str(), "pyproject.toml" | "requirements.txt") {
        for (needle, framework) in [
            ("django", "Django"),
            ("fastapi", "FastAPI"),
            ("flask", "Flask"),
        ] {
            if lower.contains(needle) {
                builder.add_framework(framework, "Python", evidence(framework));
            }
        }
    }

    if lower_name == "go.mod" {
        if lower.contains("github.com/gin-gonic/gin") {
            builder.add_framework("Gin", "Go", evidence("Gin"));
        }
        if lower.contains("github.com/gorilla/mux") {
            builder.add_framework("Gorilla Mux", "Go", evidence("Gorilla Mux"));
        }
        if lower.contains("google.golang.org/grpc") {
            builder.add_framework("gRPC", "Go", evidence("gRPC"));
        }
    }

    if lower_name == "cargo.toml" {
        for (needle, framework) in [
            ("axum", "Axum"),
            ("actix-web", "Actix Web"),
            ("rocket", "Rocket"),
            ("warp", "Warp"),
            ("tonic", "Tonic"),
        ] {
            if lower.contains(needle) {
                builder.add_framework(framework, "Rust", evidence(framework));
            }
        }
    }
}

fn inspect_source_file(relative: &str, language: &str, text: &str, builder: &mut InventoryBuilder) {
    inspect_entrypoints(relative, language, text, builder);
    inspect_source_frameworks(relative, language, text, builder);
    inspect_routes(relative, language, text, builder);
    inspect_controller_path(relative, builder);
}

fn inspect_source_frameworks(
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

fn inspect_entrypoints(relative: &str, language: &str, text: &str, builder: &mut InventoryBuilder) {
    let lower_path = relative.to_ascii_lowercase();
    let lower = text.to_ascii_lowercase();
    let file_name = Path::new(relative)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(relative)
        .to_ascii_lowercase();

    match language {
        "JavaScript" | "TypeScript" => {
            if matches!(
                file_name.as_str(),
                "server.js" | "server.ts" | "app.js" | "app.ts" | "index.js" | "index.ts"
            ) && contains_any(&lower, &[".listen(", "createserver(", "express("])
            {
                builder.add_entrypoint(
                    "node-server",
                    relative,
                    "server file with listener or app factory",
                );
            }
        }
        "Python" => {
            if matches!(file_name.as_str(), "app.py" | "main.py" | "manage.py")
                || lower.contains("if __name__ == \"__main__\"")
                || lower.contains("if __name__ == '__main__'")
                || lower.contains("uvicorn.run(")
            {
                builder.add_entrypoint("python-app", relative, "Python application entrypoint");
            }
        }
        "Go" => {
            if lower.contains("package main") && lower.contains("func main(") {
                builder.add_entrypoint("go-main", relative, "Go package main entrypoint");
            }
        }
        "Rust" => {
            if lower_path == "src/main.rs"
                || lower.contains("fn main(")
                || lower.contains("#[tokio::main]")
            {
                builder.add_entrypoint("rust-binary", relative, "Rust binary entrypoint");
            }
        }
        _ => {}
    }
}

fn inspect_routes(relative: &str, language: &str, text: &str, builder: &mut InventoryBuilder) {
    for (index, line) in text.lines().enumerate() {
        let line_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        match language {
            "JavaScript" | "TypeScript" => {
                inspect_node_route_line(relative, line_number, line, builder)
            }
            "Python" => inspect_python_route_line(relative, line_number, line, builder),
            "Go" => inspect_go_route_line(relative, line_number, line, builder),
            "Rust" => inspect_rust_route_line(relative, line_number, line, builder),
            _ => {}
        }
    }
}

fn inspect_node_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    builder: &mut InventoryBuilder,
) {
    for (method, marker) in [
        ("GET", ".get("),
        ("POST", ".post("),
        ("PUT", ".put("),
        ("PATCH", ".patch("),
        ("DELETE", ".delete("),
        ("USE", ".use("),
        ("ANY", ".all("),
    ] {
        if let Some(route) = extract_quoted_after_marker(line, marker) {
            builder.add_route_controller(route_item(
                relative,
                line_number,
                method,
                &route,
                "Express",
                trim_detail(line),
            ));
        }
    }
}

fn inspect_python_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    builder: &mut InventoryBuilder,
) {
    let trimmed = line.trim();
    if !trimmed.starts_with('@') {
        return;
    }
    for (method, marker, framework) in [
        ("ANY", ".route(", "Flask"),
        ("GET", ".get(", "FastAPI"),
        ("POST", ".post(", "FastAPI"),
        ("PUT", ".put(", "FastAPI"),
        ("PATCH", ".patch(", "FastAPI"),
        ("DELETE", ".delete(", "FastAPI"),
    ] {
        if let Some(route) = extract_quoted_after_marker(trimmed, marker) {
            let method = if method == "ANY" {
                python_route_methods(trimmed).unwrap_or_else(|| method.to_string())
            } else {
                method.to_string()
            };
            builder.add_route_controller(route_item(
                relative,
                line_number,
                &method,
                &route,
                framework,
                trim_detail(line),
            ));
        }
    }
}

fn inspect_go_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    builder: &mut InventoryBuilder,
) {
    for (method, marker, framework) in [
        ("ANY", "http.handlefunc(", "net/http"),
        ("ANY", ".handlefunc(", "net/http"),
        ("GET", ".get(", "Gin"),
        ("POST", ".post(", "Gin"),
        ("PUT", ".put(", "Gin"),
        ("PATCH", ".patch(", "Gin"),
        ("DELETE", ".delete(", "Gin"),
    ] {
        if let Some(route) = extract_quoted_after_marker_case_insensitive(line, marker) {
            builder.add_route_controller(route_item(
                relative,
                line_number,
                method,
                &route,
                framework,
                trim_detail(line),
            ));
        }
    }
}

fn inspect_rust_route_line(
    relative: &str,
    line_number: u32,
    line: &str,
    builder: &mut InventoryBuilder,
) {
    for (method, marker, framework) in [
        ("ANY", ".route(", "Axum"),
        ("GET", "#[get(", "Actix Web"),
        ("POST", "#[post(", "Actix Web"),
        ("PUT", "#[put(", "Actix Web"),
        ("PATCH", "#[patch(", "Actix Web"),
        ("DELETE", "#[delete(", "Actix Web"),
    ] {
        if let Some(route) = extract_quoted_after_marker_case_insensitive(line, marker) {
            builder.add_route_controller(route_item(
                relative,
                line_number,
                method,
                &route,
                framework,
                trim_detail(line),
            ));
        }
    }
}

fn inspect_controller_path(relative: &str, builder: &mut InventoryBuilder) {
    let lower = relative.to_ascii_lowercase();
    if lower.contains("/controllers/")
        || lower.contains("/controller/")
        || lower.contains("controller.")
        || lower.contains("/handlers/")
        || lower.contains("/routes/")
    {
        builder.add_route_controller(InventoryRouteController {
            kind: "controller".to_string(),
            path: relative.to_string(),
            line: None,
            method: None,
            route: None,
            framework: None,
            detail: "controller, route, or handler path".to_string(),
        });
    }
}

fn route_item(
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

fn manifest_kind(relative: &str, file_name: &str) -> Option<&'static str> {
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

fn dependency_manifest_kind(relative: &str, file_name: &str) -> Option<&'static str> {
    let lower_name = file_name.to_ascii_lowercase();
    let lower_path = relative.to_ascii_lowercase();
    match lower_name.as_str() {
        "package.json" => Some("node-dependencies"),
        "package-lock.json" | "npm-shrinkwrap.json" => Some("npm-lockfile"),
        "pnpm-lock.yaml" => Some("pnpm-lockfile"),
        "yarn.lock" => Some("yarn-lockfile"),
        "bun.lockb" => Some("bun-lockfile"),
        "pyproject.toml" => Some("python-project-dependencies"),
        "poetry.lock" => Some("poetry-lockfile"),
        "pipfile" | "pipfile.lock" => Some("pipenv-dependencies"),
        "requirements.txt" => Some("python-requirements"),
        "go.mod" => Some("go-module-dependencies"),
        "go.sum" => Some("go-checksums"),
        "cargo.toml" => Some("rust-cargo-dependencies"),
        "cargo.lock" => Some("rust-cargo-lockfile"),
        "pom.xml" => Some("maven-dependencies"),
        "build.gradle" | "build.gradle.kts" => Some("gradle-dependencies"),
        "gemfile" | "gemfile.lock" => Some("ruby-dependencies"),
        _ if lower_path.ends_with("/requirements.txt") => Some("python-requirements"),
        _ => None,
    }
}

fn config_file_kind(relative: &str, file_name: &str) -> Option<&'static str> {
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

fn language_for_path(path: &Path) -> Option<&'static str> {
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

fn generated_vendor_path(
    relative: &str,
    file_name: &str,
    is_dir: bool,
) -> Option<InventoryPathClassification> {
    let lower_name = file_name.to_ascii_lowercase();
    let lower_path = relative.to_ascii_lowercase();
    let (kind, reason) = if is_dir && vendor_dir(&lower_name) {
        ("vendor", "dependency or vendored source directory")
    } else if is_dir && generated_dir(&lower_name) {
        ("generated", "generated or build output directory")
    } else if !is_dir && generated_file(&lower_path) {
        ("generated", "generated source file")
    } else {
        return None;
    };
    Some(InventoryPathClassification {
        path: relative.to_string(),
        kind: kind.to_string(),
        reason: reason.to_string(),
    })
}

fn ignored_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | ".hg" | ".svn" | ".kuzushi" | ".codex-active" | ".ruff_cache" | ".pytest_cache"
    )
}

fn vendor_dir(name: &str) -> bool {
    matches!(
        name,
        "node_modules"
            | "vendor"
            | "third_party"
            | "third-party"
            | "external"
            | ".venv"
            | "venv"
            | "__pycache__"
    )
}

fn generated_dir(name: &str) -> bool {
    matches!(
        name,
        "target"
            | "dist"
            | "build"
            | "out"
            | ".next"
            | "coverage"
            | "generated"
            | "gen"
            | "__generated__"
    )
}

fn generated_file(path: &str) -> bool {
    path.ends_with(".pb.go")
        || path.ends_with(".gen.go")
        || path.ends_with(".generated.ts")
        || path.ends_with(".generated.js")
        || path.ends_with(".g.rs")
        || path.contains("/generated/")
        || path.contains("/__generated__/")
}

fn read_text_prefix(path: &Path, max_bytes: usize) -> Result<Option<String>> {
    let bytes = fs::read(path).with_context(|| format!("Could not read {}", path.display()))?;
    if bytes.iter().take(4096).any(|byte| *byte == 0) {
        return Ok(None);
    }
    let prefix = &bytes[..bytes.len().min(max_bytes)];
    Ok(Some(String::from_utf8_lossy(prefix).to_string()))
}

fn repo_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn root_name(root: &Path) -> String {
    root.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repository")
        .to_string()
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn trim_detail(line: &str) -> String {
    line.trim().split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_quoted_after_marker(line: &str, marker: &str) -> Option<String> {
    let index = line.find(marker)?;
    extract_first_quoted(&line[index + marker.len()..])
}

fn extract_quoted_after_marker_case_insensitive(line: &str, marker: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let index = lower.find(marker)?;
    extract_first_quoted(&line[index + marker.len()..])
}

fn extract_first_quoted(value: &str) -> Option<String> {
    let mut chars = value.char_indices();
    while let Some((start, quote)) = chars.next() {
        if !matches!(quote, '"' | '\'' | '`') {
            continue;
        }
        for (offset, ch) in value[start + quote.len_utf8()..].char_indices() {
            if ch == quote {
                let end = start + quote.len_utf8() + offset;
                let candidate = &value[start + quote.len_utf8()..end];
                if !candidate.trim().is_empty() {
                    return Some(candidate.to_string());
                }
                return None;
            }
        }
    }
    None
}

fn python_route_methods(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let methods_index = lower.find("methods")?;
    let method_area = &lower[methods_index..];
    let mut methods = Vec::new();
    for method in ["get", "post", "put", "patch", "delete"] {
        if method_area.contains(method) {
            methods.push(method.to_ascii_uppercase());
        }
    }
    if methods.is_empty() {
        None
    } else {
        Some(methods.join(","))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn repository_inventory_detects_node_express_routes_and_manifests() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/controllers")).unwrap();
        fs::create_dir_all(temp.path().join("node_modules/express")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"scripts":{"start":"node src/server.js"},"dependencies":{"express":"^4.18.0"}}"#,
        )
        .unwrap();
        fs::write(temp.path().join("package-lock.json"), "{}\n").unwrap();
        fs::write(temp.path().join("tsconfig.json"), "{}\n").unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import express from 'express';\nconst app = express();\napp.get('/users', handler);\napp.listen(3000);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/controllers/userController.ts"),
            "export function handler() {}\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("node_modules/express/index.js"),
            "module.exports = {}\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_language(&inventory, "TypeScript", 2);
        assert_has_file(&inventory.manifests, "package.json", "node-package");
        assert_has_file(
            &inventory.dependency_manifests,
            "package-lock.json",
            "npm-lockfile",
        );
        assert_has_file(
            &inventory.config_files,
            "tsconfig.json",
            "typescript-config",
        );
        assert_framework(&inventory, "Express", "JavaScript");
        assert!(inventory.entrypoints.iter().any(|entrypoint| {
            entrypoint.kind == "node-start-script" && entrypoint.path == "package.json"
        }));
        assert!(inventory.entrypoints.iter().any(|entrypoint| {
            entrypoint.kind == "node-server" && entrypoint.path == "src/server.ts"
        }));
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.kind == "route"
                && item.method.as_deref() == Some("GET")
                && item.route.as_deref() == Some("/users")
        }));
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.kind == "controller" && item.path == "src/controllers/userController.ts"
        }));
        assert!(inventory
            .generated_vendor_paths
            .iter()
            .any(|item| item.path == "node_modules" && item.kind == "vendor"));
        assert!(!inventory
            .source_files
            .iter()
            .any(|file| file.path.starts_with("node_modules/")));
    }

    #[test]
    fn repository_inventory_detects_python_frameworks_and_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "fastapi\nflask\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from fastapi import FastAPI\napp = FastAPI()\n@app.post('/items')\ndef create_item(): pass\nif __name__ == '__main__':\n    pass\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_language(&inventory, "Python", 1);
        assert_has_file(
            &inventory.manifests,
            "requirements.txt",
            "python-requirements",
        );
        assert_framework(&inventory, "FastAPI", "Python");
        assert_framework(&inventory, "Flask", "Python");
        assert!(inventory
            .entrypoints
            .iter()
            .any(|entrypoint| entrypoint.kind == "python-app" && entrypoint.path == "app.py"));
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.kind == "route"
                && item.method.as_deref() == Some("POST")
                && item.route.as_deref() == Some("/items")
        }));
    }

    #[test]
    fn python_route_methods_extracts_declared_method_lists() {
        assert_eq!(
            python_route_methods("@app.route('/items', methods=['GET', 'POST'])").as_deref(),
            Some("GET,POST")
        );
        assert_eq!(
            python_route_methods("@bp.route('/item', methods=['delete', 'PATCH'])").as_deref(),
            Some("PATCH,DELETE")
        );
        assert_eq!(python_route_methods("@app.get('/items')"), None);
        assert_eq!(
            python_route_methods("@app.route('/items', methods=[])"),
            None
        );
    }

    #[test]
    fn repository_inventory_detects_go_entrypoints_routes_and_vendor_paths() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("vendor/example")).unwrap();
        fs::write(
            temp.path().join("go.mod"),
            "module demo\nrequire github.com/gin-gonic/gin v1.9.0\n",
        )
        .unwrap();
        fs::write(temp.path().join("go.sum"), "example h1:abc\n").unwrap();
        fs::write(
            temp.path().join("main.go"),
            "package main\nimport \"net/http\"\nfunc main() { http.HandleFunc(\"/health\", health) }\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_language(&inventory, "Go", 1);
        assert_has_file(&inventory.manifests, "go.mod", "go-module");
        assert_has_file(&inventory.dependency_manifests, "go.sum", "go-checksums");
        assert_framework(&inventory, "Gin", "Go");
        assert_framework(&inventory, "net/http", "Go");
        assert!(inventory
            .entrypoints
            .iter()
            .any(|entrypoint| entrypoint.kind == "go-main" && entrypoint.path == "main.go"));
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.route.as_deref() == Some("/health")
                && item.framework.as_deref() == Some("net/http")
        }));
        assert!(inventory
            .generated_vendor_paths
            .iter()
            .any(|item| item.path == "vendor" && item.kind == "vendor"));
    }

    #[test]
    fn repository_inventory_detects_rust_entrypoints_and_config() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::create_dir_all(temp.path().join("target/debug")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\n[dependencies]\naxum = \"0.7\"\n",
        )
        .unwrap();
        fs::write(temp.path().join("Cargo.lock"), "# lock\n").unwrap();
        fs::write(
            temp.path().join("src/main.rs"),
            "use axum::{routing::get, Router};\n#[tokio::main]\nasync fn main() { let app = Router::new().route(\"/ready\", get(ready)); }\n",
        )
        .unwrap();
        fs::write(temp.path().join("Dockerfile"), "FROM scratch\n").unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_language(&inventory, "Rust", 1);
        assert_has_file(&inventory.manifests, "Cargo.toml", "rust-cargo");
        assert_has_file(
            &inventory.dependency_manifests,
            "Cargo.lock",
            "rust-cargo-lockfile",
        );
        assert_has_file(&inventory.config_files, "Dockerfile", "dockerfile");
        assert_framework(&inventory, "Axum", "Rust");
        assert!(
            inventory
                .entrypoints
                .iter()
                .any(|entrypoint| entrypoint.kind == "rust-binary"
                    && entrypoint.path == "src/main.rs")
        );
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.route.as_deref() == Some("/ready") && item.framework.as_deref() == Some("Axum")
        }));
        assert!(inventory
            .generated_vendor_paths
            .iter()
            .any(|item| item.path == "target" && item.kind == "generated"));
    }

    #[test]
    fn repository_inventory_is_deterministic_for_mixed_fixtures_and_skips_generated_sources() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/generated")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"next":"14.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("pyproject.toml"),
            "[project]\ndependencies = ['django']\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"mixed\"\n",
        )
        .unwrap();
        fs::write(temp.path().join("src/api.ts"), "export const ok = true;\n").unwrap();
        fs::write(temp.path().join("worker.py"), "print('ok')\n").unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn ok() {}\n").unwrap();
        fs::write(
            temp.path().join("src/generated/client.generated.ts"),
            "export const generated = true;\n",
        )
        .unwrap();

        let first = build_repository_inventory(temp.path()).unwrap();
        let second = build_repository_inventory(temp.path()).unwrap();

        assert_eq!(first, second);
        assert_eq!(
            first
                .languages
                .iter()
                .map(|language| language.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Python", "Rust", "TypeScript"]
        );
        assert_framework(&first, "Next.js", "JavaScript");
        assert_framework(&first, "Django", "Python");
        assert!(first
            .generated_vendor_paths
            .iter()
            .any(|item| item.path == "src/generated" && item.kind == "generated"));
        assert!(!first
            .source_files
            .iter()
            .any(|file| file.path == "src/generated/client.generated.ts"));
    }

    fn assert_language(inventory: &RepositoryInventory, name: &str, files: usize) {
        let language = inventory
            .languages
            .iter()
            .find(|language| language.name == name)
            .unwrap_or_else(|| panic!("missing language {name}: {:?}", inventory.languages));
        assert_eq!(language.files, files);
    }

    fn assert_has_file(files: &[InventoryFile], path: &str, kind: &str) {
        assert!(
            files
                .iter()
                .any(|file| file.path == path && file.kind == kind),
            "missing {path} {kind}: {files:?}"
        );
    }

    fn assert_framework(inventory: &RepositoryInventory, name: &str, language: &str) {
        assert!(
            inventory
                .frameworks
                .iter()
                .any(|framework| framework.name == name && framework.language == language),
            "missing framework {name}/{language}: {:?}",
            inventory.frameworks
        );
    }
}
