use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::repository_inventory::{
    build_repository_inventory, InventoryRouteController, InventorySourceFile, RepositoryInventory,
};
use crate::static_evidence::static_content_hash;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AttackSurfaceMap {
    pub root_name: String,
    pub surfaces: Vec<AttackSurface>,
    pub summary: AttackSurfaceSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttackSurfaceSummary {
    pub total: usize,
    pub by_kind: BTreeMap<String, usize>,
    pub by_file: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AttackSurfaceKind {
    HttpRoute,
    RpcHandler,
    CliEntrypoint,
    BackgroundJob,
    DeserializationPoint,
    FileUploadParsePath,
    AuthBoundary,
    DbQueryBoundary,
    CommandExecutionBoundary,
}

impl AttackSurfaceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HttpRoute => "http_route",
            Self::RpcHandler => "rpc_handler",
            Self::CliEntrypoint => "cli_entrypoint",
            Self::BackgroundJob => "background_job",
            Self::DeserializationPoint => "deserialization_point",
            Self::FileUploadParsePath => "file_upload_parse_path",
            Self::AuthBoundary => "auth_boundary",
            Self::DbQueryBoundary => "db_query_boundary",
            Self::CommandExecutionBoundary => "command_execution_boundary",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AttackSurface {
    pub id: String,
    pub kind: AttackSurfaceKind,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub language: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    pub title: String,
    pub evidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boundary: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

impl AttackSurface {
    fn from_draft(draft: AttackSurfaceDraft) -> Self {
        let mut surface = Self {
            id: String::new(),
            kind: draft.kind,
            path: draft.path,
            line: draft.line,
            language: draft.language,
            framework: draft.framework,
            title: draft.title,
            evidence: draft.evidence,
            method: draft.method,
            route: draft.route,
            boundary: draft.boundary,
            metadata: draft.metadata,
        };
        surface.id = attack_surface_id(&surface);
        surface
    }
}

#[derive(Debug, Clone)]
struct AttackSurfaceDraft {
    kind: AttackSurfaceKind,
    path: String,
    line: Option<u32>,
    language: String,
    framework: Option<String>,
    title: String,
    evidence: String,
    method: Option<String>,
    route: Option<String>,
    boundary: Option<String>,
    metadata: Value,
}

#[derive(Debug, Default)]
struct AttackSurfaceBuilder {
    surfaces: BTreeMap<String, AttackSurface>,
}

impl AttackSurfaceBuilder {
    fn add(&mut self, draft: AttackSurfaceDraft) {
        let surface = AttackSurface::from_draft(draft);
        self.surfaces.entry(surface.id.clone()).or_insert(surface);
    }

    fn finish(self, root_name: String) -> AttackSurfaceMap {
        let surfaces = self.surfaces.into_values().collect::<Vec<_>>();
        AttackSurfaceMap {
            root_name,
            summary: summarize_surfaces(&surfaces),
            surfaces,
        }
    }
}

pub fn build_attack_surface_map(root: impl AsRef<Path>) -> Result<AttackSurfaceMap> {
    let inventory = build_repository_inventory(root.as_ref())?;
    build_attack_surface_map_from_inventory(root, &inventory)
}

pub fn build_attack_surface_map_from_inventory(
    root: impl AsRef<Path>,
    inventory: &RepositoryInventory,
) -> Result<AttackSurfaceMap> {
    let root = root
        .as_ref()
        .canonicalize()
        .with_context(|| format!("repository root {} does not exist", root.as_ref().display()))?;
    if !root.is_dir() {
        anyhow::bail!("repository root {} is not a directory", root.display());
    }

    let mut builder = AttackSurfaceBuilder::default();
    add_inventory_surfaces(&mut builder, inventory);
    for source_file in &inventory.source_files {
        inspect_source_file(&root, source_file, &mut builder)?;
    }

    Ok(builder.finish(inventory.root_name.clone()))
}

fn add_inventory_surfaces(builder: &mut AttackSurfaceBuilder, inventory: &RepositoryInventory) {
    for route in &inventory.routes_controllers {
        if route.kind == "route" {
            add_route_surface(builder, route);
        }
    }

    for entrypoint in &inventory.entrypoints {
        builder.add(AttackSurfaceDraft {
            kind: AttackSurfaceKind::CliEntrypoint,
            path: entrypoint.path.clone(),
            line: None,
            language: language_from_path(&entrypoint.path)
                .unwrap_or("Unknown")
                .to_string(),
            framework: None,
            title: format!("Entrypoint: {}", entrypoint.kind),
            evidence: entrypoint.detail.clone(),
            method: None,
            route: None,
            boundary: Some("process_entrypoint".to_string()),
            metadata: json!({
                "source": "repository_inventory",
                "entrypointKind": entrypoint.kind,
            }),
        });
    }
}

fn add_route_surface(builder: &mut AttackSurfaceBuilder, route: &InventoryRouteController) {
    let method = route.method.clone().unwrap_or_else(|| "ANY".to_string());
    let route_path = route.route.clone().unwrap_or_else(|| "unknown".to_string());
    builder.add(AttackSurfaceDraft {
        kind: AttackSurfaceKind::HttpRoute,
        path: route.path.clone(),
        line: route.line,
        language: language_from_path(&route.path)
            .unwrap_or("Unknown")
            .to_string(),
        framework: route.framework.clone(),
        title: format!("{method} {route_path}"),
        evidence: route.detail.clone(),
        method: Some(method),
        route: Some(route_path),
        boundary: Some("public_http".to_string()),
        metadata: json!({ "source": "repository_inventory" }),
    });
}

fn inspect_source_file(
    root: &Path,
    source_file: &InventorySourceFile,
    builder: &mut AttackSurfaceBuilder,
) -> Result<()> {
    let full_path = root.join(&source_file.path);
    let bytes = fs::read(&full_path)
        .with_context(|| format!("Could not read source file {}", full_path.display()))?;
    if bytes.iter().take(4096).any(|byte| *byte == 0) {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&bytes);
    let framework = framework_for_source(&source_file.language, &text);

    for (index, line) in text.lines().enumerate() {
        let line_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        inspect_line(
            source_file,
            framework.as_deref(),
            line_number,
            line,
            builder,
        );
    }

    Ok(())
}

fn inspect_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    match source_file.language.as_str() {
        "JavaScript" | "TypeScript" => {
            inspect_node_line(source_file, framework, line_number, line, builder);
        }
        "Python" => inspect_python_line(source_file, framework, line_number, line, builder),
        "Go" => inspect_go_line(source_file, framework, line_number, line, builder),
        "Rust" => inspect_rust_line(source_file, framework, line_number, line, builder),
        _ => {}
    }
}

fn inspect_node_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    if detail.is_empty() {
        return;
    }
    let lower = detail.to_ascii_lowercase();

    if is_route_line(&lower) && line_has_auth_guard(&lower) {
        let route = node_route_from_line(line);
        builder.add(surface(
            AttackSurfaceKind::AuthBoundary,
            source_file,
            framework,
            line_number,
            "Route auth boundary",
            &detail,
            route.method.as_deref(),
            route.path.as_deref(),
            Some("auth_guard"),
            json!({ "source": "source_line", "detector": "node.express.auth-route" }),
        ));
    } else if line_has_auth_guard(&lower) {
        builder.add(surface(
            AttackSurfaceKind::AuthBoundary,
            source_file,
            framework,
            line_number,
            "Authentication or authorization guard",
            &detail,
            None,
            None,
            Some("auth_guard"),
            json!({ "source": "source_line", "detector": "node.auth-guard" }),
        ));
    }

    if line_contains_any(
        &lower,
        &[
            "graphqlhttp(",
            "new apolloserver",
            "apolloserver(",
            "createexpressmiddleware",
            "trpc.",
            ".procedure",
            "grpc",
        ],
    ) || node_route_from_line(line)
        .path
        .as_deref()
        .is_some_and(|route| route.to_ascii_lowercase().contains("graphql"))
    {
        let route = node_route_from_line(line);
        builder.add(surface(
            AttackSurfaceKind::RpcHandler,
            source_file,
            framework,
            line_number,
            "RPC handler",
            &detail,
            route.method.as_deref(),
            route.path.as_deref(),
            Some("remote_rpc"),
            json!({ "source": "source_line", "detector": "node.rpc-handler" }),
        ));
    }

    if line_contains_any(
        &lower,
        &[
            "cron.schedule(",
            "new queue(",
            "queue(",
            "agenda.define(",
            ".process(",
            "setinterval(",
        ],
    ) {
        builder.add(surface(
            AttackSurfaceKind::BackgroundJob,
            source_file,
            framework,
            line_number,
            "Background job or scheduler",
            &detail,
            None,
            None,
            Some("async_job"),
            json!({ "source": "source_line", "detector": "node.background-job" }),
        ));
    }

    if line_contains_any(
        &lower,
        &[
            "json.parse(",
            "yaml.load(",
            "yaml.parse(",
            "deserialize(",
            ".deserialize(",
            "jwt.decode(",
            "protobuf.decode(",
        ],
    ) {
        builder.add(surface(
            AttackSurfaceKind::DeserializationPoint,
            source_file,
            framework,
            line_number,
            "Deserialization or parser boundary",
            &detail,
            None,
            None,
            Some("parser_boundary"),
            json!({ "source": "source_line", "detector": "node.deserialization" }),
        ));
    }

    if line_contains_any(
        &lower,
        &[
            "multer(",
            "upload.single(",
            "upload.array(",
            "upload.fields(",
            "busboy(",
            "formidable(",
            "multipart",
            "parsemultipart",
        ],
    ) {
        let route = node_route_from_line(line);
        builder.add(surface(
            AttackSurfaceKind::FileUploadParsePath,
            source_file,
            framework,
            line_number,
            "File upload or multipart parser",
            &detail,
            route.method.as_deref(),
            route.path.as_deref(),
            Some("file_input"),
            json!({ "source": "source_line", "detector": "node.file-upload" }),
        ));
    }

    if line_contains_any(
        &lower,
        &[
            ".query(",
            "prisma.",
            "sequelize.query(",
            "mongoose.",
            "knex(",
            ".collection(",
        ],
    ) {
        builder.add(surface(
            AttackSurfaceKind::DbQueryBoundary,
            source_file,
            framework,
            line_number,
            "Database query boundary",
            &detail,
            None,
            None,
            Some("data_store"),
            json!({ "source": "source_line", "detector": "node.db-query" }),
        ));
    }

    if line_contains_any(
        &lower,
        &[
            "child_process.exec",
            "child_process.spawn",
            "execfile(",
            "exec(",
            "spawn(",
            "execa(",
        ],
    ) {
        builder.add(surface(
            AttackSurfaceKind::CommandExecutionBoundary,
            source_file,
            framework,
            line_number,
            "Command execution boundary",
            &detail,
            None,
            None,
            Some("process_execution"),
            json!({ "source": "source_line", "detector": "node.command-exec" }),
        ));
    }

    if lower.contains("process.argv") || detail.starts_with("#!/usr/bin/env node") {
        builder.add(surface(
            AttackSurfaceKind::CliEntrypoint,
            source_file,
            framework,
            line_number,
            "CLI argument entrypoint",
            &detail,
            None,
            None,
            Some("process_entrypoint"),
            json!({ "source": "source_line", "detector": "node.cli-entrypoint" }),
        ));
    }
}

fn inspect_python_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    let lower = detail.to_ascii_lowercase();
    if lower.contains("login_required") || lower.contains("permission_required") {
        builder.add(surface(
            AttackSurfaceKind::AuthBoundary,
            source_file,
            framework,
            line_number,
            "Authentication or authorization guard",
            &detail,
            None,
            None,
            Some("auth_guard"),
            json!({ "source": "source_line", "detector": "python.auth-guard" }),
        ));
    }
    if line_contains_any(&lower, &["pickle.loads", "yaml.load(", "json.loads("]) {
        builder.add(surface(
            AttackSurfaceKind::DeserializationPoint,
            source_file,
            framework,
            line_number,
            "Deserialization or parser boundary",
            &detail,
            None,
            None,
            Some("parser_boundary"),
            json!({ "source": "source_line", "detector": "python.deserialization" }),
        ));
    }
    if line_contains_any(&lower, &["cursor.execute", ".execute(", "session.execute("]) {
        builder.add(surface(
            AttackSurfaceKind::DbQueryBoundary,
            source_file,
            framework,
            line_number,
            "Database query boundary",
            &detail,
            None,
            None,
            Some("data_store"),
            json!({ "source": "source_line", "detector": "python.db-query" }),
        ));
    }
    if line_contains_any(&lower, &["shell=true", "subprocess.", "os.system("]) {
        builder.add(surface(
            AttackSurfaceKind::CommandExecutionBoundary,
            source_file,
            framework,
            line_number,
            "Command execution boundary",
            &detail,
            None,
            None,
            Some("process_execution"),
            json!({ "source": "source_line", "detector": "python.command-exec" }),
        ));
    }
}

fn inspect_go_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    let lower = detail.to_ascii_lowercase();
    if line_contains_any(&lower, &["authmiddleware", "requireuser", "authorize"]) {
        builder.add(surface(
            AttackSurfaceKind::AuthBoundary,
            source_file,
            framework,
            line_number,
            "Authentication or authorization guard",
            &detail,
            None,
            None,
            Some("auth_guard"),
            json!({ "source": "source_line", "detector": "go.auth-guard" }),
        ));
    }
    if line_contains_any(&lower, &["json.newdecoder", "yaml.", "proto.unmarshal"]) {
        builder.add(surface(
            AttackSurfaceKind::DeserializationPoint,
            source_file,
            framework,
            line_number,
            "Deserialization or parser boundary",
            &detail,
            None,
            None,
            Some("parser_boundary"),
            json!({ "source": "source_line", "detector": "go.deserialization" }),
        ));
    }
    if line_contains_any(&lower, &[".query(", ".exec(", "db."]) {
        builder.add(surface(
            AttackSurfaceKind::DbQueryBoundary,
            source_file,
            framework,
            line_number,
            "Database query boundary",
            &detail,
            None,
            None,
            Some("data_store"),
            json!({ "source": "source_line", "detector": "go.db-query" }),
        ));
    }
    if line_contains_any(&lower, &["exec.command(", "os.startprocess("]) {
        builder.add(surface(
            AttackSurfaceKind::CommandExecutionBoundary,
            source_file,
            framework,
            line_number,
            "Command execution boundary",
            &detail,
            None,
            None,
            Some("process_execution"),
            json!({ "source": "source_line", "detector": "go.command-exec" }),
        ));
    }
}

fn inspect_rust_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    let lower = detail.to_ascii_lowercase();
    if line_contains_any(&lower, &["require_user", "requireuser", "authorize"]) {
        builder.add(surface(
            AttackSurfaceKind::AuthBoundary,
            source_file,
            framework,
            line_number,
            "Authentication or authorization guard",
            &detail,
            None,
            None,
            Some("auth_guard"),
            json!({ "source": "source_line", "detector": "rust.auth-guard" }),
        ));
    }
    if line_contains_any(
        &lower,
        &["serde_json::from", "serde_yaml::from", "bincode::"],
    ) {
        builder.add(surface(
            AttackSurfaceKind::DeserializationPoint,
            source_file,
            framework,
            line_number,
            "Deserialization or parser boundary",
            &detail,
            None,
            None,
            Some("parser_boundary"),
            json!({ "source": "source_line", "detector": "rust.deserialization" }),
        ));
    }
    if line_contains_any(&lower, &["sqlx::query", ".execute(", ".fetch_"]) {
        builder.add(surface(
            AttackSurfaceKind::DbQueryBoundary,
            source_file,
            framework,
            line_number,
            "Database query boundary",
            &detail,
            None,
            None,
            Some("data_store"),
            json!({ "source": "source_line", "detector": "rust.db-query" }),
        ));
    }
    if line_contains_any(
        &lower,
        &["std::process::command", "tokio::process::command"],
    ) {
        builder.add(surface(
            AttackSurfaceKind::CommandExecutionBoundary,
            source_file,
            framework,
            line_number,
            "Command execution boundary",
            &detail,
            None,
            None,
            Some("process_execution"),
            json!({ "source": "source_line", "detector": "rust.command-exec" }),
        ));
    }
    if lower.contains("std::env::args") {
        builder.add(surface(
            AttackSurfaceKind::CliEntrypoint,
            source_file,
            framework,
            line_number,
            "CLI argument entrypoint",
            &detail,
            None,
            None,
            Some("process_entrypoint"),
            json!({ "source": "source_line", "detector": "rust.cli-entrypoint" }),
        ));
    }
}

fn surface(
    kind: AttackSurfaceKind,
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    title: &str,
    evidence: &str,
    method: Option<&str>,
    route: Option<&str>,
    boundary: Option<&str>,
    metadata: Value,
) -> AttackSurfaceDraft {
    AttackSurfaceDraft {
        kind,
        path: source_file.path.clone(),
        line: Some(line_number),
        language: source_file.language.clone(),
        framework: framework.map(str::to_string),
        title: title.to_string(),
        evidence: evidence.to_string(),
        method: method.map(str::to_string),
        route: route.map(str::to_string),
        boundary: boundary.map(str::to_string),
        metadata,
    }
}

#[derive(Debug, Default)]
struct RouteLine {
    method: Option<String>,
    path: Option<String>,
}

fn node_route_from_line(line: &str) -> RouteLine {
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

fn is_route_line(lower: &str) -> bool {
    line_contains_any(
        lower,
        &[
            ".get(", ".post(", ".put(", ".patch(", ".delete(", ".use(", ".all(",
        ],
    )
}

fn line_has_auth_guard(lower: &str) -> bool {
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

fn framework_for_source(language: &str, text: &str) -> Option<String> {
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

fn summarize_surfaces(surfaces: &[AttackSurface]) -> AttackSurfaceSummary {
    let mut by_kind = BTreeMap::new();
    let mut by_file = BTreeMap::new();
    for surface in surfaces {
        *by_kind
            .entry(surface.kind.as_str().to_string())
            .or_insert(0) += 1;
        *by_file.entry(surface.path.clone()).or_insert(0) += 1;
    }
    AttackSurfaceSummary {
        total: surfaces.len(),
        by_kind,
        by_file,
    }
}

fn attack_surface_id(surface: &AttackSurface) -> String {
    let metadata = serde_json::to_string(&surface.metadata).unwrap_or_else(|_| "{}".to_string());
    let segments = [
        surface.kind.as_str(),
        &surface.path,
        &surface
            .line
            .map(|line| line.to_string())
            .unwrap_or_default(),
        &surface.language,
        surface.framework.as_deref().unwrap_or(""),
        &surface.title,
        &surface.evidence,
        surface.method.as_deref().unwrap_or(""),
        surface.route.as_deref().unwrap_or(""),
        surface.boundary.as_deref().unwrap_or(""),
        &metadata,
    ];
    let body = segments.join("\0");
    format!("AS-{}", &static_content_hash(&body)[..16])
}

fn language_from_path(path: &str) -> Option<&'static str> {
    let extension = Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())?
        .to_ascii_lowercase();
    match extension.as_str() {
        "js" | "jsx" | "mjs" | "cjs" => Some("JavaScript"),
        "ts" | "tsx" => Some("TypeScript"),
        "py" => Some("Python"),
        "go" => Some("Go"),
        "rs" => Some("Rust"),
        _ => None,
    }
}

fn trim_detail(line: &str) -> String {
    line.trim().split_whitespace().collect::<Vec<_>>().join(" ")
}

fn line_contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;

    use super::*;

    #[test]
    fn attack_surface_detects_node_express_boundaries_from_source() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::create_dir_all(temp.path().join("node_modules/express")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{
              "scripts": {
                "start": "node src/server.ts && touch SHOULD_NOT_EXIST"
              },
              "dependencies": {
                "express": "^4.18.0",
                "multer": "^1.4.5",
                "graphql": "^16.0.0"
              }
            }"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            r#"
              import express from 'express';
              import multer from 'multer';
              import { exec } from 'child_process';
              const app = express();
              const upload = multer();
              app.use('/admin', requireAuth);
              app.post('/upload', requireAuth, upload.single('file'), (req, res) => {
                const parsed = JSON.parse(req.body.metadata);
                db.query(`select * from users where name = ${req.query.name}`);
                exec(req.query.cmd);
                res.json(parsed);
              });
              app.post('/graphql', graphqlHTTP({ schema }));
              cron.schedule('* * * * *', runJob);
              const args = process.argv.slice(2);
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("node_modules/express/index.js"),
            "module.exports = {}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        assert!(!temp.path().join("SHOULD_NOT_EXIST").exists());

        assert_has_kind(&map, AttackSurfaceKind::HttpRoute);
        assert_has_kind(&map, AttackSurfaceKind::RpcHandler);
        assert_has_kind(&map, AttackSurfaceKind::CliEntrypoint);
        assert_has_kind(&map, AttackSurfaceKind::BackgroundJob);
        assert_has_kind(&map, AttackSurfaceKind::DeserializationPoint);
        assert_has_kind(&map, AttackSurfaceKind::FileUploadParsePath);
        assert_has_kind(&map, AttackSurfaceKind::AuthBoundary);
        assert_has_kind(&map, AttackSurfaceKind::DbQueryBoundary);
        assert_has_kind(&map, AttackSurfaceKind::CommandExecutionBoundary);

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/upload")
                && surface.framework.as_deref() == Some("Express")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/graphql")
        }));
        assert!(map
            .surfaces
            .iter()
            .all(|surface| !surface.path.starts_with("node_modules/")));
    }

    #[test]
    fn attack_surface_detects_python_and_go_security_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/app.py"),
            r#"
              @login_required
              def handler(request):
                  yaml.load(request.body)
                  cursor.execute("select * from users")
                  subprocess.call(request.GET["cmd"], shell=True)
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/main.go"),
            r#"
              package main
              func handler() {
                  authorize(user)
                  json.NewDecoder(r.Body).Decode(&payload)
                  db.Query("select * from users")
                  exec.Command("sh", "-c", input)
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("app.py")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("python.command-exec")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("main.go")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("go.deserialization")
        }));
        assert_has_kind(&map, AttackSurfaceKind::AuthBoundary);
        assert_has_kind(&map, AttackSurfaceKind::DbQueryBoundary);
        assert_has_kind(&map, AttackSurfaceKind::CommandExecutionBoundary);
    }

    #[test]
    fn attack_surface_map_is_deterministic_and_summarized() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"^4.18.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/api.ts"),
            "import express from 'express';\nconst app = express();\napp.get('/a', requireAuth, handler);\nJSON.parse(req.body.payload);\n",
        )
        .unwrap();

        let first = build_attack_surface_map(temp.path()).unwrap();
        let second = build_attack_surface_map(temp.path()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.summary.total, first.surfaces.len());
        assert_eq!(
            first.summary.by_kind.get("http_route"),
            Some(&1),
            "{:?}",
            first.summary
        );

        let ids = first
            .surfaces
            .iter()
            .map(|surface| surface.id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), first.surfaces.len());
    }

    fn assert_has_kind(map: &AttackSurfaceMap, kind: AttackSurfaceKind) {
        assert!(
            map.surfaces.iter().any(|surface| surface.kind == kind),
            "missing {kind:?} in {:#?}",
            map.surfaces
        );
        assert!(
            map.summary.by_kind.contains_key(kind.as_str()),
            "summary missing {kind:?}: {:?}",
            map.summary
        );
    }
}
