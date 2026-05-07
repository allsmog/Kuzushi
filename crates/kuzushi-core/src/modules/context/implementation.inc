use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use super::support::should_skip_path;
use super::{
    builtin_module, dag, hidden_module, opt, tool_with_options, BuiltinModule, ModuleKind,
    ModuleRegistry, OptionType, ToolExecutionContext,
};

pub(super) fn register_context_modules(registry: &mut ModuleRegistry) {
    registry.register(context_module());
    registry.register(context_lite_module());
}

fn context_module() -> BuiltinModule {
    builtin_module(
        "context",
        "Context",
        ModuleKind::Intel,
        "Build and persist repository context snapshots for scanner and shell use.",
        vec![tool_with_options(
            "context:build",
            "Build a lightweight native repository context snapshot.",
            vec![
                opt(
                    "sampleLimit",
                    OptionType::Int,
                    "Maximum source files to sample in the context snapshot.",
                )
                .default(json!(200)),
                opt("discovery", OptionType::Enum, "Repository discovery mode.")
                    .choices(&["auto", "flat", "modules"])
                    .default(json!("auto")),
                opt(
                    "enrichment",
                    OptionType::Bool,
                    "Request LLM-backed context enrichment when supported.",
                )
                .default(json!(false))
                .advanced(),
                opt("scope", OptionType::Enum, "Context slice to build.")
                    .choices(&["all", "repo", "enrichment", "app-model"])
                    .default(json!("all")),
            ],
        )],
        vec![dag("context:build", "context", &[])],
    )
}

fn context_lite_module() -> BuiltinModule {
    hidden_module(
        "context-lite",
        "Context Lite",
        ModuleKind::Internal,
        "Internal minimal repository context node kept for MVP scan compatibility.",
        vec![],
        vec![dag("context-lite:index", "context", &["context:build"])],
    )
}

pub(super) fn build_context_snapshot(
    input: Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("context:build requires a workspace target")?;
    let sample_limit = input
        .get("sampleLimit")
        .or_else(|| input.get("limit"))
        .and_then(Value::as_u64)
        .unwrap_or(200)
        .min(2_000) as usize;
    let discovery = input
        .get("discovery")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "auto" | "flat" | "modules"))
        .unwrap_or("auto");
    let enrichment = input
        .get("enrichment")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if enrichment {
        anyhow::bail!(
            "context:build Rust native executor does not support LLM enrichment yet; run with {{\"enrichment\":false}} or use a pi-agent-core-backed context adapter once configured"
        );
    }
    let scope = input
        .get("scope")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "all" | "repo" | "enrichment" | "app-model"))
        .unwrap_or("all");

    let mut files_sample = Vec::new();
    let mut files_indexed = 0usize;
    collect_context_files(
        workspace.root(),
        workspace.root(),
        sample_limit,
        &mut files_indexed,
        &mut files_sample,
    )?;

    let repo_context = infer_repo_context(workspace.root(), &files_sample)?;
    let repository_inventory =
        crate::repository_inventory::build_repository_inventory(workspace.root())?;
    let attack_surface_map = crate::attack_surface::build_attack_surface_map_from_inventory(
        workspace.root(),
        &repository_inventory,
    )?;
    let app_model_routes = attack_surface_routes(&attack_surface_map);
    let app_model_background_jobs = attack_surface_app_model_items(
        &attack_surface_map,
        crate::attack_surface::AttackSurfaceKind::BackgroundJob,
    );
    let app_model_data_stores = attack_surface_app_model_items(
        &attack_surface_map,
        crate::attack_surface::AttackSurfaceKind::DbQueryBoundary,
    );
    let app_model_service_boundaries = attack_surface_service_boundaries(&attack_surface_map);
    let file_tree = files_sample
        .iter()
        .map(|path| json!({ "path": path }))
        .collect::<Vec<_>>();
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_millis() as u64;
    let snapshot = json!({
        "target": workspace.root().display().to_string(),
        "timestamp": now_ms,
        "discovery": discovery,
        "options": {
            "enrichment": enrichment,
        },
        "repoContext": repo_context,
        "repositoryInventory": repository_inventory,
        "attackSurfaceMap": attack_surface_map,
        "fileIndex": {
            "tree": file_tree,
            "totalFiles": files_indexed,
            "truncated": files_indexed > files_sample.len(),
            "patternMatches": {},
        },
        "appModel": {
            "routes": app_model_routes,
            "outboundClients": [],
            "serviceBoundaries": app_model_service_boundaries,
            "dataStores": app_model_data_stores,
            "backgroundJobs": app_model_background_jobs,
        },
        "generatedSlices": generated_context_slices(scope, enrichment),
        "staleSlices": stale_context_slices(scope),
        "scanner": "native-context-lite",
        "filesIndexed": files_indexed,
        "filesSample": files_sample,
    });

    let snapshot_path = save_context_snapshot(workspace.root(), &snapshot)?;
    let output = format!(
        "context:build indexed {} file{} under {}\n  Snapshot: {}",
        files_indexed,
        if files_indexed == 1 { "" } else { "s" },
        workspace.root().display(),
        snapshot_path.display()
    );

    Ok(json!({
        "ok": true,
        "output": output,
        "data": {
            "root": workspace.root().display().to_string(),
            "stateDir": workspace.state_dir().display().to_string(),
            "snapshotPath": snapshot_path.display().to_string(),
            "snapshot": snapshot,
        },
    }))
}

fn attack_surface_routes(map: &crate::attack_surface::AttackSurfaceMap) -> Vec<Value> {
    map.surfaces
        .iter()
        .filter(|surface| surface.kind == crate::attack_surface::AttackSurfaceKind::HttpRoute)
        .map(|surface| {
            json!({
                "id": surface.id,
                "path": surface.route,
                "method": surface.method,
                "source": surface.path,
                "line": surface.line,
                "framework": surface.framework,
                "evidence": surface.evidence,
            })
        })
        .collect()
}

fn attack_surface_app_model_items(
    map: &crate::attack_surface::AttackSurfaceMap,
    kind: crate::attack_surface::AttackSurfaceKind,
) -> Vec<Value> {
    map.surfaces
        .iter()
        .filter(|surface| surface.kind == kind)
        .map(|surface| {
            json!({
                "id": surface.id,
                "kind": surface.kind.as_str(),
                "source": surface.path,
                "line": surface.line,
                "title": surface.title,
                "evidence": surface.evidence,
                "boundary": surface.boundary,
            })
        })
        .collect()
}

fn attack_surface_service_boundaries(map: &crate::attack_surface::AttackSurfaceMap) -> Vec<Value> {
    map.surfaces
        .iter()
        .filter(|surface| {
            matches!(
                surface.kind,
                crate::attack_surface::AttackSurfaceKind::AuthBoundary
                    | crate::attack_surface::AttackSurfaceKind::CommandExecutionBoundary
                    | crate::attack_surface::AttackSurfaceKind::FileUploadParsePath
                    | crate::attack_surface::AttackSurfaceKind::RpcHandler
            )
        })
        .map(|surface| {
            json!({
                "id": surface.id,
                "kind": surface.kind.as_str(),
                "source": surface.path,
                "line": surface.line,
                "title": surface.title,
                "route": surface.route,
                "method": surface.method,
                "boundary": surface.boundary,
            })
        })
        .collect()
}

fn save_context_snapshot(root: &Path, snapshot: &Value) -> Result<PathBuf> {
    let snapshot_path = root.join(".kuzushi").join("context-snapshot.json");
    if let Some(parent) = snapshot_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    let body = format!("{}\n", serde_json::to_string_pretty(snapshot)?);
    fs::write(&snapshot_path, body)
        .with_context(|| format!("Could not write {}", snapshot_path.display()))?;
    Ok(snapshot_path)
}

fn generated_context_slices(scope: &str, enrichment: bool) -> Vec<&'static str> {
    match scope {
        "repo" => vec!["repo"],
        "enrichment" => vec!["enrichment"],
        "app-model" => vec!["app-model"],
        _ if enrichment => vec!["all", "repo", "app-model", "enrichment"],
        _ => vec!["repo", "app-model"],
    }
}

fn stale_context_slices(scope: &str) -> Vec<&'static str> {
    match scope {
        "repo" => vec!["enrichment", "app-model"],
        "enrichment" => vec!["app-model"],
        _ => vec![],
    }
}

fn infer_repo_context(root: &Path, files: &[String]) -> Result<Value> {
    let mut signals = RepoContextSignals::default();
    for file in files {
        signals.ingest_file(file);
    }
    signals.inspect_manifests(root)?;
    Ok(signals.into_json())
}

#[derive(Default)]
struct RepoContextSignals {
    languages: BTreeSet<&'static str>,
    frameworks: BTreeSet<&'static str>,
    auth_patterns: BTreeSet<&'static str>,
    orm_or_db: BTreeSet<&'static str>,
    entry_points: BTreeSet<String>,
    sanitization_libs: BTreeSet<&'static str>,
}

impl RepoContextSignals {
    fn ingest_file(&mut self, file: &str) {
        if let Some(language) = language_for_context_file(file) {
            self.languages.insert(language);
        }
        if is_context_entry_point(file) {
            self.entry_points.insert(file.to_string());
        }
    }

    fn inspect_manifests(&mut self, root: &Path) -> Result<()> {
        inspect_manifest_dependencies(
            &root.join("package.json"),
            &mut self.frameworks,
            &mut self.auth_patterns,
            &mut self.orm_or_db,
            &mut self.sanitization_libs,
        )?;
        inspect_manifest_text(
            &root.join("Cargo.toml"),
            &["actix-web", "axum", "rocket"],
            &mut self.frameworks,
        )?;
        inspect_manifest_text(
            &root.join("Cargo.toml"),
            &["sqlx", "diesel"],
            &mut self.orm_or_db,
        )?;
        inspect_manifest_text(
            &root.join("pyproject.toml"),
            &["django", "fastapi", "flask"],
            &mut self.frameworks,
        )?;
        inspect_manifest_text(
            &root.join("pyproject.toml"),
            &["sqlalchemy"],
            &mut self.orm_or_db,
        )?;
        inspect_manifest_text(
            &root.join("go.mod"),
            &["gin-gonic/gin", "gorilla/mux"],
            &mut self.frameworks,
        )?;
        inspect_manifest_text(&root.join("go.mod"), &["gorm.io/gorm"], &mut self.orm_or_db)
    }

    fn into_json(self) -> Value {
        json!({
            "languages": self.languages.into_iter().collect::<Vec<_>>(),
            "frameworks": self.frameworks.into_iter().collect::<Vec<_>>(),
            "authPatterns": self.auth_patterns.into_iter().collect::<Vec<_>>(),
            "ormOrDb": self.orm_or_db.into_iter().collect::<Vec<_>>(),
            "entryPoints": self.entry_points.into_iter().collect::<Vec<_>>(),
            "sanitizationLibs": self.sanitization_libs.into_iter().collect::<Vec<_>>(),
        })
    }
}

fn language_for_context_file(file: &str) -> Option<&'static str> {
    match Path::new(file).extension().and_then(|ext| ext.to_str())? {
        "js" | "jsx" => Some("JavaScript"),
        "ts" | "tsx" => Some("TypeScript"),
        "rs" => Some("Rust"),
        "py" => Some("Python"),
        "go" => Some("Go"),
        "java" => Some("Java"),
        "rb" => Some("Ruby"),
        "php" => Some("PHP"),
        "c" | "h" => Some("C"),
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => Some("C++"),
        _ => None,
    }
}

fn is_context_entry_point(file: &str) -> bool {
    let lower = file.to_lowercase();
    matches!(
        lower.as_str(),
        "package.json" | "server.js" | "server.ts" | "src/main.rs" | "main.go" | "app.py"
    ) || [
        "/server.js",
        "/server.ts",
        "/src/main.rs",
        "/main.go",
        "/app.py",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

fn inspect_manifest_dependencies(
    path: &Path,
    frameworks: &mut BTreeSet<&'static str>,
    auth_patterns: &mut BTreeSet<&'static str>,
    orm_or_db: &mut BTreeSet<&'static str>,
    sanitization_libs: &mut BTreeSet<&'static str>,
) -> Result<()> {
    let Ok(raw) = fs::read_to_string(path) else {
        return Ok(());
    };
    let parsed = serde_json::from_str::<Value>(&raw)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    let deps = package_json_dependency_names(&parsed);
    insert_package_json_context_signals(
        &deps,
        frameworks,
        auth_patterns,
        orm_or_db,
        sanitization_libs,
    );

    Ok(())
}

fn package_json_dependency_names(parsed: &Value) -> BTreeSet<&str> {
    let mut deps = BTreeSet::new();
    for key in ["dependencies", "devDependencies", "peerDependencies"] {
        if let Some(object) = parsed.get(key).and_then(Value::as_object) {
            deps.extend(object.keys().map(|key| key.as_str()));
        }
    }
    deps
}

fn insert_package_json_context_signals(
    deps: &BTreeSet<&str>,
    frameworks: &mut BTreeSet<&'static str>,
    auth_patterns: &mut BTreeSet<&'static str>,
    orm_or_db: &mut BTreeSet<&'static str>,
    sanitization_libs: &mut BTreeSet<&'static str>,
) {
    if deps.contains("express") {
        frameworks.insert("express");
    }
    if deps.contains("next") {
        frameworks.insert("next");
    }
    if deps.contains("react") {
        frameworks.insert("react");
    }
    if deps.contains("@nestjs/core") {
        frameworks.insert("nestjs");
    }
    if deps.contains("passport") || deps.contains("next-auth") || deps.contains("@auth/core") {
        auth_patterns.insert("session/auth middleware");
    }
    if deps.contains("jsonwebtoken") || deps.contains("jose") {
        auth_patterns.insert("jwt");
    }
    if deps.contains("prisma") || deps.contains("@prisma/client") {
        orm_or_db.insert("prisma");
    }
    if deps.contains("mongoose") {
        orm_or_db.insert("mongoose");
    }
    if deps.contains("sequelize") {
        orm_or_db.insert("sequelize");
    }
    if deps.contains("zod") {
        sanitization_libs.insert("zod");
    }
    if deps.contains("joi") {
        sanitization_libs.insert("joi");
    }
}

fn inspect_manifest_text(
    path: &Path,
    probes: &[&'static str],
    matches: &mut BTreeSet<&'static str>,
) -> Result<()> {
    let Ok(raw) = fs::read_to_string(path) else {
        return Ok(());
    };
    let lower = raw.to_lowercase();
    for needle in probes {
        if lower.contains(needle) {
            matches.insert(needle);
        }
    }
    Ok(())
}

fn collect_context_files(
    root: &Path,
    dir: &Path,
    sample_limit: usize,
    files_indexed: &mut usize,
    files_sample: &mut Vec<String>,
) -> Result<()> {
    let Ok(read_dir) = fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries = read_dir.filter_map(|entry| entry.ok()).collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let file_name = entry.file_name();
        if should_skip_path(&file_name.to_string_lossy()) {
            continue;
        }

        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_context_files(root, &path, sample_limit, files_indexed, files_sample)?;
        } else if file_type.is_file() {
            *files_indexed += 1;
            if files_sample.len() < sample_limit {
                let display_path = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                files_sample.push(display_path);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_repo_context_collects_languages_entrypoints_and_manifest_signals() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{
              "dependencies": {
                "express": "^4",
                "passport": "^1",
                "jsonwebtoken": "^9",
                "prisma": "^5",
                "zod": "^3"
              },
              "devDependencies": {"react": "^18"}
            }"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "axum = \"0.7\"\nsqlx = \"0.8\"",
        )
        .unwrap();

        let context = infer_repo_context(
            temp.path(),
            &[
                "server.ts".to_string(),
                "src/main.rs".to_string(),
                "cmd/api/main.go".to_string(),
                "native/parser.cpp".to_string(),
            ],
        )
        .unwrap();

        assert_eq!(
            context["languages"],
            json!(["C++", "Go", "Rust", "TypeScript"])
        );
        assert_eq!(
            context["entryPoints"],
            json!(["cmd/api/main.go", "server.ts", "src/main.rs"])
        );
        assert!(context["frameworks"]
            .as_array()
            .unwrap()
            .contains(&json!("express")));
        assert!(context["frameworks"]
            .as_array()
            .unwrap()
            .contains(&json!("axum")));
        assert!(context["authPatterns"]
            .as_array()
            .unwrap()
            .contains(&json!("jwt")));
        assert!(context["ormOrDb"]
            .as_array()
            .unwrap()
            .contains(&json!("prisma")));
        assert!(context["sanitizationLibs"]
            .as_array()
            .unwrap()
            .contains(&json!("zod")));
    }
}
