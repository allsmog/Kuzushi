use super::prelude::*;
use super::*;

pub(crate) fn inspect_rust_line(
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

pub(crate) fn surface(
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
